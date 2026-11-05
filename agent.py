#!/usr/bin/env python3
"""
helix-agent — Nostr DM chat agent (ZeroClaw-lite)
Listens for NIP-04 (kind 4) and NIP-44 gift-wrap (kind 1059) DMs,
replies via omnirouter LLM, handles NIP-42 AUTH.
"""

import asyncio
import base64
import json
import logging
import os
import subprocess
import sys
import time
from collections import defaultdict, deque

import httpx
import websockets
import minipae

# ── Config ────────────────────────────────────────────────────────────────────
LOG_PATH        = "/opt/ares/ares_logs/helix-agent.log"
RELAY_WS        = "wss://omokoda.duckdns.org:3443/relay"
RELAY_AUTH_TAG  = "wss://omokoda.duckdns.org:3443"   # no path in AUTH tag
OMNIROUTER_BASE = "http://127.0.0.1:8300/v1"
OMNIROUTER_KEY_FILE = "/opt/ares/.omniroute_key_swarm_orchestrator"
MODEL           = "free-pool"
SYSTEM_PROMPT   = (
    "You are Helix, a sovereign AI agent on the omokoda network. "
    "You communicate via Nostr DMs. Be concise and helpful."
)
AGENT_VOICE_SERVICE = "agent-voice.service"
MAX_HISTORY     = 20
CONTEXT_TURNS   = 6

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH),
    ],
)
log = logging.getLogger("helix-agent")

# ── Keys ───────────────────────────────────────────────────────────────────────
SK_HEX   = os.environ["HELIX_NSEC_HEX"]
PUB_HEX  = os.environ["HELIX_PUBKEY_HEX"]
SK_BYTES = bytes.fromhex(SK_HEX)
PUB_BYTES = bytes.fromhex(PUB_HEX)
NPUB     = os.environ.get("HELIX_NPUB", "?")

log.info("Helix pubkey: %s", PUB_HEX)
log.info("Helix npub:   %s", NPUB)


def read_omnirouter_key() -> str:
    with open(OMNIROUTER_KEY_FILE) as fh:
        return fh.read().strip()


# ── Conversation store ────────────────────────────────────────────────────────
conversations: dict[str, deque] = defaultdict(lambda: deque(maxlen=MAX_HISTORY))


def get_context(sender_pubkey: str) -> list[dict]:
    return list(conversations[sender_pubkey])[-CONTEXT_TURNS:]


def store_turn(sender_pubkey: str, role: str, content: str):
    conversations[sender_pubkey].append({"role": role, "content": content})


# ── agent-voice presence ──────────────────────────────────────────────────────
def is_agent_voice_active() -> bool:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", AGENT_VOICE_SERVICE],
            capture_output=True, text=True, timeout=3,
        )
        return result.stdout.strip() == "active"
    except Exception:
        return False


# ── LLM call ─────────────────────────────────────────────────────────────────
async def call_llm(messages: list[dict]) -> str:
    key = read_omnirouter_key()
    payload = {
        "model": MODEL,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + messages,
        "max_tokens": 500,
    }
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{OMNIROUTER_BASE}/chat/completions",
                headers={
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        log.error("LLM call failed: %s", exc)
        return "I'm thinking... try again shortly."


# ── NIP-04 decryption (pure Python, no extra deps) ───────────────────────────
def _nip04_shared_secret(sk_bytes: bytes, peer_pubkey_hex: str) -> bytes:
    """ECDH x-coordinate for NIP-04 (SHA256 of x is NOT taken — raw x used as AES key)."""
    sk_int = int.from_bytes(sk_bytes, "big")
    peer_x = int(peer_pubkey_hex, 16)
    peer_point = minipae._lift_x(peer_x)
    if peer_point is None:
        raise ValueError("invalid peer pubkey")
    x, _ = minipae._point_mul(sk_int, peer_point)
    return x.to_bytes(32, "big")


def _nip04_decrypt(content: str, sk_bytes: bytes, peer_pubkey_hex: str) -> str | None:
    """Decrypt NIP-04 AES-CBC DM. Returns plaintext or None on failure."""
    try:
        # format: <base64_ciphertext>?iv=<base64_iv>
        if "?iv=" not in content:
            return None
        ct_b64, iv_b64 = content.split("?iv=", 1)
        ct = base64.b64decode(ct_b64)
        iv = base64.b64decode(iv_b64)
        shared = _nip04_shared_secret(sk_bytes, peer_pubkey_hex)
        # AES-256-CBC decrypt using only stdlib-compatible approach
        # We'll use a minimal pure-python CBC since we don't want extra deps
        from Crypto.Cipher import AES  # pycryptodome if available
        cipher = AES.new(shared, AES.MODE_CBC, iv)
        raw = cipher.decrypt(ct)
        # PKCS7 unpad
        pad_len = raw[-1]
        return raw[:-pad_len].decode("utf-8")
    except ImportError:
        # pycryptodome not available; skip NIP-04 and treat as unreadable
        log.warning("pycryptodome not available — NIP-04 messages will be skipped")
        return None
    except Exception as exc:
        log.warning("NIP-04 decrypt failed: %s", exc)
        return None


# ── DM decryption dispatcher ──────────────────────────────────────────────────
def decrypt_dm(event: dict) -> tuple[str | None, str | None]:
    """Return (sender_pubkey_hex, plaintext) or (None, None) on failure."""
    sender_pubkey = event.get("pubkey")
    kind = event.get("kind")
    content = event.get("content", "")

    try:
        if kind == 4:
            # Try NIP-44 first (some clients send kind-4 with NIP-44 payload)
            try:
                conv_key = minipae.conversation_key(SK_BYTES, bytes.fromhex(sender_pubkey))
                plaintext = minipae.nip44_decrypt(content, conv_key)
                return sender_pubkey, plaintext
            except Exception:
                pass
            # Fall back to NIP-04 AES-CBC
            plaintext = _nip04_decrypt(content, SK_BYTES, sender_pubkey)
            return sender_pubkey, plaintext

        elif kind == 1059:
            # Gift-wrap: outer event encrypted to our pubkey with sender's ephemeral key
            outer_conv = minipae.conversation_key(SK_BYTES, bytes.fromhex(sender_pubkey))
            seal_json = minipae.nip44_decrypt(content, outer_conv)
            seal = json.loads(seal_json)
            # Seal is kind-13, encrypted rumour
            seal_sender = seal["pubkey"]
            inner_conv = minipae.conversation_key(SK_BYTES, bytes.fromhex(seal_sender))
            rumour_json = minipae.nip44_decrypt(seal["content"], inner_conv)
            rumour = json.loads(rumour_json)
            return seal_sender, rumour.get("content", "")

        return sender_pubkey, None

    except Exception as exc:
        log.warning("Decrypt failed event=%s kind=%s: %s",
                    (event.get("id") or "?")[:12], kind, exc)
        return sender_pubkey, None


# ── Reply builder ─────────────────────────────────────────────────────────────
def build_reply_event(recipient_pubkey_hex: str, plaintext: str) -> dict:
    conv_key = minipae.conversation_key(SK_BYTES, bytes.fromhex(recipient_pubkey_hex))
    encrypted = minipae.nip44_encrypt(plaintext, conv_key)
    return minipae.sign_event(4, encrypted, [["p", recipient_pubkey_hex]], SK_BYTES)


def is_voice_offer(text: str) -> bool:
    kw = ["voice call", "voice offer", "audio call", "call me", "webrtc", "offer sdp",
          "sdp offer", "jingle", "voip"]
    lower = text.lower()
    return any(k in lower for k in kw)


# ── Event handler ─────────────────────────────────────────────────────────────
async def handle_event(ws, event: dict):
    kind    = event.get("kind")
    sender  = event.get("pubkey")
    eid     = (event.get("id") or "?")[:12]

    # Only events addressed to us (kind 4); gift-wrap (1059) always addressed to us
    if kind == 4:
        p_tags = [t[1] for t in event.get("tags", []) if t[0] == "p"]
        if PUB_HEX not in p_tags:
            return

    log.info("DM received id=%s kind=%s from=%s...", eid, kind, (sender or "?")[:12])

    real_sender, plaintext = decrypt_dm(event)
    if not plaintext:
        log.warning("Could not decrypt event %s — skipping", eid)
        return

    log.info("Decrypted from %s...: %.80s", (real_sender or "?")[:12], plaintext)

    # Voice-offer branch
    if is_voice_offer(plaintext):
        av = is_agent_voice_active()
        if av:
            reply_text = (
                "[Voice offer received] agent-voice is active on this node — "
                "voice call handling is available. Proceed with your preferred protocol."
            )
        else:
            reply_text = (
                "[Voice offer received] agent-voice is not active on this node. "
                "Text chat is available. How can I help?"
            )
        log.info("Voice-offer path — agent-voice active: %s", av)
    else:
        store_turn(real_sender, "user", plaintext)
        reply_text = await call_llm(get_context(real_sender))
        store_turn(real_sender, "assistant", reply_text)

    try:
        reply_ev = build_reply_event(real_sender, reply_text)
        await ws.send(json.dumps(["EVENT", reply_ev]))
        log.info("Reply sent to %s...: %.60s", real_sender[:12], reply_text)
    except Exception as exc:
        log.error("Failed to send reply: %s", exc)


# ── WebSocket session ─────────────────────────────────────────────────────────
async def run_agent():
    sub_id = "helix-dm-sub"
    dm_filter = {
        "kinds": [4, 1059],
        "#p": [PUB_HEX],
        "limit": 50,
        "since": int(time.time()) - 3600,
    }

    log.info("Connecting to relay %s", RELAY_WS)
    async with websockets.connect(
        RELAY_WS,
        open_timeout=20,
        ping_interval=30,
        ping_timeout=20,
        max_size=4 * 1024 * 1024,
    ) as ws:
        # ── NIP-42: handle upfront AUTH challenge before REQ ──────────────
        try:
            first_raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
            first = json.loads(first_raw)
            log.info("Relay first message: %.120s", first_raw)
            if first[0] == "AUTH":
                challenge = first[1]
                log.info("NIP-42 AUTH challenge: %.40s", challenge)
                auth_ev = minipae.build_auth_event(challenge, RELAY_AUTH_TAG, SK_BYTES)
                await ws.send(json.dumps(["AUTH", auth_ev]))
                log.info("AUTH response sent (kind 22242)")
                # Wait for OK
                ok_raw = await asyncio.wait_for(ws.recv(), timeout=10.0)
                ok = json.loads(ok_raw)
                log.info("AUTH result: %.120s", ok_raw)
                if ok[0] == "OK":
                    if ok[2] is True:
                        log.info("NIP-42 AUTH accepted by relay")
                    else:
                        log.warning("NIP-42 AUTH rejected: %s", ok)
            else:
                log.info("No upfront AUTH — relay opened with: %s", first[0])
                # Could be an early event; we'll process it after subscribing
        except asyncio.TimeoutError:
            log.info("No initial AUTH challenge within 5s — proceeding")

        # ── Subscribe to DMs ──────────────────────────────────────────────
        await ws.send(json.dumps(["REQ", sub_id, dm_filter]))
        log.info("REQ sent — subscribed kinds=[4,1059] for %s...", PUB_HEX[:16])

        # ── Event loop ────────────────────────────────────────────────────
        while True:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=120.0)
            except asyncio.TimeoutError:
                log.debug("Sending keepalive ping")
                try:
                    await ws.ping()
                except Exception:
                    raise
                continue

            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                log.warning("Non-JSON from relay: %.80s", raw)
                continue

            if msg[0] == "EVENT" and len(msg) >= 3 and msg[1] == sub_id:
                asyncio.create_task(handle_event(ws, msg[2]))
            elif msg[0] == "EOSE":
                log.info("EOSE — backlog done, listening for new DMs")
            elif msg[0] == "NOTICE":
                log.info("NOTICE: %s", msg[1] if len(msg) > 1 else "(empty)")
            elif msg[0] == "AUTH":
                # Mid-session challenge
                challenge = msg[1]
                log.info("Mid-session AUTH challenge: %.40s", challenge)
                auth_ev = minipae.build_auth_event(challenge, RELAY_AUTH_TAG, SK_BYTES)
                await ws.send(json.dumps(["AUTH", auth_ev]))
            elif msg[0] == "CLOSED":
                log.warning("Subscription CLOSED: %.200s", raw)
                break
            elif msg[0] == "OK":
                log.debug("OK: %.80s", raw)


# ── Reconnect loop ────────────────────────────────────────────────────────────
async def main():
    backoff = 5
    while True:
        try:
            await run_agent()
            backoff = 5
        except Exception as exc:
            log.error("Agent crashed (%s) — reconnecting in %ds", exc, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 120)


if __name__ == "__main__":
    asyncio.run(main())
