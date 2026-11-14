#!/usr/bin/env python3
"""
helix-agent — Nostr DM chat agent (ZeroClaw-lite)

Listens for text DMs addressed to this agent and replies via the OmniRouter LLM:

  * kind 4 with a NIP-04 payload           -> replies kind 4 / NIP-04
  * kind 4 with a NIP-44 payload           -> replies kind 4 / NIP-44
  * kind 1059 NIP-17 gift wrap (3 layers)  -> replies with a NIP-17 gift wrap
  * kind 1059 single-layer wrap            -> replies with a single-layer wrap

Every inbound event is authenticated before it is acted on: ids are recomputed,
signatures verified, and for NIP-17 the sender is the seal signer (the outer key
is a throwaway) whose rumor must name the same author. Replays are dropped.

Call signalling (offer/answer/ice/hangup JSON) shares kind 1059 with chat. It is
never sent to the LLM and never answered here: it belongs to agent-voice.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import secrets
import sys
import time
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

import minipae

KIND_DM = 4
KIND_SEAL = 13
KIND_RUMOR = 14
KIND_GIFT_WRAP = 1059
CALL_SIGNAL_TYPES = {"offer", "answer", "ice", "hangup"}
NIP17_BACKDATE = 2 * 24 * 3600      # NIP-17 wraps may be timestamped up to 2 days back

SYSTEM_PROMPT = (
    "You are Helix, a sovereign AI agent on the omokoda network. "
    "You communicate via Nostr DMs. Be concise and helpful."
)

log = logging.getLogger("helix-agent")


# ── Config ────────────────────────────────────────────────────────────────────
@dataclass
class Config:
    seckey: bytes
    relay_ws: str = "wss://omokoda.duckdns.org:3443/relay"
    relay_auth_tag: str = "wss://omokoda.duckdns.org:3443"   # no path in AUTH tag
    omnirouter_base: str = "http://127.0.0.1:8300/v1"
    omnirouter_key_file: str = "/opt/ares/.omniroute_key_swarm_orchestrator"
    model: str = "free-pool"
    log_path: str = "/opt/ares/ares_logs/helix-agent.log"
    state_dir: str = "/opt/ares/helix-agent-state"
    max_history: int = 20
    context_turns: int = 6
    max_age: int = 3600            # ignore messages older than this (seconds)
    max_future: int = 300          # ... or timestamped further ahead than this
    max_in_flight: int = 32        # bounded work queue; excess is dropped, not queued
    rate_per_minute: int = 20      # per-sender
    # One brain per business: when set, chat goes to the agent-voice HTTP
    # bridge (the same card-grounded agent that answers calls) instead of a
    # separate OmniRouter prompt.
    brain_url: str = ""
    card_id: str = ""              # expected card; the bridge must report the same one
    system_prompt_file: str = ""   # OmniRouter mode: the compiler's system-prompt.md
    memory: str = "off"            # "minipae": persist per-contact history (opt-in)

    @property
    def pubkey_hex(self) -> str:
        return minipae.pubkey_from_secret(int.from_bytes(self.seckey, "big")).hex()

    @classmethod
    def from_env(cls, env=os.environ) -> "Config":
        cfg = cls(seckey=bytes.fromhex(env["HELIX_NSEC_HEX"]))
        declared = env.get("HELIX_PUBKEY_HEX")
        if declared and declared.lower() != cfg.pubkey_hex:
            raise SystemExit("HELIX_PUBKEY_HEX does not match HELIX_NSEC_HEX")
        for attr, var in (("relay_ws", "HELIX_RELAY_WS"),
                          ("relay_auth_tag", "HELIX_RELAY_AUTH_TAG"),
                          ("omnirouter_base", "HELIX_OMNIROUTER_BASE"),
                          ("omnirouter_key_file", "HELIX_OMNIROUTER_KEY_FILE"),
                          ("model", "HELIX_MODEL"),
                          ("log_path", "HELIX_LOG_PATH"),
                          ("state_dir", "HELIX_STATE_DIR"),
                          ("brain_url", "HELIX_BRAIN_URL"),
                          ("card_id", "HELIX_CARD_ID"),
                          ("system_prompt_file", "HELIX_SYSTEM_PROMPT_FILE"),
                          ("memory", "HELIX_MEMORY")):
            if env.get(var):
                setattr(cfg, attr, env[var])
        return cfg


# ── Verification and decryption ───────────────────────────────────────────────
class Rejected(ValueError):
    """An inbound event that must not be acted on."""


@dataclass(frozen=True)
class Inbound:
    sender: str            # authenticated sender pubkey (hex)
    text: str
    transport: str         # "nip04" | "nip44" | "nip17" | "wrap1"
    created_at: int        # the timestamp the sender actually signed/authored
    ids: tuple[str, ...]   # ids to remember for replay protection


def verify_event(ev: dict, what: str = "event") -> str:
    """Recompute the id and check the signature. Returns the signer pubkey hex."""
    try:
        pub = bytes.fromhex(ev["pubkey"])
        sig = bytes.fromhex(ev["sig"])
        actual = minipae.event_id(ev)
        claimed = ev["id"]
    except (KeyError, TypeError, ValueError) as e:
        raise Rejected(f"{what} is malformed: {e}") from None
    if len(pub) != 32 or claimed != actual:
        raise Rejected(f"{what} id does not match its content")
    if not minipae.schnorr_verify(bytes.fromhex(actual), pub, sig):
        raise Rejected(f"{what} signature does not verify")
    return ev["pubkey"]


def _nip04_key(seckey: bytes, peer_hex: str) -> bytes:
    point = minipae._lift_x(int(peer_hex, 16))
    if point is None:
        raise Rejected("invalid peer pubkey")
    x, _ = minipae._point_mul(int.from_bytes(seckey, "big"), point)
    return x.to_bytes(32, "big")


def nip04_decrypt(content: str, seckey: bytes, peer_hex: str) -> str:
    from Crypto.Cipher import AES
    ct_b64, iv_b64 = content.split("?iv=", 1)
    raw = AES.new(_nip04_key(seckey, peer_hex), AES.MODE_CBC,
                  base64.b64decode(iv_b64)).decrypt(base64.b64decode(ct_b64))
    pad = raw[-1]
    if not 1 <= pad <= 16 or raw[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad padding")
    return raw[:-pad].decode("utf-8")


def nip04_encrypt(plaintext: str, seckey: bytes, peer_hex: str) -> str:
    from Crypto.Cipher import AES
    data = plaintext.encode("utf-8")
    pad = 16 - len(data) % 16
    iv = secrets.token_bytes(16)
    ct = AES.new(_nip04_key(seckey, peer_hex), AES.MODE_CBC, iv).encrypt(data + bytes([pad]) * pad)
    return base64.b64encode(ct).decode() + "?iv=" + base64.b64encode(iv).decode()


def _nip44_open(content: str, seckey: bytes, peer_hex: str) -> str:
    return minipae.nip44_decrypt(
        content, minipae.conversation_key(seckey, bytes.fromhex(peer_hex)))


def _nip44_seal(plaintext: str, seckey: bytes, peer_hex: str) -> str:
    return minipae.nip44_encrypt(
        plaintext, minipae.conversation_key(seckey, bytes.fromhex(peer_hex)))


def unwrap_dm(event: dict, seckey: bytes, our_pubkey_hex: str) -> Inbound:
    """Authenticate and decrypt one inbound event. Raises Rejected."""
    kind = event.get("kind") if isinstance(event, dict) else None
    if kind not in (KIND_DM, KIND_GIFT_WRAP):
        raise Rejected("unsupported kind")
    if ["p", our_pubkey_hex] not in event.get("tags", []):
        raise Rejected("not addressed to this agent")
    outer = verify_event(event, "event")
    content = event.get("content", "")

    try:
        if kind == KIND_DM:
            if "?iv=" in content:
                return Inbound(outer, nip04_decrypt(content, seckey, outer), "nip04",
                               event["created_at"], (event["id"],))
            return Inbound(outer, _nip44_open(content, seckey, outer), "nip44",
                           event["created_at"], (event["id"],))

        inner_str = _nip44_open(content, seckey, outer)
    except Rejected:
        raise
    except Exception as e:
        raise Rejected(f"cannot decrypt: {type(e).__name__}") from None

    try:
        inner = json.loads(inner_str)
    except ValueError:
        inner = None
    if not (isinstance(inner, dict) and inner.get("kind") == KIND_SEAL):
        # Single-layer wrap: the outer signer is the real sender.
        return Inbound(outer, inner_str, "wrap1", event["created_at"], (event["id"],))

    seal_signer = verify_event(inner, "seal")
    try:
        rumor = json.loads(_nip44_open(inner["content"], seckey, seal_signer))
    except Exception as e:
        raise Rejected(f"cannot decrypt seal: {type(e).__name__}") from None
    if not isinstance(rumor, dict) or rumor.get("kind") != KIND_RUMOR:
        raise Rejected("seal does not contain a kind:14 rumor")
    if rumor.get("pubkey") != seal_signer:
        raise Rejected("rumor author does not match the seal signer")
    if not isinstance(rumor.get("content"), str) or not isinstance(rumor.get("created_at"), int):
        raise Rejected("rumor is malformed")
    return Inbound(seal_signer, rumor["content"], "nip17", rumor["created_at"],
                   (event["id"], inner["id"]))


def is_call_signal(text: str) -> bool:
    """True for agent-phone call signalling JSON (never chat, never for the LLM)."""
    if not text.lstrip().startswith("{"):
        return False
    try:
        d = json.loads(text)
    except ValueError:
        return False
    return isinstance(d, dict) and d.get("type") in CALL_SIGNAL_TYPES and "call_id" in d


# ── Reply builder ─────────────────────────────────────────────────────────────
def _throwaway_seckey() -> bytes:
    while True:
        sk = secrets.token_bytes(32)
        if 0 < int.from_bytes(sk, "big") < minipae.N:
            return sk


def build_reply_event(transport: str, recipient_hex: str, plaintext: str, seckey: bytes) -> dict:
    """Reply in the same protocol the sender used, so their client can read it."""
    p_tag = [["p", recipient_hex]]
    if transport == "nip04":
        return minipae.sign_event(KIND_DM, nip04_encrypt(plaintext, seckey, recipient_hex),
                                  p_tag, seckey)
    if transport == "nip44":
        return minipae.sign_event(KIND_DM, _nip44_seal(plaintext, seckey, recipient_hex),
                                  p_tag, seckey)
    if transport == "wrap1":
        return minipae.sign_event(KIND_GIFT_WRAP, _nip44_seal(plaintext, seckey, recipient_hex),
                                  p_tag, seckey)
    if transport == "nip17":
        our_hex = minipae.pubkey_from_secret(int.from_bytes(seckey, "big")).hex()
        rumor = {"kind": KIND_RUMOR, "content": plaintext, "tags": p_tag,
                 "created_at": int(time.time()), "pubkey": our_hex}
        seal = minipae.sign_event(
            KIND_SEAL, _nip44_seal(json.dumps(rumor, separators=(",", ":")), seckey, recipient_hex),
            [], seckey)
        throwaway = _throwaway_seckey()
        return minipae.sign_event(
            KIND_GIFT_WRAP,
            _nip44_seal(json.dumps(seal, separators=(",", ":")), throwaway, recipient_hex),
            p_tag, throwaway)
    raise ValueError(f"unknown transport {transport}")


# ── Replay protection ─────────────────────────────────────────────────────────
class SeenStore:
    """Remembers handled event ids across restarts (bounded, append-only file)."""

    def __init__(self, path: Path | None, limit: int = 20000):
        self.path, self.limit = path, limit
        self._ids: OrderedDict[str, None] = OrderedDict()
        if path is not None:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                if path.exists():
                    for line in path.read_text().split()[-limit:]:
                        self._ids[line] = None
                    path.write_text("".join(i + "\n" for i in self._ids))   # compact
            except OSError as e:
                log.warning("seen-store unavailable (%s); replay protection is in-memory only", e)
                self.path = None

    def add(self, ids) -> bool:
        """Record ids. Returns False if any of them was already seen."""
        if any(i in self._ids for i in ids):
            return False
        for i in ids:
            self._ids[i] = None
        while len(self._ids) > self.limit:
            self._ids.popitem(last=False)
        if self.path is not None:
            try:
                with self.path.open("a") as fh:
                    fh.write("".join(i + "\n" for i in ids))
            except OSError as e:
                log.warning("seen-store write failed: %s", e)
        return True


# ── Brain ────────────────────────────────────────────────────────────────────
UNAVAILABLE = "I can't answer right now. Please try again shortly."


class BrainMismatch(RuntimeError):
    """The configured brain serves a different business card than expected."""


def system_prompt(cfg: Config) -> str:
    if cfg.system_prompt_file:
        return Path(cfg.system_prompt_file).read_text()
    return SYSTEM_PROMPT


async def check_brain(cfg: Config) -> None:
    """Fail at startup, not mid-conversation, if the brain is the wrong business."""
    if not (cfg.brain_url and cfg.card_id):
        return
    import httpx
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{cfg.brain_url.rstrip('/')}/health")
        resp.raise_for_status()
        served = resp.json().get("card_id")
    if served != cfg.card_id:
        raise BrainMismatch(f"brain serves card {served!r}, expected {cfg.card_id!r}")


async def call_llm(cfg: Config, messages: list[dict]) -> str:
    """One reply for the conversation in `messages` (last entry is the user turn)."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=45.0) as client:
            if cfg.brain_url:
                resp = await client.post(
                    f"{cfg.brain_url.rstrip('/')}/chat",
                    json={"message": messages[-1]["content"], "history": messages[:-1]})
                resp.raise_for_status()
                return resp.json()["reply"].strip()
            key = Path(cfg.omnirouter_key_file).read_text().strip()
            resp = await client.post(
                f"{cfg.omnirouter_base}/chat/completions",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={"model": cfg.model, "max_tokens": 500,
                      "messages": [{"role": "system", "content": system_prompt(cfg)}] + messages},
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        log.error("brain call failed: %s", type(exc).__name__)
        return UNAVAILABLE


# ── Persistent per-contact memory (opt-in) ────────────────────────────────────
class ContactMemory:
    """Conversation history per contact, as encrypted minipae engrams.

    Slug: mem/helix/<scope>/dm/<sender-pubkey>, where scope is the business
    card id (or "personal"). It is its own namespace on purpose: agent-voice
    loads everything under mem/card/<id>/ into call prompts, and one contact's
    DMs must not surface in another caller's conversation.

    Off unless HELIX_MEMORY=minipae: message history is not stored by default.
    Best-effort throughout — a memory outage never blocks a reply.
    """

    def __init__(self, scope: str, client=None, max_turns: int = 20):
        scope = "".join(c if c in "abcdefghijklmnopqrstuvwxyz0123456789_-" else "-"
                        for c in (scope or "personal").lower())[:64]
        self.prefix, self.max_turns, self._client = f"mem/helix/{scope}/dm/", max_turns, client

    def _get_client(self):
        if self._client is None:
            self._client = minipae.NipaeClient()      # needs NIPAE_NSEC + relays
        return self._client

    def load(self, sender: str) -> list[dict]:
        try:
            raw = self._get_client().get(self.prefix + sender)
            turns = json.loads(raw) if raw else []
            return [t for t in turns if isinstance(t, dict)
                    and t.get("role") in ("user", "assistant")
                    and isinstance(t.get("content"), str)][-self.max_turns:]
        except Exception as e:
            log.warning("memory read failed: %s", type(e).__name__)
            return []

    def save(self, sender: str, turns: list[dict]) -> bool:
        try:
            return bool(self._get_client().set(
                self.prefix + sender, json.dumps(turns[-self.max_turns:], ensure_ascii=False)))
        except Exception as e:
            log.warning("memory write failed: %s", type(e).__name__)
            return False


# ── Agent ─────────────────────────────────────────────────────────────────────
class AuthRejected(RuntimeError):
    """The relay refused our NIP-42 credentials. Retrying will not help."""


@dataclass
class Agent:
    cfg: Config
    llm: object = None                       # async (cfg, messages) -> str
    seen: SeenStore = None
    memory: ContactMemory = None             # None = history lives in RAM only
    stats: dict = field(default_factory=lambda: defaultdict(int))

    def __post_init__(self):
        self.llm = self.llm or call_llm
        if self.seen is None:
            self.seen = SeenStore(Path(self.cfg.state_dir) / "seen-events")
        if self.memory is None and self.cfg.memory == "minipae":
            self.memory = ContactMemory(self.cfg.card_id)
        self.pub = self.cfg.pubkey_hex
        self.conversations = defaultdict(lambda: deque(maxlen=self.cfg.max_history))
        self._locks = defaultdict(asyncio.Lock)          # per-sender ordering
        self._recent = defaultdict(deque)                # per-sender rate window
        self._in_flight = 0
        self._tasks: set = set()

    def _rate_ok(self, sender: str) -> bool:
        window, now = self._recent[sender], time.time()
        while window and window[0] < now - 60:
            window.popleft()
        if len(window) >= self.cfg.rate_per_minute:
            return False
        window.append(now)
        return True

    def accept(self, event: dict) -> Inbound | None:
        """Authenticate, classify and de-duplicate. None means: do nothing."""
        eid = str(event.get("id", "?"))[:12] if isinstance(event, dict) else "?"
        try:
            msg = unwrap_dm(event, self.cfg.seckey, self.pub)
        except Rejected as e:
            self.stats["rejected"] += 1
            log.warning("rejected event %s: %s", eid, e)
            return None
        if is_call_signal(msg.text):
            self.stats["call_signal"] += 1
            log.info("event %s is call signalling — left for agent-voice", eid)
            return None
        now = time.time()
        if msg.created_at < now - self.cfg.max_age or msg.created_at > now + self.cfg.max_future:
            self.stats["stale"] += 1
            return None
        if not msg.text.strip():
            return None
        if not self.seen.add(msg.ids):
            self.stats["replay"] += 1
            return None
        if not self._rate_ok(msg.sender):
            self.stats["rate_limited"] += 1
            log.warning("rate limit hit for %s...", msg.sender[:12])
            return None
        return msg

    async def respond(self, msg: Inbound) -> dict:
        """One chat turn for one sender; returns the signed reply event."""
        async with self._locks[msg.sender]:
            history = self.conversations[msg.sender]
            loop = asyncio.get_running_loop()
            if self.memory is not None and not history:      # first turn since start
                history.extend(await loop.run_in_executor(None, self.memory.load, msg.sender))
            history.append({"role": "user", "content": msg.text})
            reply = await self.llm(self.cfg, list(history)[-self.cfg.context_turns:])
            if reply == UNAVAILABLE:
                history.pop()                 # a failed turn is not conversation history
            else:
                history.append({"role": "assistant", "content": reply})
                if self.memory is not None:
                    await loop.run_in_executor(None, self.memory.save, msg.sender, list(history))
        return build_reply_event(msg.transport, msg.sender, reply, self.cfg.seckey)

    async def _work(self, ws, msg: Inbound):
        try:
            await ws.send(json.dumps(["EVENT", await self.respond(msg)]))
            self.stats["replied"] += 1
            log.info("replied to %s... via %s", msg.sender[:12], msg.transport)
        except Exception as exc:
            log.error("reply to %s... failed: %s", msg.sender[:12], type(exc).__name__)
        finally:
            self._in_flight -= 1

    def dispatch(self, ws, event: dict) -> None:
        msg = self.accept(event)
        if msg is None:
            return
        if self._in_flight >= self.cfg.max_in_flight:
            self.stats["shed"] += 1
            log.warning("overloaded — dropping message from %s...", msg.sender[:12])
            return
        self._in_flight += 1
        task = asyncio.create_task(self._work(ws, msg))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _req(self) -> list:
        now = int(time.time())
        return ["REQ", "helix-dm-sub",
                {"kinds": [KIND_DM], "#p": [self.pub], "since": now - self.cfg.max_age},
                {"kinds": [KIND_GIFT_WRAP], "#p": [self.pub],
                 "since": now - self.cfg.max_age - NIP17_BACKDATE}]

    async def _authenticate(self, ws, challenge: str) -> str:
        ev = minipae.build_auth_event(challenge, self.cfg.relay_auth_tag, self.cfg.seckey)
        await ws.send(json.dumps(["AUTH", ev]))
        return ev["id"]

    async def run_session(self, ws) -> None:
        """Drive one relay connection until it closes. Raises on CLOSED/AuthRejected."""
        pending_auth = None
        try:
            first = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
        except asyncio.TimeoutError:
            first = None
        if first and first[0] == "AUTH":
            pending_auth = await self._authenticate(ws, first[1])
        else:
            await ws.send(json.dumps(self._req()))
            if first:
                self._on_message(ws, first)

        while True:
            try:
                msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=120.0))
            except asyncio.TimeoutError:
                await ws.ping()
                continue
            except ValueError:
                continue
            if not isinstance(msg, list) or not msg:
                continue
            if msg[0] == "AUTH" and len(msg) > 1:
                pending_auth = await self._authenticate(ws, msg[1])
            elif msg[0] == "OK" and len(msg) > 2 and msg[1] == pending_auth:
                pending_auth = None
                if msg[2] is not True:
                    raise AuthRejected(str(msg[3] if len(msg) > 3 else ""))
                log.info("NIP-42 AUTH accepted")
                await ws.send(json.dumps(self._req()))      # (re)subscribe once authenticated
            elif msg[0] == "CLOSED":
                reason = str(msg[2]) if len(msg) > 2 else ""
                if pending_auth is None:                     # not just "auth first, then REQ"
                    raise ConnectionError(f"subscription closed: {reason[:120]}")
            else:
                self._on_message(ws, msg)

    def _on_message(self, ws, msg: list) -> None:
        if msg[0] == "EVENT" and len(msg) >= 3 and msg[1] == "helix-dm-sub":
            self.dispatch(ws, msg[2])
        elif msg[0] == "EOSE":
            log.info("EOSE — backlog done, listening")
        elif msg[0] == "NOTICE":
            log.info("NOTICE: %.200s", msg[1] if len(msg) > 1 else "")

    async def run_forever(self) -> int:
        import websockets
        try:
            await check_brain(self.cfg)
        except BrainMismatch as exc:
            log.critical("%s — stopping", exc)
            return 3
        except Exception as exc:              # brain down at boot: keep trying per message
            log.warning("brain health check failed (%s); continuing", type(exc).__name__)
        backoff = 5
        while True:
            started = time.time()
            try:
                log.info("connecting to %s", self.cfg.relay_ws)
                async with websockets.connect(self.cfg.relay_ws, open_timeout=20,
                                              ping_interval=30, ping_timeout=20,
                                              max_size=4 * 1024 * 1024) as ws:
                    await self.run_session(ws)
            except AuthRejected as exc:
                log.critical("relay rejected NIP-42 credentials (%s) — stopping", exc)
                return 2
            except Exception as exc:
                log.error("session ended (%s: %s)", type(exc).__name__, exc)
            if time.time() - started > 300:
                backoff = 5                                  # it was healthy; start over
            log.info("reconnecting in %ds; stats=%s", backoff, dict(self.stats))
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 120)


def _setup_logging(path: str) -> None:
    try:
        handler: logging.Handler = logging.FileHandler(path)
    except OSError:
        handler = logging.StreamHandler(sys.stderr)
    logging.basicConfig(level=logging.INFO, handlers=[handler],
                        format="%(asctime)s [%(levelname)s] %(message)s")


def main() -> int:
    cfg = Config.from_env()
    _setup_logging(cfg.log_path)
    log.info("Helix pubkey: %s", cfg.pubkey_hex)
    return asyncio.run(Agent(cfg).run_forever())


if __name__ == "__main__":
    sys.exit(main())
