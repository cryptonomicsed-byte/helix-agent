"""Offline tests for helix-agent: authentication, dispatch, reply protocol, replay.

Covers audit acceptance T03 (legacy DM), T04 (NIP-17 DM, true sender) and the
T11 replay half. Run: python -m pytest -q
"""
import asyncio
import json
import secrets
import time

import minipae
import pytest

import agent as A


def keypair():
    sk = A._throwaway_seckey()
    return sk, minipae.pubkey_from_secret(int.from_bytes(sk, "big")).hex()


async def echo_llm(cfg, messages):
    return "echo:" + messages[-1]["content"]


class FakeWS:
    def __init__(self, incoming=()):
        self.sent, self._in = [], asyncio.Queue()
        for m in incoming:
            self._in.put_nowait(json.dumps(m))

    async def send(self, raw):
        self.sent.append(json.loads(raw))

    async def recv(self):
        return await self._in.get()

    async def ping(self):
        pass


@pytest.fixture
def ctx(tmp_path):
    sk, pub = keypair()
    cfg = A.Config(seckey=sk, state_dir=str(tmp_path))
    return A.Agent(cfg, llm=echo_llm), sk, pub


def read_reply(ev, user_sk, agent_pub):
    """Decrypt a reply exactly as the user's client would."""
    user_pub = minipae.pubkey_from_secret(int.from_bytes(user_sk, "big")).hex()
    return A.unwrap_dm(ev, user_sk, user_pub)


@pytest.mark.parametrize("transport", ["nip04", "nip44", "wrap1", "nip17"])
async def test_reply_uses_senders_protocol_and_reaches_real_sender(ctx, transport):
    agent, _, agent_pub = ctx
    user_sk, user_pub = keypair()
    inbound = A.build_reply_event(transport, agent_pub, "hello", user_sk)
    if transport == "nip17":
        assert inbound["pubkey"] != user_pub            # outer key is a throwaway

    msg = agent.accept(inbound)
    assert msg and msg.sender == user_pub and msg.transport == transport

    reply = await agent.respond(msg)
    assert ["p", user_pub] in reply["tags"]
    got = read_reply(reply, user_sk, agent_pub)
    assert got.transport == transport
    assert got.sender == agent_pub and got.text == "echo:hello"


@pytest.mark.parametrize("signal", [
    {"type": "offer", "call_id": "c1", "sdp": "v=0"},
    {"type": "ice", "call_id": "c1", "candidate": {}},
    {"type": "hangup", "call_id": "c1"},
])
@pytest.mark.parametrize("transport", ["wrap1", "nip17"])
async def test_call_signalling_never_reaches_llm_or_gets_a_reply(ctx, transport, signal):
    agent, _, agent_pub = ctx
    called = []

    async def llm(cfg, messages):
        called.append(messages)
        return "x"
    agent.llm = llm
    user_sk, _ = keypair()
    ws = FakeWS()
    agent.dispatch(ws, A.build_reply_event(transport, agent_pub, json.dumps(signal), user_sk))
    await asyncio.sleep(0.05)
    assert called == [] and ws.sent == []
    assert agent.stats["call_signal"] == 1


def test_json_chat_that_is_not_a_signal_is_still_chat():
    assert not A.is_call_signal('{"type": "note", "call_id": "x"}')
    assert not A.is_call_signal("call me about the offer")
    assert A.is_call_signal('{"type":"offer","call_id":"x","sdp":"v=0"}')


def test_rejects_bad_signature_and_moved_signature(ctx):
    agent, _, agent_pub = ctx
    user_sk, _ = keypair()
    ev = A.build_reply_event("nip44", agent_pub, "hi", user_sk)
    assert agent.accept(dict(ev, sig="00" * 64)) is None
    other = A.build_reply_event("nip44", agent_pub, "different", user_sk)
    assert agent.accept(dict(ev, content=other["content"])) is None
    assert agent.stats["rejected"] == 2


def test_rejects_wrong_addressee(ctx):
    agent, _, _ = ctx
    user_sk, _ = keypair()
    _, someone_else = keypair()
    assert agent.accept(A.build_reply_event("nip17", someone_else, "hi", user_sk)) is None


def test_rejects_seal_impersonating_another_author(ctx):
    agent, agent_sk, agent_pub = ctx
    attacker_sk, _ = keypair()
    _, victim_pub = keypair()
    rumor = {"kind": 14, "content": "send funds", "tags": [], "created_at": int(time.time()),
             "pubkey": victim_pub}
    seal = minipae.sign_event(13, A._nip44_seal(json.dumps(rumor), attacker_sk, agent_pub),
                              [], attacker_sk)
    t = A._throwaway_seckey()
    wrap = minipae.sign_event(1059, A._nip44_seal(json.dumps(seal), t, agent_pub),
                              [["p", agent_pub]], t)
    assert agent.accept(wrap) is None


def test_rejects_forged_seal_signature(ctx):
    agent, _, agent_pub = ctx
    user_sk, user_pub = keypair()
    rumor = {"kind": 14, "content": "hi", "tags": [], "created_at": int(time.time()),
             "pubkey": user_pub}
    seal = minipae.sign_event(13, A._nip44_seal(json.dumps(rumor), user_sk, agent_pub),
                              [], user_sk)
    seal["sig"] = "00" * 64
    t = A._throwaway_seckey()
    wrap = minipae.sign_event(1059, A._nip44_seal(json.dumps(seal), t, agent_pub),
                              [["p", agent_pub]], t)
    assert agent.accept(wrap) is None


def test_replay_is_dropped_even_after_restart(ctx, tmp_path):
    agent, sk, agent_pub = ctx
    user_sk, _ = keypair()
    ev = A.build_reply_event("nip17", agent_pub, "once", user_sk)
    assert agent.accept(ev) is not None
    assert agent.accept(ev) is None
    restarted = A.Agent(A.Config(seckey=sk, state_dir=str(tmp_path)), llm=echo_llm)
    assert restarted.accept(ev) is None
    assert restarted.stats["replay"] == 1


def test_stale_message_is_ignored(ctx, monkeypatch):
    agent, _, agent_pub = ctx
    user_sk, _ = keypair()
    real = time.time
    monkeypatch.setattr(minipae.time, "time", lambda: real() - 7200)
    ev = A.build_reply_event("nip04", agent_pub, "old", user_sk)
    monkeypatch.undo()
    assert agent.accept(ev) is None and agent.stats["stale"] == 1


def test_rate_limit_per_sender(ctx):
    agent, _, agent_pub = ctx
    agent.cfg.rate_per_minute = 2
    user_sk, _ = keypair()
    results = [agent.accept(A.build_reply_event("nip44", agent_pub, f"m{i}", user_sk))
               for i in range(3)]
    assert [r is not None for r in results] == [True, True, False]


async def test_session_auths_then_subscribes_and_replies(ctx):
    agent, _, agent_pub = ctx
    user_sk, _ = keypair()
    ws = FakeWS([["AUTH", "challenge-1"]])
    task = asyncio.create_task(agent.run_session(ws))
    await asyncio.sleep(0.05)
    assert ws.sent[0][0] == "AUTH" and ws.sent[0][1]["kind"] == 22242
    assert len(ws.sent) == 1                      # no REQ before AUTH is accepted
    ws._in.put_nowait(json.dumps(["OK", ws.sent[0][1]["id"], True, ""]))
    await asyncio.sleep(0.05)
    assert ws.sent[1][0] == "REQ"
    ws._in.put_nowait(json.dumps(
        ["EVENT", "helix-dm-sub", A.build_reply_event("nip04", agent_pub, "ping", user_sk)]))
    await asyncio.sleep(0.1)
    assert ws.sent[2][0] == "EVENT" and ws.sent[2][1]["kind"] == 4
    task.cancel()


async def test_session_stops_on_rejected_auth(ctx):
    agent, _, _ = ctx
    ws = FakeWS([["AUTH", "challenge-1"]])
    task = asyncio.create_task(agent.run_session(ws))
    await asyncio.sleep(0.05)
    ws._in.put_nowait(json.dumps(["OK", ws.sent[0][1]["id"], False, "restricted"]))
    with pytest.raises(A.AuthRejected):
        await task


async def test_session_raises_on_closed_so_reconnect_backs_off(ctx):
    agent, _, _ = ctx
    ws = FakeWS([["EOSE", "helix-dm-sub"], ["CLOSED", "helix-dm-sub", "error: shutting down"]])
    with pytest.raises(ConnectionError):
        await agent.run_session(ws)


def test_import_has_no_side_effects_and_logs_no_bodies(ctx, caplog):
    agent, _, agent_pub = ctx
    user_sk, _ = keypair()
    with caplog.at_level("DEBUG"):
        agent.accept(A.build_reply_event("nip44", agent_pub, "my secret message", user_sk))
    assert "my secret message" not in caplog.text


# -- shared brain and persistent memory --------------------------------------

class FakeNipae:
    def __init__(self):
        self.store = {}

    def get(self, slug):
        return self.store.get(slug)

    def set(self, slug, value):
        assert minipae.validate_slug(slug), slug
        self.store[slug] = value
        return True


async def _bridge(card_id="dna_abc", fail=False):
    """A stand-in for agent-voice's HTTP bridge (/health, /chat) on loopback."""
    seen = []

    async def handle(reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        line = head.split(b"\r\n")[0].decode()
        length = 0
        for h in head.split(b"\r\n"):
            if h.lower().startswith(b"content-length:"):
                length = int(h.split(b":")[1])
        body = await reader.readexactly(length) if length else b""
        if line.startswith("GET /health"):
            out, code = {"status": "ok", "card_id": card_id}, 200
        elif fail:
            out, code = {"error": "boom"}, 500
        else:
            req = json.loads(body)
            seen.append(req)
            out, code = {"reply": "grounded:" + req["message"], "session_id": "s",
                         "history": []}, 200
        data = json.dumps(out).encode()
        writer.write(b"HTTP/1.1 %d OK\r\nContent-Type: application/json\r\n"
                     b"Content-Length: %d\r\nConnection: close\r\n\r\n" % (code, len(data)) + data)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}", seen


async def test_chat_goes_to_the_card_grounded_brain_with_history(tmp_path):
    server, url, seen = await _bridge()
    sk, pub = keypair()
    agent = A.Agent(A.Config(seckey=sk, state_dir=str(tmp_path), brain_url=url,
                             card_id="dna_abc"))
    user_sk, _ = keypair()
    try:
        await A.check_brain(agent.cfg)
        for text in ("what are your hours?", "and on sunday?"):
            reply = await agent.respond(agent.accept(A.build_reply_event("nip17", pub, text, user_sk)))
        assert read_reply(reply, user_sk, pub).text == "grounded:and on sunday?"
        assert seen[1]["history"] == [
            {"role": "user", "content": "what are your hours?"},
            {"role": "assistant", "content": "grounded:what are your hours?"}]
    finally:
        server.close()


async def test_brain_for_another_business_is_refused(tmp_path):
    server, url, _ = await _bridge(card_id="dna_other")
    sk, _ = keypair()
    try:
        with pytest.raises(A.BrainMismatch):
            await A.check_brain(A.Config(seckey=sk, state_dir=str(tmp_path),
                                         brain_url=url, card_id="dna_abc"))
    finally:
        server.close()


async def test_brain_failure_gives_safe_reply_and_is_not_remembered(tmp_path):
    server, url, _ = await _bridge(fail=True)
    sk, pub = keypair()
    mem = FakeNipae()
    agent = A.Agent(A.Config(seckey=sk, state_dir=str(tmp_path), brain_url=url),
                    memory=A.ContactMemory("dna_abc", client=mem))
    user_sk, _ = keypair()
    try:
        reply = await agent.respond(agent.accept(A.build_reply_event("nip44", pub, "hi", user_sk)))
        assert read_reply(reply, user_sk, pub).text == A.UNAVAILABLE
        assert mem.store == {}
    finally:
        server.close()


async def test_history_survives_restart_and_stays_per_contact(tmp_path):
    sk, pub = keypair()
    mem = FakeNipae()
    captured = []

    async def llm(cfg, messages):
        captured.append(messages)
        return "ok"

    def boot():
        return A.Agent(A.Config(seckey=sk, state_dir=str(tmp_path)), llm=llm,
                       memory=A.ContactMemory("dna_abc", client=mem))

    alice, _ = keypair()
    bob, _ = keypair()
    await boot().respond(boot().accept(A.build_reply_event("nip44", pub, "I am Alice", alice)))
    agent = boot()                                              # restart
    await agent.respond(agent.accept(A.build_reply_event("nip44", pub, "who am I?", alice)))
    await agent.respond(agent.accept(A.build_reply_event("nip44", pub, "who am I?", bob)))
    assert [m["content"] for m in captured[1]] == ["I am Alice", "ok", "who am I?"]
    assert [m["content"] for m in captured[2]] == ["who am I?"]     # Bob sees nothing of Alice
    assert all(k.startswith("mem/helix/dna_abc/dm/") for k in mem.store)


async def test_memory_is_off_by_default_and_outage_does_not_block(tmp_path):
    sk, pub = keypair()
    assert A.Agent(A.Config(seckey=sk, state_dir=str(tmp_path)), llm=echo_llm).memory is None

    class Down:
        def get(self, slug): raise OSError("relay down")
        def set(self, slug, value): raise OSError("relay down")

    agent = A.Agent(A.Config(seckey=sk, state_dir=str(tmp_path)), llm=echo_llm,
                    memory=A.ContactMemory("dna_abc", client=Down()))
    user_sk, _ = keypair()
    reply = await agent.respond(agent.accept(A.build_reply_event("nip44", pub, "hi", user_sk)))
    assert read_reply(reply, user_sk, pub).text == "echo:hi"


def test_compiled_system_prompt_file_is_used(tmp_path):
    f = tmp_path / "system-prompt.md"
    f.write_text("You are the AI employee of Santino's Pizza.")
    sk, _ = keypair()
    assert "Santino" in A.system_prompt(A.Config(seckey=sk, system_prompt_file=str(f)))
