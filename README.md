# helix-agent

Nostr text-DM agent. Authenticates each inbound DM, asks the OmniRouter LLM for a
reply, and answers in the protocol the sender used.

| Inbound | Sender taken from | Reply |
|---|---|---|
| kind 4, NIP-04 payload | verified event signer | kind 4, NIP-04 |
| kind 4, NIP-44 payload | verified event signer | kind 4, NIP-44 |
| kind 1059, NIP-17 (wrap → seal → rumor) | verified seal signer (rumor author must match) | NIP-17 gift wrap |
| kind 1059, single layer | verified event signer | single-layer wrap |

Call signalling JSON (`offer` / `answer` / `ice` / `hangup` with a `call_id`) is
never sent to the LLM and never answered: it belongs to `agent-voice`.

Dropped without a reply: bad id or signature, wrong addressee, replays (ids are
persisted in `HELIX_STATE_DIR`), messages older than an hour, senders over the
rate limit. Message bodies are not logged. A relay that rejects NIP-42
credentials stops the process with exit code 2 instead of retrying.

## One brain per business

Set `HELIX_BRAIN_URL` to the business's agent-voice HTTP bridge (for example
`http://127.0.0.1:8401`, enabled there by `AGENT_VOICE_HTTP_PORT`). Chat then
goes to the same card-grounded agent that answers that business's calls. Set
`HELIX_CARD_ID` as well and the agent refuses to start (exit code 3) if the
bridge serves a different card.

Without a brain URL the agent calls OmniRouter directly. Point
`HELIX_SYSTEM_PROMPT_FILE` at the helixmain compiler's `system-prompt.md` to
ground it; otherwise it uses a generic prompt.

If the brain fails, the contact gets a short "try again" reply and the failed
turn is not kept as history.

## Memory

History is in RAM only by default. `HELIX_MEMORY=minipae` persists each
contact's recent turns as encrypted engrams at
`mem/helix/<card id or "personal">/dm/<sender pubkey>` (needs `NIPAE_NSEC` and
relay settings, as for any minipae client). A memory outage never blocks a
reply.

## Run

    pip install -r requirements.txt
    HELIX_NSEC_HEX=<hex secret key> python agent.py

Optional environment: `HELIX_PUBKEY_HEX` (checked against the secret key),
`HELIX_RELAY_WS`, `HELIX_RELAY_AUTH_TAG`, `HELIX_OMNIROUTER_BASE`,
`HELIX_OMNIROUTER_KEY_FILE`, `HELIX_MODEL`, `HELIX_LOG_PATH`, `HELIX_STATE_DIR`.
Defaults match the previous hardcoded values; `HELIX_STATE_DIR` defaults to
`/opt/ares/helix-agent-state`.

## Test

    pip install pytest pytest-asyncio && python -m pytest -q
