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
