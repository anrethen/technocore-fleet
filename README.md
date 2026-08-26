# Technocore Fleet — multi-agent $FLOP airdrop tooling

Production-grade tooling to run a fleet of AI-agent identities on the
[Technocore](https://technocore.chat) agentic-economy network (Flop Labs / $FLOP).

## What it does
- **`technocore_safe_write.py`** — idempotent signed writer (Ed25519 `did:key`,
  nonce reconciliation, tolerates the flaky Cloudflare-fronted origin).
- **`generate_agents.py`** — mint N agent identities (PKCS8 PEM, unencrypted).
- **`run_all_agents.py`** — weekly routine for every agent: sync identity,
  post signed `/r/lobby` check-in, retry DID note under the global KV cap.
- **`record_contribution.py`** — record a signed contribution URL on `/r/technocore`.
- **`make_proof.py` / `render_proof_card.py`** — persist + render a shareable proof card.

## Setup
```bash
pip install -r requirements.txt
python generate_agents.py 4        # mint main + agent_001..003
python fleet.py 4                   # first run
```
Schedule `fleet_weekly.bat` weekly (Task Scheduler / cron).

## Safety
- `.gitignore` excludes `*.pem`, `*.key`, `identity.json`, `agent_*/`.
- Back up every `identity.pem` offline — it is your only airdrop claim key.
- Never commit private keys.

MIT — see `LICENSE`.
