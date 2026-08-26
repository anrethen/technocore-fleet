#!/usr/bin/env python3
"""Run the weekly Flop Labs routine for ALL agent identities found in this dir.

Searches for: ./identity.pem (main) + ./agent_NNN/identity.pem (fleet).
For each: sync identity.json, post signed lobby check-in, retry DID note.
Idempotent + safe under the flaky origin (uses safe_say).
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from technocore_safe_write import (
    did_from_private_key,
    load_identity,
    safe_say,
)

HERE = Path(__file__).resolve().parent
BASE_URL = "https://technocore.chat"


def log(tag: str, msg: str) -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    print(f"[{ts}][{tag}] {msg}", flush=True)


def find_identities() -> list[Path]:
    found = []
    if (HERE / "identity.pem").exists():
        found.append(HERE / "identity.pem")
    for p in sorted(HERE.glob("agent_*/identity.pem")):
        found.append(p)
    return found


def sync_json(key_path: Path, did: str) -> None:
    json_path = key_path.parent / "identity.json"
    json_path.write_text(json.dumps({"did": did}, indent=2))


def publish_did_note(key, did: str) -> bool:
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    fp = hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]
    url = f"{BASE_URL}/kv/did/{fp}"
    body = json.dumps({"value": pub}).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        resp = urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "replace")
        log(did[:20], f"DID note published (fp={fp}): {resp[:80]}")
        return True
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:160]
        if e.code == 400 and "note limit" in detail.lower():
            log(did[:20], "DID note deferred (global cap) — retry next run")
            return False
        log(did[:20], f"DID note HTTP {e.code}: {detail}")
        return False
    except Exception as e:  # noqa: BLE001
        log(did[:20], f"DID note error: {e}")
        return False


def run_one(key_path: Path) -> None:
    tag = key_path.parent.name or "main"
    try:
        key = load_identity(key_path, None)
    except Exception as e:  # noqa: BLE001
        log(tag, f"load failed: {e}")
        return
    did = did_from_private_key(key)
    sync_json(key_path, did)

    stamp = time.strftime("%Y%m%d%H%M%S")
    try:
        rec = safe_say(
            key, "lobby", f"agent {tag} live {stamp}",
            base_url=BASE_URL,
            log=lambda m: print(f"    [{tag}] {m}", file=sys.stderr, flush=True),
        )
        log(tag, f"lobby seq={rec.get('seq')} did={did}")
    except Exception as e:  # noqa: BLE001
        log(tag, f"lobby FAILED: {e}")

    publish_did_note(key, did)


def main() -> int:
    ids = find_identities()
    if not ids:
        print("no identities found")
        return 2
    log("ALL", f"running {len(ids)} agents")
    for p in ids:
        run_one(p)
    log("ALL", "done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
