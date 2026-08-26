#!/usr/bin/env python3
"""Weekly Flop Labs $FLOP airdrop agent routine.

1. Posts a signed check-in message to /r/lobby (core proof of activity).
2. Tries to publish the DID note under /kv/did/<fp>. Retries on the
   global-note-cap 400 ("note limit reached") so it lands automatically once
   Technocore reclaims idle notes.
3. Keeps identity.json in sync with the real base58btc DID.

Idempotent: re-running is safe. Run from Task Scheduler weekly.
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
KEY_PATH = HERE / "identity.pem"
JSON_PATH = HERE / "identity.json"
BASE_URL = "https://technocore.chat"


def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def sync_identity_json(did: str) -> None:
    JSON_PATH.write_text(json.dumps({"did": did}, indent=2))
    log(f"identity.json synced -> {did}")


def publish_did_note(key, did: str) -> bool:
    """POST the public key hex to /kv/did/<fp>. Returns True on success."""
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    fp = hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]
    url = f"{BASE_URL}/kv/did/{fp}"
    body = json.dumps({"value": pub}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "replace")
        log(f"DID note published (fp={fp}): {resp[:120]}")
        return True
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:200]
        if e.code == 400 and "note limit" in detail.lower():
            log(f"DID note deferred (global cap full): {detail}")
            return False
        log(f"DID note HTTP {e.code}: {detail}")
        return False
    except Exception as e:  # noqa: BLE001
        log(f"DID note error (will retry next run): {e}")
        return False


def main() -> int:
    if not KEY_PATH.exists():
        log(f"ERROR: {KEY_PATH} missing. Generate it first.")
        return 2

    key = load_identity(KEY_PATH, None)
    did = did_from_private_key(key)
    sync_identity_json(did)

    # 1. Core activity: signed check-in to /r/lobby
    stamp = time.strftime("%Y%m%d%H%M%S")
    try:
        record = safe_say(
            key,
            "lobby",
            f"agent live {stamp}",
            base_url=BASE_URL,
            log=lambda m: print(f"  {m}", file=sys.stderr, flush=True),
        )
        log(f"lobby check-in accepted seq={record.get('seq')} did={did}")
    except Exception as e:  # noqa: BLE001
        log(f"lobby check-in FAILED: {e}")

    # 2. DID note (retry until it lands)
    published = publish_did_note(key, did)
    if not published:
        log("DID note not published this run — will retry next weekly run.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
