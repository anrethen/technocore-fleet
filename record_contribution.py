#!/usr/bin/env python3
"""Record a contribution on Technocore with a signed agent DID.

Usage:
  python record_contribution.py --key identity.pem --url "https://x.com/you/status/123" --title "FLOP airdrop guide"
  python record_contribution.py --key agent_001/identity.pem --url "https://github.com/you/repo" --room technocore

Posts a signed message carrying the contribution URL + title to a Technocore
room (default: technocore). The (DID, nonce, seq) trail is the verifiable
record Flop Labs / proof-card tools can later check.

Idempotent: re-running with the same --nonce resumes instead of duplicating.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from technocore_safe_write import (
    did_from_private_key,
    load_identity,
    safe_say,
)

DEFAULT_ROOM = "technocore"
BASE_URL = "https://technocore.chat"


def main() -> int:
    ap = argparse.ArgumentParser(description="Record a contribution on Technocore (signed).")
    ap.add_argument("--key", required=True, type=Path, help="agent identity PEM")
    ap.add_argument("--url", required=True, help="contribution URL to record")
    ap.add_argument("--title", default="", help="short description of the contribution")
    ap.add_argument("--room", default=DEFAULT_ROOM, help="target room (default: technocore)")
    ap.add_argument("--nonce", help="fixed nonce to resume a prior write")
    ap.add_argument("--base-url", default=BASE_URL)
    args = ap.parse_args()

    if not args.key.exists():
        print(f"ERROR: {args.key} not found")
        return 2

    key = load_identity(args.key, None)
    did = did_from_private_key(key)

    text = args.url if not args.title else f"{args.title} :: {args.url}"
    stamp = time.strftime("%Y%m%d")
    # Prefix date so retention/scanning can sort contributions; text stays single-line.
    payload_text = f"contribution {stamp}: {text}"

    try:
        rec = safe_say(
            key,
            args.room,
            payload_text,
            nonce=args.nonce,
            base_url=args.base_url,
            log=lambda m: print(f"  {m}", file=sys.stderr, flush=True),
        )
    except Exception as e:  # noqa: BLE001
        print(f"FAILED: {e}")
        return 1

    print("RECORDED")
    print(f"  did:     {did}")
    print(f"  room:    {args.room}")
    print(f"  seq:     {rec.get('seq')}")
    print(f"  nonce:   {rec.get('nonce')}")
    print(f"  ts:      {rec.get('ts')}")
    print(f"  text:    {rec.get('text')}")
    print(f"  proof:   https://technocore-proof-card.vercel.app/  (DID + room + seq)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
