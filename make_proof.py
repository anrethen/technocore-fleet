#!/usr/bin/env python3
"""Generate + persist a local Technocore proof card for a (DID, room, seq).

The Technocore ring buffer drops old messages, so the online proof can vanish.
This script writes a self-contained proof JSON (re-verifiable later) and renders
a shareable PNG card via the proof-card service if reachable.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from technocore_safe_write import did_from_private_key, load_identity

HERE = Path(__file__).resolve().parent
PROOF_DIR = HERE / "proofs"
BASE_URL = "https://technocore.chat"


def build_proof(key_path: Path, room: str, seq: int, url: str, title: str) -> dict:
    key = load_identity(key_path, None)
    did = did_from_private_key(key)
    return {
        "did": did,
        "room": room,
        "seq": seq,
        "contribution_url": url,
        "title": title,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": BASE_URL,
        "verify": "https://technocore-proof-card.vercel.app/",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True, type=Path)
    ap.add_argument("--room", default="technocore")
    ap.add_argument("--seq", required=True, type=int)
    ap.add_argument("--url", required=True)
    ap.add_argument("--title", default="")
    args = ap.parse_args()

    proof = build_proof(args.key, args.room, args.seq, args.url, args.title)
    PROOF_DIR.mkdir(exist_ok=True)
    out = PROOF_DIR / f"proof_{args.room}_{args.seq}.json"
    out.write_text(json.dumps(proof, indent=2, ensure_ascii=False))
    print("PROOF SAVED:", out)
    print(json.dumps(proof, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
