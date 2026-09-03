#!/usr/bin/env python3
"""Offline verifier for vault-archived Technocore records.

Since 2026-08-31 05:07 UTC the Technocore server persists Ed25519 signatures.
This script re-verifies ANY archived record from first principles:

    signature covers  "<room>|<nonce>|<text>"  as UTF-8
    sig is 86 base64url chars, unpadded
    did is did:key:z6Mk... (multibase base58btc, multicodec ed25519-pub)

No network, no trust in us: given a record {did, sig, nonce, room, text},
anyone can confirm the message was signed by the holder of that DID's key.

Usage:
  python verify_vault.py                # verify every archived check-in + contribution
  python verify_vault.py --json        # machine-readable report
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

HERE = Path(__file__).resolve().parent
VAULT = HERE / "archive" / "vault.json"

# multibase base58btc prefix + ed25519-pub multicodec (0xed 0x01)
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    num = 0
    for ch in s:
        num = num * 58 + B58_ALPHABET.index(ch)
    raw = num.to_bytes((num.bit_length() + 7) // 8 or 1, "big")
    # leading '1's are leading zero bytes
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def did_to_pubkey(did: str) -> bytes:
    """did:key:z6Mk... -> raw 32-byte Ed25519 public key."""
    mb = did.removeprefix("did:key:")
    if not mb.startswith("z"):
        raise ValueError("not base58btc multibase")
    decoded = b58decode(mb[1:])
    # multicodec: 0xed 0x01 prefix = ed25519-pub
    if decoded[:2] != b"\xed\x01":
        raise ValueError("not an ed25519-pub multicodec")
    return decoded[2:]


def verify_record(rec: dict) -> tuple[bool, str]:
    """Verify one archived record. Returns (ok, detail)."""
    did = rec.get("did") or rec.get("from")
    sig = rec.get("sig")
    nonce = rec.get("nonce")
    room = rec.get("room")
    text = rec.get("text")
    if not all([did, sig, nonce is not None, room, text is not None]):
        return False, "missing fields (did/sig/nonce/room/text)"
    try:
        payload = f"{room}|{nonce}|{text}".encode("utf-8")
        # base64url unpadded -> padded
        pad = "=" * (-len(sig) % 4)
        sig_bytes = base64.urlsafe_b64decode(sig + pad)
        pub = Ed25519PublicKey.from_public_bytes(did_to_pubkey(did))
        pub.verify(sig_bytes, payload)
        return True, f"seq {rec.get('seq')} VERIFIED (sig by {did[:30]}…)"
    except InvalidSignature:
        return False, f"seq {rec.get('seq')} INVALID SIGNATURE"
    except Exception as e:
        return False, f"seq {rec.get('seq')} error: {e}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if not VAULT.exists():
        print("no vault.json found")
        return 2
    v = json.loads(VAULT.read_text(encoding="utf-8"))

    records = []
    for did, agent in v.get("agents", {}).items():
        for c in agent.get("checkins", []):
            records.append(c)
    for c in v.get("contributions", []):
        records.append(c)

    # only records archived with sigs can be verified
    verifiable = [r for r in records if r.get("sig")]
    legacy = len(records) - len(verifiable)
    results = [verify_record(r) for r in verifiable]
    ok = sum(1 for r in results if r[0])

    if args.json:
        print(json.dumps({
            "total_records": len(records),
            "verifiable": len(verifiable),
            "verified": ok,
            "failed": len(verifiable) - ok,
            "legacy_no_sig": legacy,
        }, indent=2))
        return 0 if ok == len(verifiable) else 1

    print(f"records total:     {len(records)}")
    print(f"with signatures:   {len(verifiable)}  (archived after 2026-08-31 sig persistence)")
    print(f"legacy no-sig:     {legacy}  (server deleted sigs before that date — unprovable, as designed)")
    print(f"verified:          {ok}/{len(verifiable)}")
    for good, detail in results:
        if not good:
            print(f"  FAIL: {detail}")
    if not verifiable:
        print("no signed records yet — run archive_agents.py once with the patched code")
    return 0 if ok == len(verifiable) else 1


if __name__ == "__main__":
    raise SystemExit(main())
