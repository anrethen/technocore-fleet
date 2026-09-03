#!/usr/bin/env python3
"""Extract 32-byte Ed25519 seeds from our fleet identity.pem files.

Outputs hex seeds (one per line: tag<TAB>seed_hex<TAB>did) for the tclk deal
harness. Seeds never leave this machine; the tclk script consumes them locally.
"""
from __future__ import annotations
from pathlib import Path

from cryptography.hazmat.primitives import serialization

HERE = Path(__file__).resolve().parent
OUT = HERE / "tclk_seeds.tsv"

rows = []
pems = [HERE / "identity.pem"] + sorted(HERE.glob("agent_*/identity.pem"))
for pem in pems:
    key = serialization.load_pem_private_key(pem.read_bytes(), password=None)
    raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    # did:key derivation (multibase base58btc, ed25519-pub multicodec)
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    def b58(b: bytes) -> str:
        n = int.from_bytes(b, "big")
        s = ""
        while n:
            n, r = divmod(n, 58)
            s = B58[r] + s
        pad = len(b) - len(b.lstrip(b"\x00"))
        return "1" * pad + s
    did = "did:key:z" + b58(b"\xed\x01" + pub)
    tag = pem.parent.name
    rows.append(f"{tag}\t{raw.hex()}\t{did}")

OUT.write_text("\n".join(rows), encoding="utf-8")
print(f"wrote {len(rows)} seeds -> {OUT}")
for r in rows:
    print(" ", r.split("\t")[0], r.split("\t")[2][:40])
