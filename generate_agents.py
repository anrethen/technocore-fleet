#!/usr/bin/env python3
"""Generate N additional agent identities (agent_001/, agent_002/, ...).

Each gets its own Ed25519 key (PKCS8 PEM, unencrypted) + identity.json.
Keys stay local; never committed (covered by .gitignore).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_safe_write import did_from_private_key

HERE = Path(__file__).resolve().parent


def make_agent(folder: Path) -> str:
    folder.mkdir(exist_ok=True)
    pem_path = folder / "identity.pem"
    json_path = folder / "identity.json"
    if pem_path.exists():
        print(f"  skip {folder.name} (already exists)")
        return folder.name
    pk = Ed25519PrivateKey.generate()
    pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    did = did_from_private_key(pk)
    pem_path.write_bytes(pem)
    json_path.write_text(json.dumps({"did": did}, indent=2))
    print(f"  created {folder.name}: {did}")
    return folder.name


def main() -> int:
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    for i in range(start, start + count):
        make_agent(HERE / f"agent_{i:03d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
