#!/usr/bin/env python3
"""Archive the latest swarm deal transcript from swarm_log.txt into the vault.

Parses the deal room name out of the swarm-deal.mjs output, exports the
transcript from technocore.chat, and appends it to archive/vault.json under
'deals' (dedup by deal room).
"""
from __future__ import annotations

import json
import re
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
VAULT = HERE / "archive" / "vault.json"
LOG = HERE / "archive" / "swarm_log.txt"
BASE = "https://technocore.chat"

ROOM_RE = re.compile(r"deal room /r/(mb-p-tclk-[0-9a-f]+)")


def http_get(url: str, tries: int = 3) -> str:
    for _ in range(tries):
        try:
            return urllib.request.urlopen(url, timeout=25).read().decode("utf-8", "ignore")
        except Exception:
            time.sleep(4)
    return ""


def main() -> int:
    if not LOG.exists():
        print("no swarm log yet")
        return 0
    text = LOG.read_text(encoding="utf-8", errors="ignore")
    rooms = ROOM_RE.findall(text)
    if not rooms:
        print("no deal room in log")
        return 0
    room = rooms[-1]
    v = json.loads(VAULT.read_text(encoding="utf-8"))
    deals = v.setdefault("deals", [])
    if any(d.get("deal_room") == room for d in deals):
        print(f"{room} already archived")
        return 0
    exp = http_get(f"{BASE}/r/{room}/export")
    recs = [json.loads(x) for x in exp.strip().splitlines() if x.strip()] if exp else []
    deals.append({
        "type": "tclk/1 hash-locked deal",
        "deal_room": room,
        "rail": "paper",
        "payer": "did:key:z6MkpUMrDs158yxRa9ACTAPgqQEbuLx4Q1NbH1hdGVsCeRqa",
        "payee": "did:key:z6MknEvppSwfSrHHuCB1K41SQE8MJUtSiHo6tnBmMp6DTREZ",
        "auditor": "did:key:z6Mkhd9hGEX5qGYnJtuGbkkz7iWrxXXxHTPsCBLm4EFicxcp",
        "transcript": recs,
        "archived_ts": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    VAULT.write_text(json.dumps(v, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"archived {room}: {len(recs)} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
