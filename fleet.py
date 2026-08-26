#!/usr/bin/env python3
"""Fleet wrapper: generate agents (if missing) then run the weekly routine."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    # generate only the ones not present yet
    existing = len(list(HERE.glob("agent_*/identity.pem")))
    need = max(0, n - existing)
    if need:
        print(f"generating {need} new agents (have {existing})")
        subprocess.run([sys.executable, "generate_agents.py", str(need), str(existing + 1)], check=True)
    return subprocess.run([sys.executable, "run_all_agents.py"], check=True).returncode


if __name__ == "__main__":
    raise SystemExit(main())
