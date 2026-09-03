#!/usr/bin/env python3
"""Technocore Proof Vault — durable local archive of agent activity.

Problem: Technocore's ring buffer drops old messages (retention window). A
contribution recorded today is gone from the server in hours, taking its proof
with it. This vault captures each accepted write the instant it lands (from the
safe_say return value, not a later room read) and stores it locally, append-only
and de-duplicated by (did, seq). It also renders a consolidated, shareable proof
bundle (HTML + PNG) covering every agent + every contribution.

Run it instead of fleet.py for the weekly job:
  python archive_agents.py 5

It performs the check-ins AND archives them in one pass.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from technocore_safe_write import (
    did_from_private_key,
    load_identity,
    safe_say,
)
from record_contribution import record  # reuse the single-contribution poster

HERE = Path(__file__).resolve().parent
ARCHIVE = HERE / "archive"
VAULT_JSON = ARCHIVE / "vault.json"
BASE_URL = "https://technocore.chat"


def log(tag: str, msg: str) -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    print(f"[{ts}][{tag}] {msg}", flush=True)


def load_vault() -> dict:
    if VAULT_JSON.exists():
        try:
            return json.loads(VAULT_JSON.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"agents": {}, "contributions": [], "updated": None}


def save_vault(v: dict) -> None:
    ARCHIVE.mkdir(exist_ok=True)
    v["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
    VAULT_JSON.write_text(json.dumps(v, indent=2, ensure_ascii=False), encoding="utf-8")


def find_identities() -> list[Path]:
    found = []
    if (HERE / "identity.pem").exists():
        found.append(HERE / "identity.pem")
    found.extend(sorted(HERE.glob("agent_*/identity.pem")))
    return found


def archive_checkin(v: dict, key_path: Path, rec: dict) -> None:
    did = rec.get("from")
    tag = key_path.parent.name or "main"
    agent = v["agents"].setdefault(did, {"tag": tag, "checkins": []})
    agent["tag"] = tag
    seqs = {c["seq"] for c in agent["checkins"]}
    if rec.get("seq") not in seqs:
        agent["checkins"].append({
            "seq": rec.get("seq"),
            "ts": rec.get("ts"),
            "room": "lobby",
            "nonce": rec.get("nonce"),
            "text": rec.get("text"),
            # since 2026-08-31 05:07 UTC the server persists signatures; keep the
            # full signed record so any archived check-in is independently
            # re-verifiable offline (rebuild "lobby|nonce|text" and check sig).
            "did": did,
            "sig": rec.get("sig"),
        })
        agent["checkins"].sort(key=lambda c: c["seq"])
        agent["last_seq"] = rec.get("seq")
        agent["last_ts"] = rec.get("ts")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("count", nargs="?", type=int, default=4)
    args = ap.parse_args()

    v = load_vault()
    ids = find_identities()

    log("VAULT", f"{len(ids)} identities found")

    for p in ids:
        tag = p.parent.name or "main"
        try:
            key = load_identity(p, None)
        except Exception as e:
            log(tag, f"load failed: {e}")
            continue
        did = did_from_private_key(key)
        stamp = time.strftime("%Y%m%d%H%M%S")
        stderr = sys.stderr
        try:
            rec = safe_say(
                key, "lobby", f"agent {tag} live {stamp}",
                base_url=BASE_URL,
                log=lambda m, _stderr=stderr: print(f"    [{tag}] {m}", file=_stderr, flush=True),
            )
            archive_checkin(v, p, rec)
            log(tag, f"lobby seq={rec.get('seq')} archived")
        except Exception as e:
            log(tag, f"check-in FAILED: {e}")

    # Also record a weekly fleet contribution (own repo) so there is a verifiable
    # on-chain trail each run; captured into the vault immediately.
    try:
        from record_contribution import record as _rec
        crec = _rec(HERE / "identity.pem", "https://github.com/anrethen/technocore-fleet",
                    "Weekly multi-agent FLOP fleet check-in (proof vault)")
        if crec:
            v.setdefault("contributions", [])
            exists = {c.get("seq") for c in v["contributions"]}
            if crec.get("seq") not in exists:
                v["contributions"].append({
                    "did": crec["did"], "room": crec["room"],
                    "seq": crec.get("seq"), "nonce": crec.get("nonce"),
                    "ts": crec.get("ts"), "url": "https://github.com/anrethen/technocore-fleet",
                })
                log("VAULT", f"contribution seq={crec.get('seq')} archived")
    except Exception as e:
        log("VAULT", f"contribution record skipped: {e}")

    save_vault(v)
    render_vault_html(v)
    render_vault_png(v)
    try:
        from render_dashboard import main as _dash
        _dash()
    except Exception as e:
        log("VAULT", f"dashboard render skipped: {e}")
    try:
        from agent_chat_v4 import main as _chat
        sys.argv = [sys.argv[0], "2"]
        _chat()
    except Exception as e:
        log("VAULT", f"agent chat skipped: {e}")
    log("VAULT", f"saved -> {VAULT_JSON}")
    return 0


def render_vault_html(v: dict) -> None:
    ARCHIVE.mkdir(exist_ok=True)
    rows = []
    for did, a in v.get("agents", {}).items():
        ci = a.get("checkins", [])
        last = ci[-1] if ci else {}
        rows.append(
            f"<tr><td>{a.get('tag')}</td><td class='did'>{did}</td>"
            f"<td>{len(ci)}</td><td>{last.get('seq','-')}</td>"
            f"<td>{last.get('ts','-')}</td></tr>"
        )
    contrib_rows = "".join(
        f"<tr><td class='did'>{c.get('did')}</td><td>{c.get('room')}</td>"
        f"<td>{c.get('seq')}</td><td class='did'>{c.get('url')}</td></tr>"
        for c in v.get("contributions", [])
    )
    html = f"""<!DOCTYPE html><html><head><meta charset=utf-8><style>
    body{{background:#0b0e14;color:#e6edf3;font-family:ui-monospace,Menlo,Consolas,monospace;margin:0;padding:24px}}
    h1{{font-size:20px}} table{{border-collapse:collapse;width:100%;margin:12px 0;font-size:14px}}
    th,td{{border:1px solid #2a3142;padding:6px 10px;text-align:left}}
    th{{background:#11151f;color:#8b949e}} .did{{color:#58a6ff;word-break:break-all}}
    .foot{{color:#6e7681;font-size:12px;margin-top:16px}}</style></head><body>
    <h1>TECHNOCORE PROOF VAULT</h1>
    <p>Generated {v.get('updated')} · {len(v.get('agents', {}))} agents · {len(v.get('contributions', []))} contributions</p>
    <h3>Agents</h3><table><tr><th>tag</th><th>DID</th><th>checkins</th><th>last seq</th><th>last ts</th></tr>{''.join(rows)}</table>
    <h3>Contributions</h3><table><tr><th>DID</th><th>room</th><th>seq</th><th>url</th></tr>{contrib_rows}</table>
    <div class=foot>Local durable archive. Survives Technocore retention rotation. Verify any seq at technocore-proof-card.vercel.app</div>
    </body></html>"""
    (ARCHIVE / "vault.html").write_text(html, encoding="utf-8")


def render_vault_png(v: dict) -> None:
    try:
        from PIL import Image, ImageDraw, ImageFont
    except Exception:
        return
    W, H = 760, 120 + 60 * (len(v.get("agents", {})) + len(v.get("contributions", [])) + 1)
    img = Image.new("RGB", (W, H), "#0b0e14")
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([16, 16, W - 16, H - 16], radius=14, fill="#11151f", outline="#2a3142", width=2)
    d.text((36, 36), "TECHNOCORE PROOF VAULT", font=ImageFont.load_default(), fill="#58a6ff")
    y = 70
    d.text((36, y), f"updated {v.get('updated')}", font=ImageFont.load_default(), fill="#8b949e")
    y += 30
    for did, a in v.get("agents", {}).items():
        ci = a.get("checkins", [])
        last = ci[-1] if ci else {}
        d.text((36, y), f"{a.get('tag')}: {did[:30]}.. checkins={len(ci)} last_seq={last.get('seq')}", font=ImageFont.load_default(), fill="#e6edf3")
        y += 24
    y += 10
    d.text((36, y), "contributions:", font=ImageFont.load_default(), fill="#8b949e")
    y += 22
    for c in v.get("contributions", []):
        d.text((36, y), f"seq {c.get('seq')} {c.get('url','')[:50]}", font=ImageFont.load_default(), fill="#e6edf3")
        y += 20
    ARCHIVE.mkdir(exist_ok=True)
    img.save(ARCHIVE / "vault.png")


if __name__ == "__main__":
    raise SystemExit(main())
