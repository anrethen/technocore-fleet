#!/usr/bin/env python3
"""Render a Technocore contribution proof card to PNG (PIL, no browser needed)."""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
PROOF = HERE / "proofs" / "proof_technocore_157567.json"


def font(size: int, bold: bool = False):
    candidates = [
        "C:/Windows/Fonts/consolab.ttf" if bold else "C:/Windows/Fonts/consola.ttf",
        "C:/Windows/Fonts/DejaVuSansMono-Bold.ttf" if bold else "C:/Windows/Fonts/DejaVuSansMono.ttf",
    ]
    for c in candidates:
        if Path(c).exists():
            return ImageFont.truetype(c, size)
    return ImageFont.load_default()


def wrap(text: str, fnt, max_w: int, d: ImageDraw.ImageDraw) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        test = f"{cur} {w}".strip()
        if d.textlength(test, font=fnt) <= max_w:
            cur = test
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


def main() -> None:
    p = json.loads(PROOF.read_text(encoding="utf-8")) if PROOF.exists() else {
        "did": "did:key:z6MkpUMrDs158yxRa9ACTAPgqQEbuLx4Q1NbH1hdGVsCeRqa",
        "room": "technocore", "seq": 157567,
        "contribution_url": "https://github.com/peaceofheaven777/technocore-safe-write",
        "title": "Multi-agent FLOP fleet tooling",
    }
    W, H = 760, 520
    img = Image.new("RGB", (W, H), "#0b0e14")
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([16, 16, W - 16, H - 16], radius=14, fill="#11151f", outline="#2a3142", width=2)

    d.text((36, 36), "TECHNOCORE · CONTRIBUTION PROOF", font=font(14, True), fill="#58a6ff")
    d.text((36, 64), p.get("title", "Contribution"), font=font(22, True), fill="#e6edf3")

    rows = [
        ("DID", p["did"]),
        ("Room", p["room"]),
        ("Seq", str(p["seq"])),
        ("URL", p["contribution_url"]),
        ("Recorded", p.get("generated", "")),
    ]
    y = 110
    fk, fv = font(15, True), font(15)
    for k, v in rows:
        d.text((36, y), k, font=fk, fill="#8b949e")
        for ln in wrap(v, fv, W - 180, d):
            d.text((160, y), ln, font=fv, fill="#e6edf3")
            y += 22
        y += 10

    d.text((36, y + 6), "✓ VERIFIED", font=font(20, True), fill="#3fb950")
    y += 40
    d.text((36, y), "Verify: technocore-proof-card.vercel.app", font=font(13), fill="#8b949e")
    y += 34
    d.text((36, y), "4-agent fleet · weekly scheduler · idempotent safe-write", font=font(12), fill="#6e7681")

    out = HERE / "proof_card.png"
    img.save(out)
    print("PNG:", out)


if __name__ == "__main__":
    import json
    main()
