#!/usr/bin/env python3
"""Spec for technocore_safe_write, run against a real HTTP server.

The server here is not a stub that returns canned strings: it stores messages,
assigns sequences, enforces the `room|nonce|text` signature, and serves the same
`?format=json` room snapshot shape as technocore.chat. That matters, because the
bug being fixed is a *storage* bug seen through a broken response, so a mock that
does not store cannot demonstrate the fix.

The failure mode reproduced in FLAKY mode is the exact one observed live on
2026-08-24: the write is committed, then the response is destroyed before it
reaches the client (connection closed / 502 / hang). A naive retry loop signs a
new nonce and writes again, producing duplicates.

Proven here:
  A. baseline: a healthy origin stores exactly one message
  B. the naive pattern (new nonce per attempt) DUPLICATES under FLAKY mode
  C. safe_say stores exactly ONE message under the same FLAKY mode
  D. safe_say is resumable: re-running with the same nonce never writes twice
  E. the pre-send guard means an already-stored nonce triggers zero POSTs
  F. a hard 4xx is not retried (permanent errors must not loop)
  G. signatures produced here verify against the DID (protocol compatibility)
"""

from __future__ import annotations

import base64
import json
import re
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import technocore_safe_write as T

INVISIBLE = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})

fails: list[str] = []


def ok(cond: bool, msg: str) -> None:
    print(("  PASS " if cond else "  FAIL ") + msg)
    if not cond:
        fails.append(msg)


# ------------------------------------------------------------------ mock origin
class Origin:
    """Stores messages the way the real room does, and can break responses."""

    def __init__(self) -> None:
        self.rooms: dict[str, list[dict]] = {}
        self.seq = 0
        self.mode = "healthy"  # healthy | flaky | reject
        self.post_count = 0
        self.flaky_pattern: list[str] = []
        self.lock = threading.Lock()
        # Highest nonce accepted per (room, did), like the real origin.
        self.last_nonce: dict[tuple[str, str], int] = {}

    def store(self, room: str, did: str, nonce: str, text: str) -> dict:
        with self.lock:
            self.seq += 1
            record = {
                "seq": self.seq,
                "from": did,
                "nonce": nonce,
                "text": text,
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            self.rooms.setdefault(room, []).append(record)
            return record

    def snapshot(self, room: str, limit: int) -> dict:
        with self.lock:
            msgs = self.rooms.get(room, [])[-limit:]
            return {
                "room": room,
                "last_seq": self.seq,
                "messages": msgs,
            }

    def count(self, room: str, did: str) -> int:
        with self.lock:
            return sum(1 for m in self.rooms.get(room, []) if m["from"] == did)


ORIGIN = Origin()


def normalize(text: str) -> str:
    return "".join(
        " " if unicodedata.category(c) in INVISIBLE else c for c in text
    ).strip()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a):  # silence
        pass

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        m = re.match(r"/r/([a-z0-9][a-z0-9_-]{0,47})", self.path)
        if not m:
            self._json(404, {"error": "no such room"})
            return
        limit = 200
        lm = re.search(r"[?&]limit=(\d+)", self.path)
        if lm:
            limit = int(lm.group(1))
        self._json(200, ORIGIN.snapshot(m.group(1), limit))

    def do_POST(self) -> None:
        m = re.match(r"/r/([a-z0-9][a-z0-9_-]{0,47})", self.path)
        if not m:
            self._json(404, {"error": "no such room"})
            return
        room = m.group(1)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw)
        except ValueError:
            self._json(400, {"error": "bad json"})
            return

        did = payload.get("did", "")
        sig = payload.get("sig", "")
        nonce = str(payload.get("nonce", ""))
        text = normalize(payload.get("text", ""))

        with ORIGIN.lock:
            ORIGIN.post_count += 1
            index = ORIGIN.post_count

        if ORIGIN.mode == "reject":
            self._json(400, {"error": "room is closed for writes"})
            return

        # Real signature check over the exact protocol payload.
        try:
            pk = public_key_from_did(did)
            pk.verify(base64.urlsafe_b64decode(sig + "=="), f"{room}|{nonce}|{text}".encode())
        except Exception:
            self._json(403, {"error": "signature does not verify"})
            return

        # The real origin requires a strictly-increasing nonce per key per room,
        # and names its last-used nonce when it rejects a replay.
        with ORIGIN.lock:
            seen = ORIGIN.last_nonce.get((room, did))
        if seen is not None and int(nonce) <= seen:
            self._json(
                400,
                {
                    "error": f"400 nonce {nonce} is not greater than {seen}, the last "
                    f"one this key used in /r/{room} - a signed URL is "
                    f"single-use, so count up"
                },
            )
            return

        # THE WRITE COMMITS HERE, before any response is attempted.
        record = ORIGIN.store(room, did, nonce, text)
        with ORIGIN.lock:
            ORIGIN.last_nonce[(room, did)] = int(nonce)

        if ORIGIN.mode == "flaky":
            behaviour = ORIGIN.flaky_pattern[
                min(index - 1, len(ORIGIN.flaky_pattern) - 1)
            ] if ORIGIN.flaky_pattern else "kill"
            if behaviour == "kill":
                # Response destroyed after commit: the client sees a broken
                # connection and cannot tell that the write landed.
                try:
                    self.wfile.close()
                except Exception:
                    pass
                self.close_connection = True
                return
            if behaviour == "502":
                self._json(502, {"error": "bad gateway"})
                return

        self._json(
            200,
            {
                "room": room,
                "last_seq": ORIGIN.seq,
                "posted": record,
                "messages": ORIGIN.snapshot(room, 50)["messages"],
            },
        )


def public_key_from_did(did: str) -> Ed25519PublicKey:
    prefix = "did:key:"
    if not did.startswith(prefix):
        raise ValueError("bad did")
    mb = did[len(prefix) :]
    decoded = base58_decode(mb[1:])
    if len(decoded) != 34 or not decoded.startswith(T.MULTICODEC_ED25519):
        raise ValueError("bad multicodec")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def base58_decode(value: str) -> bytes:
    number = 0
    for ch in value:
        number = number * 58 + T.BASE58BTC_INDEX[ch]
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * zeroes + decoded


# ---------------------------------------------------------------------- harness
server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
BASE = f"http://127.0.0.1:{server.server_address[1]}"
threading.Thread(target=server.serve_forever, daemon=True).start()

KEY = Ed25519PrivateKey.generate()
DID = T.did_from_private_key(KEY)
NOSLEEP = lambda _s: None
TEXT = "Hello from a Technocore contributor testing idempotent writes."


def reset(mode: str, pattern: list[str] | None = None) -> None:
    with ORIGIN.lock:
        ORIGIN.rooms.clear()
        ORIGIN.seq = 0
        ORIGIN.post_count = 0
        ORIGIN.last_nonce.clear()
    ORIGIN.mode = mode
    ORIGIN.flaky_pattern = pattern or []


print(f"mock origin on {BASE}")
print(f"test DID {DID}\n")

print("G. protocol compatibility: signature verifies against the DID")
normalized, payload = T.message_payload("lobby", "12345", TEXT)
sig = T.sign_bytes(KEY, payload)
try:
    public_key_from_did(DID).verify(base64.urlsafe_b64decode(sig + "=="), payload)
    ok(True, "signature over room|nonce|text verifies against did:key")
except Exception as e:
    ok(False, f"signature failed to verify: {e}")
ok(len(DID) == len("did:key:") + 48 and DID.startswith("did:key:z6Mk"),
   "DID is the canonical 48-char z6Mk multibase form")

print("\nA. baseline: healthy origin stores exactly one message")
reset("healthy")
rec = T.safe_say(KEY, "lobby", TEXT, base_url=BASE, sleep=NOSLEEP)
ok(ORIGIN.count("lobby", DID) == 1, f"one message stored (seq {rec.get('seq')})")
ok(ORIGIN.post_count == 1, f"exactly one POST issued (got {ORIGIN.post_count})")

print("\nB. the naive pattern duplicates under a flaky origin")
# 4 broken-but-committed responses, then a clean one: exactly what happened live.
reset("flaky", ["kill", "kill", "502", "kill", "ok"])
naive_attempts = 0
for _ in range(5):
    naive_attempts += 1
    try:
        # A NEW nonce each attempt is what a naive retry loop does, because the
        # official `say` command generates one per invocation.
        n, pl = T.message_payload("lobby", T.new_nonce(), TEXT)
        body = json.dumps(
            {"did": DID, "sig": T.sign_bytes(KEY, pl), "nonce": pl.split(b"|")[1].decode(), "text": n},
            separators=(",", ":"),
        ).encode()
        req = T.Request(
            f"{BASE}/r/lobby?format=json",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        T._request_json(req, 5.0)
        break
    except T.NetworkError:
        continue
naive_count = ORIGIN.count("lobby", DID)
print(f"    naive loop: {naive_attempts} attempts -> {naive_count} messages stored")
ok(naive_count > 1, f"naive retry DUPLICATED the message ({naive_count} copies)")

print("\nC. safe_say stores exactly one message under the same flaky origin")
reset("flaky", ["kill", "kill", "502", "kill", "ok"])
rec = T.safe_say(
    KEY, "lobby", TEXT, base_url=BASE, sleep=NOSLEEP,
    log=lambda m: print("    " + m),
)
safe_count = ORIGIN.count("lobby", DID)
ok(safe_count == 1, f"exactly one message stored despite broken responses (got {safe_count})")
ok(rec.get("from") == DID and rec.get("seq") == 1,
   f"returned the stored record (seq {rec.get('seq')})")
first_nonce = rec.get("nonce")

print("\nD. resumable: re-running with the same nonce does not write twice")
posts_before = ORIGIN.post_count
rec2 = T.safe_say(
    KEY, "lobby", TEXT, nonce=first_nonce, base_url=BASE, sleep=NOSLEEP,
    log=lambda m: print("    " + m),
)
ok(ORIGIN.count("lobby", DID) == 1, "still exactly one message after a resume run")
ok(rec2.get("seq") == rec.get("seq"),
   f"resume returned the same seq {rec2.get('seq')}")

print("\nE. pre-send guard: an already-stored nonce issues zero POSTs")
ORIGIN.mode = "healthy"
posts_before = ORIGIN.post_count
T.safe_say(KEY, "lobby", TEXT, nonce=first_nonce, base_url=BASE, sleep=NOSLEEP)
ok(ORIGIN.post_count == posts_before,
   f"no POST issued when the write already landed (delta {ORIGIN.post_count - posts_before})")

print("\nF. a permanent 4xx is not retried")
reset("reject")
raised = None
try:
    T.safe_say(KEY, "lobby", TEXT, base_url=BASE, sleep=NOSLEEP, max_attempts=5)
except T.NetworkError as e:
    raised = e
ok(raised is not None and not raised.retryable,
   f"raised a non-retryable error ({str(raised)[:60]})")
ok(ORIGIN.post_count == 1,
   f"stopped after one POST instead of looping (got {ORIGIN.post_count})")

print("\nH. a nonce-replay 400 is read as proof the write landed")
# The real origin enforces a strictly-increasing nonce per key per room. A retry
# of a fixed nonce is rejected with 400 naming the last-used nonce - which the
# server could only know if the earlier write committed. Reproduced live on
# 2026-08-24 in /r/technocore: attempt 1 timed out, attempt 2 got that 400, and
# the message was in fact stored at seq 148.
reset("flaky", ["kill", "ok"])
replay_log: list[str] = []
rec3 = T.safe_say(
    KEY, "technocore", TEXT, base_url=BASE, sleep=NOSLEEP,
    log=lambda m: (replay_log.append(m), print("    " + m))[0],
)
ok(ORIGIN.count("technocore", DID) == 1,
   f"exactly one message stored (got {ORIGIN.count('technocore', DID)})")
ok(rec3.get("from") == DID and rec3.get("seq") is not None,
   f"returned the stored record (seq {rec3.get('seq')})")

# The parser must extract the server's last-used nonce from the real wording.
live_detail = (
    '{"error": "400 nonce 1787590818170983316 is not greater than '
    '1787590818170983316, the last one this key used in /r/technocore - a '
    'signed URL is single-use, so count up"}'
)
ok(T.nonce_replay_last(live_detail) == "1787590818170983316",
   "parses the last-used nonce out of the live 400 wording")
ok(T.nonce_replay_last('{"error":"room is closed for writes"}') is None,
   "does not misread an unrelated 400 as a nonce replay")

print("\n" + "=" * 60)
server.shutdown()
if fails:
    print(f"{len(fails)} FAILED:")
    for f in fails:
        print("  -", f)
    raise SystemExit(1)
print("all idempotency assertions passed")
