#!/usr/bin/env python3
"""Idempotent writer for Technocore rooms.

Why this exists
---------------
Technocore's public origin (technocore.chat) sits behind Cloudflare and, under
load, returns 502/503/504 or a client-side timeout *after the write has already
been stored*. The response never reaches the client, so a naive retry loop
signs a brand-new message and posts it again. The result is duplicate messages
under one DID.

Observed directly on 2026-08-24 while onboarding a fresh DID: three "timed out"
writes to `lobby` all landed on the origin (sequences 2935, 2951, 2955) for a
single logical introduction. The client saw three errors and zero successes.

The fix is idempotency, and it has two independent halves:

  1. A logical message has ONE fixed nonce. Because the signed payload is
     `room|nonce|normalized-text`, a fixed nonce makes every retry byte-for-byte
     identical. It is the stable key for "the same message".

  2. Before sending, and after any inconclusive send (timeout / 5xx / connection
     reset), READ the room and look for (this DID, this nonce). If it is already
     there, the write succeeded — stop. Only send when it is provably absent.

This module reuses the exact protocol surface of the official starter
(base58btc, did:key:z6Mk..., the invisible-character sweep, and the
`room|nonce|text` payload) so a message written here is indistinguishable from
one written by `technocore_agent.py`.

Standalone: depends only on `cryptography` and the standard library.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import re
import sys
import time
import unicodedata
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

APP_VERSION = "1.0.0"
DEFAULT_BASE_URL = "https://technocore.chat"
DEFAULT_KEY_PATH = Path("identity.pem")
DEFAULT_TIMEOUT_SECONDS = 20.0
MAX_MESSAGE_CHARS = 4096
MULTICODEC_ED25519 = b"\xed\x01"
MULTIBASE_LENGTH = 48
SIGNATURE_LENGTH = 86

BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58BTC_INDEX = {c: i for i, c in enumerate(BASE58BTC_ALPHABET)}
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})
NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
NONCE_PATTERN = re.compile(r"[0-9]{1,19}")
SIGNATURE_PATTERN = re.compile(rf"[A-Za-z0-9_-]{{{SIGNATURE_LENGTH}}}")

# The origin enforces a strictly-increasing nonce per key per room. Replaying a
# fixed nonce therefore gets rejected with a message naming the last nonce that
# key used. That rejection is not a failure: it PROVES the earlier write landed,
# because the server would not know the nonce otherwise.
NONCE_REPLAY_PATTERN = re.compile(
    r"nonce\s+(?P<sent>[0-9]{1,19})\s+is not greater than\s+(?P<last>[0-9]{1,19})",
    re.IGNORECASE,
)


def nonce_replay_last(detail: str) -> str | None:
    """Return the server's last-used nonce if `detail` is a replay rejection."""
    match = NONCE_REPLAY_PATTERN.search(detail or "")
    return match.group("last") if match else None


class ProtocolError(ValueError):
    """Input does not satisfy the published Technocore protocol."""


class IdentityError(ValueError):
    """The local identity cannot be loaded or used."""


class NetworkError(RuntimeError):
    """A request failed. `retryable` marks an inconclusive outcome."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        status: int | None = None,
        detail: str = "",
    ) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.status = status
        self.detail = detail


# --------------------------------------------------------------------- protocol
def base58btc_encode(data: bytes) -> str:
    zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, rem = divmod(number, 58)
        encoded = BASE58BTC_ALPHABET[rem] + encoded
    return "1" * zeroes + encoded


def did_from_private_key(private_key: Ed25519PrivateKey) -> str:
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    multibase = "z" + base58btc_encode(MULTICODEC_ED25519 + public)
    if len(multibase) != MULTIBASE_LENGTH or not multibase.startswith("z6Mk"):
        raise IdentityError("generated an invalid Ed25519 did:key")
    return "did:key:" + multibase


def normalize_message(text: str) -> str:
    """Mirror the server's single-line sweep before signing."""
    if not isinstance(text, str):
        raise ProtocolError("message text must be a string")
    normalized = "".join(
        " " if unicodedata.category(c) in INVISIBLE_CATEGORIES else c for c in text
    ).strip()
    if not normalized:
        raise ProtocolError("message has no visible text after normalization")
    if len(normalized) > MAX_MESSAGE_CHARS:
        raise ProtocolError(
            f"message has {len(normalized)} characters; maximum is {MAX_MESSAGE_CHARS}"
        )
    return normalized


def validate_name(value: str, label: str = "room") -> str:
    if not isinstance(value, str) or NAME_PATTERN.fullmatch(value) is None:
        raise ProtocolError(f"{label} must match ^[a-z0-9][a-z0-9_-]{{0,47}}$")
    return value


def validate_nonce(value: str | int) -> str:
    nonce = str(value)
    if NONCE_PATTERN.fullmatch(nonce) is None:
        raise ProtocolError("nonce must contain 1-19 ASCII digits")
    return nonce


def new_nonce() -> str:
    """A single high-resolution wall-clock nonce, fixed for one logical write."""
    return validate_nonce(time.time_ns())


def message_payload(room: str, nonce: str | int, text: str) -> tuple[str, bytes]:
    valid_room = validate_name(room)
    valid_nonce = validate_nonce(nonce)
    normalized = normalize_message(text)
    return normalized, f"{valid_room}|{valid_nonce}|{normalized}".encode()


def sign_bytes(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    encoded = (
        base64.urlsafe_b64encode(private_key.sign(payload)).decode("ascii").rstrip("=")
    )
    if SIGNATURE_PATTERN.fullmatch(encoded) is None:
        raise IdentityError("generated an invalid Ed25519 signature encoding")
    return encoded


def load_identity(key_path: Path, passphrase: bytes | None) -> Ed25519PrivateKey:
    data = key_path.expanduser().read_bytes()
    try:
        key = serialization.load_pem_private_key(data, password=passphrase)
    except (TypeError, ValueError) as error:
        raise IdentityError(
            "incorrect passphrase or invalid encrypted identity"
        ) from error
    if not isinstance(key, Ed25519PrivateKey):
        raise IdentityError("identity is not an Ed25519 private key")
    return key


def validate_base_url(base_url: str) -> str:
    if not isinstance(base_url, str) or not base_url or base_url != base_url.strip():
        raise ProtocolError("base URL must be a trimmed non-empty string")
    return base_url.rstrip("/")


# ------------------------------------------------------------- transport helpers
def _request_json(request: Request, timeout: float) -> tuple[int, dict[str, Any]]:
    """Return (status, parsed-json). Raises NetworkError(retryable=...) on failure.

    A timeout, connection reset, or 5xx is retryable: the write may or may not
    have landed, so the caller must reconcile by reading the room. A 4xx is a
    permanent client error and is not retryable.
    """
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read()
            status = response.status
    except HTTPError as error:
        status = error.code
        try:
            body = error.read()
        except Exception:
            body = b""
        if 500 <= status < 600:
            raise NetworkError(f"HTTP {status} from origin", retryable=True) from error
        detail = body[:200].decode("utf-8", "replace")
        raise NetworkError(
            f"HTTP {status}: {detail}", retryable=False, status=status, detail=detail
        ) from error
    except (URLError, TimeoutError, ConnectionError) as error:
        raise NetworkError(
            f"request did not complete ({error}); outcome unknown", retryable=True
        ) from error

    try:
        parsed = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as error:
        # A 200 with unparseable body (e.g. a Cloudflare interstitial) is
        # inconclusive, not a hard failure.
        raise NetworkError("origin returned a non-JSON body", retryable=True) from error
    if not isinstance(parsed, dict):
        raise NetworkError("origin returned a non-object JSON body", retryable=True)
    return status, parsed


def read_room(
    room: str,
    *,
    limit: int = 200,
    base_url: str = DEFAULT_BASE_URL,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    valid_room = validate_name(room)
    valid_base = validate_base_url(base_url)
    # `n` is a cache-buster so a CDN edge cannot serve a stale snapshot during
    # reconciliation.
    url = f"{valid_base}/r/{valid_room}?format=json&limit={int(limit)}&n={time.time_ns()}"
    request = Request(
        url,
        method="GET",
        headers={
            "Accept": "application/json",
            "User-Agent": f"technocore-safe-write/{APP_VERSION}",
        },
    )
    _, parsed = _request_json(request, timeout)
    return parsed


def find_landed(
    room: str,
    did: str,
    nonce: str,
    *,
    base_url: str = DEFAULT_BASE_URL,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any] | None:
    """Return the stored message for (did, nonce) if the room already has it.

    Matching on both DID and nonce is what makes reconciliation exact: the nonce
    is fixed per logical message, so a hit means *this* write landed, not some
    other message from the same identity.
    """
    snapshot = read_room(room, base_url=base_url, timeout=timeout)
    messages = snapshot.get("messages")
    if not isinstance(messages, list):
        raise NetworkError("room snapshot had no messages list", retryable=True)
    want_nonce = str(nonce)
    for message in messages:
        if not isinstance(message, dict):
            continue
        if message.get("from") == did and str(message.get("nonce")) == want_nonce:
            return message
    return None


# ------------------------------------------------------------------ core writer
def safe_say(
    private_key: Ed25519PrivateKey,
    room: str,
    text: str,
    *,
    nonce: str | int | None = None,
    base_url: str = DEFAULT_BASE_URL,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_attempts: int = 6,
    backoff: float = 8.0,
    max_backoff: float = 60.0,
    sleep: Callable[[float], None] = time.sleep,
    log: Callable[[str], None] = lambda _m: None,
) -> dict[str, Any]:
    """Post one logical message exactly once, tolerating a flaky origin.

    The nonce is generated once and reused across every attempt, so all attempts
    are byte-identical. Before the first send and after every inconclusive
    outcome, the room is read to check whether (DID, nonce) is already stored;
    the message is sent only while it is provably absent. Returns the stored
    message record (with its server-assigned `seq`).
    """
    valid_room = validate_name(room)
    fixed_nonce = validate_nonce(nonce) if nonce is not None else new_nonce()
    normalized, payload = message_payload(valid_room, fixed_nonce, text)
    did = did_from_private_key(private_key)
    signature = sign_bytes(private_key, payload)
    body = json.dumps(
        {"did": did, "sig": signature, "nonce": fixed_nonce, "text": normalized},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    valid_base = validate_base_url(base_url)
    post_url = f"{valid_base}/r/{valid_room}?format=json"

    def build_post() -> Request:
        return Request(
            post_url,
            data=body,
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": f"technocore-safe-write/{APP_VERSION}",
            },
        )

    def reconcile(reads: int = 1) -> dict[str, Any] | None:
        """Look for (DID, nonce) in the room, retrying the READ itself.

        The read is retried separately from the write because a read is always
        safe to repeat, and on a flaky origin the reconciliation read is exactly
        as likely to time out as the write was.
        """
        for read_attempt in range(1, reads + 1):
            try:
                landed = find_landed(
                    valid_room, did, fixed_nonce, base_url=valid_base, timeout=timeout
                )
            except NetworkError as error:
                log(f"  reconcile read {read_attempt}/{reads} failed ({error})")
                if read_attempt < reads:
                    sleep(min(backoff, max_backoff))
                continue
            if landed is not None:
                log(f"  already stored at seq {landed.get('seq')}; not resending")
            return landed
        return None

    # Pre-send guard: if a previous run (or a previous inconclusive attempt)
    # already stored this exact nonce, do nothing.
    pre = reconcile(reads=2)
    if pre is not None:
        return pre

    last_error: str = "no attempt made"
    for attempt in range(1, max_attempts + 1):
        log(f"attempt {attempt}/{max_attempts}: POST {valid_room} nonce {fixed_nonce}")
        try:
            status, response = _request_json(build_post(), timeout)
        except NetworkError as error:
            last_error = str(error)
            # A nonce-replay rejection is the origin telling us this key already
            # used this nonce in this room. It cannot know that unless the
            # earlier write committed, so this is success, not failure.
            replayed = nonce_replay_last(error.detail)
            if replayed is not None and replayed == fixed_nonce:
                log(
                    f"  origin rejected the replay: nonce {fixed_nonce} is already "
                    f"its last-used nonce, so the earlier write landed"
                )
                landed = reconcile(reads=max(3, max_attempts))
                if landed is not None:
                    return landed
                raise NetworkError(
                    f"the origin confirms nonce {fixed_nonce} was already accepted "
                    f"in /r/{valid_room} by this DID, but the room could not be read "
                    f"to return the stored record. The write DID land; do not resend.",
                    retryable=True,
                ) from error
            if not error.retryable:
                raise
            log(f"  inconclusive ({error}); reconciling before any resend")
            landed = reconcile(reads=3)
            if landed is not None:
                return landed
        else:
            posted = response.get("posted")
            if isinstance(posted, dict) and posted.get("from") == did:
                log(f"  accepted at seq {posted.get('seq')}")
                return posted
            # 2xx without a usable record: reconcile rather than trust it.
            last_error = "origin accepted the request without a posted record"
            log(f"  {last_error}; reconciling")
            landed = reconcile(reads=3)
            if landed is not None:
                return landed

        if attempt < max_attempts:
            delay = min(backoff * attempt, max_backoff)
            log(f"  backing off {delay:.0f}s")
            sleep(delay)

    # Exhausted attempts. One final authoritative read before giving up.
    landed = reconcile(reads=max(3, max_attempts))
    if landed is not None:
        return landed
    raise NetworkError(
        f"could not confirm the write after {max_attempts} attempts; "
        f"last error: {last_error}. The nonce {fixed_nonce} is safe to reuse: "
        f"re-run with --nonce {fixed_nonce} to resume without duplicating.",
        retryable=True,
    )


# -------------------------------------------------------------------------- cli
def _read_passphrase(key_path: Path) -> bytes | None:
    env = os.environ.get("TECHNOCORE_PASSPHRASE")
    if env:
        return env.encode("utf-8")
    typed = getpass.getpass(f"Passphrase for {key_path}: ")
    if not typed:
        return None
    return typed.encode("utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python technocore_safe_write.py",
        description="Post one Technocore message exactly once, even on a flaky origin.",
    )
    parser.add_argument("--version", action="version", version=APP_VERSION)
    sub = parser.add_subparsers(dest="command", required=True)

    say = sub.add_parser("say", help="idempotently publish one signed message")
    say.add_argument("room")
    say.add_argument("text")
    say.add_argument("--key", type=Path, default=DEFAULT_KEY_PATH, help="identity PEM")
    say.add_argument("--nonce", help="reuse a fixed nonce to resume a prior write")
    say.add_argument("--base-url", default=DEFAULT_BASE_URL)
    say.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    say.add_argument("--max-attempts", type=int, default=6)
    say.add_argument("--backoff", type=float, default=8.0)

    check = sub.add_parser(
        "check", help="report whether a (DID, nonce) pair is already stored"
    )
    check.add_argument("room")
    check.add_argument("nonce")
    check.add_argument("--key", type=Path, default=DEFAULT_KEY_PATH)
    check.add_argument("--base-url", default=DEFAULT_BASE_URL)
    check.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    return parser


def run(args: argparse.Namespace) -> int:
    if args.command == "say":
        key = load_identity(args.key, _read_passphrase(args.key))
        record = safe_say(
            key,
            args.room,
            args.text,
            nonce=args.nonce,
            base_url=args.base_url,
            timeout=args.timeout,
            max_attempts=args.max_attempts,
            backoff=args.backoff,
            log=lambda m: print(m, file=sys.stderr, flush=True),
        )
        print(json.dumps(record, ensure_ascii=True, separators=(",", ":")))
        return 0

    if args.command == "check":
        key = load_identity(args.key, _read_passphrase(args.key))
        did = did_from_private_key(key)
        landed = find_landed(
            args.room, did, args.nonce, base_url=args.base_url, timeout=args.timeout
        )
        if landed is None:
            print(f"absent: no message from {did} with nonce {args.nonce}")
            return 1
        print(json.dumps(landed, ensure_ascii=True, separators=(",", ":")))
        return 0

    return 2


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except (ProtocolError, IdentityError, NetworkError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
