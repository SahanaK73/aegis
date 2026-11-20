"""Egress proof: one deterministic serialization, SHA-256 over those exact bytes.

Rule: the hash is NEVER inside the bytes being hashed. It travels in the
X-Content-SHA256 HTTP header. The server must hash the raw request body it
received (not a re-serialized copy) and compare.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

HASH_HEADER = "X-Content-SHA256"


def serialize_event(event: dict[str, Any]) -> bytes:
    """Deterministic JSON: sorted keys, no whitespace, ASCII only, no NaN."""
    return json.dumps(
        event,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
