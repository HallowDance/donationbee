"""Canonical encoding (LEDGER_SPEC §3): RFC 8785 with VPP's extra restrictions."""

from datetime import UTC, datetime
from typing import Any

import rfc8785

MAX_SAFE_INT = 2**53 - 1


class CanonicalError(ValueError):
    pass


def _check(value: Any, path: str = "$") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise CanonicalError(f"{path}: integer {value} exceeds 2^53-1")
        return
    if isinstance(value, float):
        raise CanonicalError(f"{path}: floats are not allowed")
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalError(f"{path}: non-string key {k!r}")
            _check(v, f"{path}.{k}")
        return
    if isinstance(value, list):
        for i, v in enumerate(value):
            _check(v, f"{path}[{i}]")
        return
    raise CanonicalError(f"{path}: unsupported type {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    _check(value)
    return rfc8785.dumps(value)


def format_ts(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise CanonicalError("naive datetime")
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
