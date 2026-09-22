#!/usr/bin/env python3
"""Network hardening helpers: loopback-only URLs, probe targets, TTL cache.

SSRF posture for this console: outbound operator URLs (LAPI, metrics, Traefik API)
must resolve to loopback. PUBLIC_IP probe targets must be literal IP addresses
(no DNS). Probe Host/SNI values must be hostname-safe (no header injection).
"""
from __future__ import annotations

import ipaddress
import re
import threading
import time
from typing import Any
from urllib.parse import urlparse

_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_LOOPBACK_NAMES = frozenset({"127.0.0.1", "localhost", "::1"})


class TtlCache:
    """Thread-safe TTL cache for expensive local probes/scrapes."""

    def __init__(self) -> None:
        self._data: dict[Any, tuple[Any, float]] = {}
        self._lock = threading.Lock()

    def get(self, key: Any) -> Any | None:
        now = time.monotonic()
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            value, exp = item
            if now >= exp:
                del self._data[key]
                return None
            return value

    def set(self, key: Any, value: Any, ttl: float) -> None:
        if ttl <= 0:
            return
        with self._lock:
            self._data[key] = (value, time.monotonic() + ttl)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


def sanitize_hostname(host: str) -> str:
    """Reject CR/LF/null and non-hostname characters (SNI / Host header)."""
    value = (host or "").strip().lower()
    if not value or len(value) > 253:
        raise ValueError("invalid host")
    if any(ch in value for ch in ("\r", "\n", "\x00", "/", "\\", " ", ":", "@")):
        raise ValueError("invalid host")
    if not _HOST_RE.match(value):
        raise ValueError("invalid host")
    return value


def assert_probe_server(value: str, *, name: str = "PUBLIC_IP") -> str:
    """PUBLIC_IP must be empty or a literal IPv4/IPv6 address (no DNS)."""
    raw = (value or "").strip()
    if not raw:
        return ""
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError as exc:
        raise ValueError(f"{name} must be a literal IP address") from exc


def assert_loopback_http_url(url: str, *, name: str = "url") -> str:
    """Allow only http(s) to loopback hostnames/addresses."""
    raw = (url or "").strip()
    if not raw:
        raise ValueError(f"{name} is empty")
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"{name} scheme must be http or https")
    if parsed.username or parsed.password:
        raise ValueError(f"{name} must not embed credentials")
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError(f"{name} missing host")
    if host in _LOOPBACK_NAMES:
        return raw.rstrip("/")
    try:
        if ipaddress.ip_address(host).is_loopback:
            return raw.rstrip("/")
    except ValueError:
        pass
    raise ValueError(f"{name} must target loopback (got {host})")


def env_int(name: str, default: int, *, minimum: int = 0, maximum: int = 10_000) -> int:
    import os

    raw = os.environ.get(name, "")
    if not str(raw).strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, min(maximum, value))
