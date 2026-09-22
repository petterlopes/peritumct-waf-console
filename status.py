#!/usr/bin/env python3
"""Shared HTTP status semantics for Domains / dashboard KPIs."""
from __future__ import annotations

from typing import Any

APP_VERSION = "1.0.17"
APP_NAME = f"waf-console/{APP_VERSION}"


def http_status_ok(code: Any) -> bool:
    """Operator-healthy probe: 2xx success or 3xx redirect on GET /."""
    try:
        c = int(code)
    except (TypeError, ValueError):
        return False
    return 200 <= c < 400
