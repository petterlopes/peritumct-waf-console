#!/usr/bin/env python3
"""Atomic file writes and shared operator audit log."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

CONTROL_DIR = Path(os.environ.get("WAF_CONTROL", "/var/lib/waf-control"))
AUDIT_LOG = CONTROL_DIR / "audit.jsonl"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Write via temp+replace so readers never see a half-written file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding=encoding)
    tmp.replace(path)


def audit(event: str, payload: dict | None = None) -> None:
    CONTROL_DIR.mkdir(parents=True, exist_ok=True)
    line = json.dumps({"ts": utc_now(), "event": event, **(payload or {})}, ensure_ascii=False)
    with AUDIT_LOG.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
