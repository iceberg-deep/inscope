"""Structured audit logging for in-scope checks."""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DEFAULT_AUDIT_PATH = Path.home() / ".inscope" / "audit.log"
ENV_VAR = "INSCOPE_AUDIT_LOG"


def audit_path() -> Path:
    """Return the audit log path, honoring the INSCOPE_AUDIT_LOG env var."""
    override = os.environ.get(ENV_VAR)
    if override:
        return Path(override)
    return DEFAULT_AUDIT_PATH


def hash_content(content: bytes) -> str:
    """Return the sha256 hex digest of the given bytes."""
    return hashlib.sha256(content).hexdigest()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def record(target: str, result: bool, scope_hash: Optional[str], path: Optional[Path] = None) -> None:
    """Append a single JSON line to the audit log."""
    log_path = path if path is not None else audit_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": _utc_now_iso(),
        "target": target,
        "result": bool(result),
        "scope_hash": scope_hash,
    }
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")
