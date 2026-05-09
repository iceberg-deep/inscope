"""
inscope - scope parsing and creep elimination for pentests and bug bounty engagements.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Union
from urllib.parse import urlparse

from . import audit as _audit

__version__ = "0.1.0"
__all__ = ["Scope", "ScopeEntry", "parse_entry", "matches"]


@dataclass
class ScopeEntry:
    """A single normalized entry in a scope definition."""

    raw: str
    kind: str  # 'domain' | 'wildcard' | 'ip' | 'cidr' | 'url'
    value: str
    excluded: bool = False

    def __str__(self) -> str:
        prefix = "!" if self.excluded else ""
        return f"{prefix}{self.kind}:{self.value}"


class Scope:
    """A parsed scope definition with in-scope / out-of-scope checks."""

    def __init__(
        self,
        entries: Optional[list[ScopeEntry]] = None,
        *,
        audit: bool = True,
        source_hash: Optional[str] = None,
    ):
        self.entries: list[ScopeEntry] = entries or []
        self.audit: bool = audit
        self.source_hash: Optional[str] = source_hash

    @classmethod
    def from_file(cls, path: Union[str, Path], *, audit: bool = True) -> "Scope":
        path = Path(path)
        data = path.read_bytes()
        source_hash = _audit.hash_content(data)
        return cls.from_lines(
            data.decode().splitlines(),
            audit=audit,
            source_hash=source_hash,
        )

    @classmethod
    def from_lines(
        cls,
        lines: Iterable[str],
        *,
        audit: bool = True,
        source_hash: Optional[str] = None,
    ) -> "Scope":
        lines_list = list(lines)
        entries: list[ScopeEntry] = []
        for line in lines_list:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entry = parse_entry(line)
            if entry is not None:
                entries.append(entry)
        if source_hash is None:
            source_hash = _audit.hash_content("\n".join(lines_list).encode())
        return cls(entries, audit=audit, source_hash=source_hash)

    def is_in_scope(self, target: str) -> bool:
        """Return True if target is in scope and not excluded."""
        return self.evaluate(target)[0]

    def evaluate(self, target: str) -> tuple[bool, Optional[ScopeEntry]]:
        """Return (in_scope, matched_entry). matched_entry is the first excluded
        entry that matched, else the first included entry that matched, else None."""
        normalized = _normalize_target(target)
        result, matched = self._evaluate(normalized)
        if self.audit:
            _audit.record(target, result, self.source_hash)
        return result, matched

    def _evaluate(self, target: str) -> tuple[bool, Optional[ScopeEntry]]:
        for entry in self.entries:
            if entry.excluded and matches(entry, target):
                return False, entry
        for entry in self.entries:
            if not entry.excluded and matches(entry, target):
                return True, entry
        return False, None

    def filter(self, targets: Iterable[str]) -> list[str]:
        """Return only the targets that are in scope."""
        return [t for t in targets if self.is_in_scope(t)]

    def included(self) -> list[ScopeEntry]:
        return [e for e in self.entries if not e.excluded]

    def excluded(self) -> list[ScopeEntry]:
        return [e for e in self.entries if e.excluded]


# ---- parsing helpers -------------------------------------------------------

_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$")


def parse_entry(line: str) -> Optional[ScopeEntry]:
    """Parse a single scope line into a normalized ScopeEntry, or None if invalid."""
    raw = line
    excluded = False
    if line.startswith("!"):
        excluded = True
        line = line[1:].strip()

    # URL
    if line.startswith(("http://", "https://")):
        parsed = urlparse(line)
        host = parsed.hostname or ""
        return ScopeEntry(raw=raw, kind="url", value=host.lower(), excluded=excluded)

    # CIDR
    if "/" in line and not line.startswith(("http://", "https://")):
        try:
            net = ipaddress.ip_network(line, strict=False)
            return ScopeEntry(raw=raw, kind="cidr", value=str(net), excluded=excluded)
        except ValueError:
            pass

    # IP
    try:
        ip = ipaddress.ip_address(line)
        return ScopeEntry(raw=raw, kind="ip", value=str(ip), excluded=excluded)
    except ValueError:
        pass

    # Wildcard subdomain
    if line.startswith("*."):
        domain = line[2:].lower()
        if _DOMAIN_RE.match(domain):
            return ScopeEntry(raw=raw, kind="wildcard", value=domain, excluded=excluded)

    # Bare domain
    if _DOMAIN_RE.match(line):
        return ScopeEntry(raw=raw, kind="domain", value=line.lower(), excluded=excluded)

    return None


def matches(entry: ScopeEntry, target: str) -> bool:
    """Return True if target matches entry."""
    target = _normalize_target(target)

    if entry.kind == "domain":
        return target == entry.value
    if entry.kind == "wildcard":
        return target == entry.value or target.endswith("." + entry.value)
    if entry.kind == "ip":
        try:
            return ipaddress.ip_address(target) == ipaddress.ip_address(entry.value)
        except ValueError:
            return False
    if entry.kind == "cidr":
        try:
            return ipaddress.ip_address(target) in ipaddress.ip_network(entry.value, strict=False)
        except ValueError:
            return False
    if entry.kind == "url":
        return target == entry.value
    return False


def _normalize_target(target: str) -> str:
    """Strip protocol, path, port. Return lowercase host or IP."""
    t = target.strip().lower()
    if "://" in t:
        parsed = urlparse(t)
        t = parsed.hostname or t
    if "/" in t:
        t = t.split("/", 1)[0]
    if ":" in t and not _looks_like_ipv6(t):
        t = t.split(":", 1)[0]
    return t


def _looks_like_ipv6(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return False
