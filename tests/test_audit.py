"""Tests for the audit log feature."""
import json
import os
from datetime import datetime
from pathlib import Path

import pytest

from inscope import Scope
from inscope.audit import audit_path, hash_content, record
from inscope.cli import main


def _audit_log() -> Path:
    return Path(os.environ["INSCOPE_AUDIT_LOG"])


def _read_entries() -> list[dict]:
    log = _audit_log()
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]


def test_audit_writes_one_line_per_call():
    s = Scope.from_lines(["example.com"])
    s.is_in_scope("example.com")
    s.is_in_scope("evil.com")
    s.is_in_scope("api.example.com")
    entries = _read_entries()
    assert len(entries) == 3


def test_audit_record_shape():
    s = Scope.from_lines(["example.com"])
    s.is_in_scope("example.com")
    entry = _read_entries()[0]
    assert set(entry.keys()) == {"timestamp", "target", "result", "scope_hash"}
    assert entry["target"] == "example.com"
    assert entry["result"] is True
    assert isinstance(entry["scope_hash"], str)
    assert len(entry["scope_hash"]) == 64  # sha256 hex digest length


def test_audit_records_out_of_scope_result():
    s = Scope.from_lines(["example.com"])
    s.is_in_scope("evil.com")
    entry = _read_entries()[0]
    assert entry["target"] == "evil.com"
    assert entry["result"] is False


def test_audit_timestamp_is_iso8601_utc():
    s = Scope.from_lines(["example.com"])
    s.is_in_scope("example.com")
    ts = _read_entries()[0]["timestamp"]
    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None


def test_audit_can_be_disabled_on_scope():
    s = Scope.from_lines(["example.com"], audit=False)
    s.is_in_scope("example.com")
    assert _read_entries() == []


def test_audit_disabled_runtime_toggle():
    s = Scope.from_lines(["example.com"])
    s.audit = False
    s.is_in_scope("example.com")
    assert _read_entries() == []


def test_audit_hash_matches_sha256_of_scope_file(tmp_path):
    scope_file = tmp_path / "scope.txt"
    payload = b"example.com\n*.api.example.com\n!auth.example.com\n"
    scope_file.write_bytes(payload)
    expected = hash_content(payload)
    s = Scope.from_file(scope_file)
    s.is_in_scope("example.com")
    assert _read_entries()[0]["scope_hash"] == expected


def test_audit_preserves_original_target_string():
    """The audit log records the target as the user passed it, not the normalized form."""
    s = Scope.from_lines(["example.com"])
    s.is_in_scope("https://example.com:8080/admin")
    assert _read_entries()[0]["target"] == "https://example.com:8080/admin"


def test_audit_creates_parent_directory(tmp_path, monkeypatch):
    nested = tmp_path / "deep" / "nested" / "dir" / "audit.log"
    monkeypatch.setenv("INSCOPE_AUDIT_LOG", str(nested))
    s = Scope.from_lines(["example.com"])
    s.is_in_scope("example.com")
    assert nested.exists()


def test_audit_appends_across_scope_instances():
    Scope.from_lines(["example.com"]).is_in_scope("example.com")
    Scope.from_lines(["example.com"]).is_in_scope("example.com")
    assert len(_read_entries()) == 2


def test_audit_path_default_when_env_unset(monkeypatch):
    monkeypatch.delenv("INSCOPE_AUDIT_LOG", raising=False)
    assert audit_path() == Path.home() / ".inscope" / "audit.log"


def test_audit_path_honors_env_var(tmp_path, monkeypatch):
    custom = tmp_path / "custom.log"
    monkeypatch.setenv("INSCOPE_AUDIT_LOG", str(custom))
    assert audit_path() == custom


def test_record_function_writes_directly(tmp_path):
    log = tmp_path / "direct.log"
    record("foo.com", True, "abc123", path=log)
    record("bar.com", False, "abc123", path=log)
    lines = log.read_text().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["target"] == "foo.com"
    assert first["result"] is True
    assert first["scope_hash"] == "abc123"


# CLI integration


def test_cli_check_audits_by_default(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.com\n")
    rc = main(["check", "--scope", str(scope_file), "--target", "example.com"])
    assert rc == 0
    entries = _read_entries()
    assert len(entries) == 1
    assert entries[0]["target"] == "example.com"
    assert entries[0]["result"] is True


def test_cli_check_no_audit_flag_disables(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.com\n")
    rc = main(["check", "--scope", str(scope_file), "--target", "example.com", "--no-audit"])
    assert rc == 0
    assert _read_entries() == []


def test_cli_filter_no_audit_flag_disables(tmp_path, monkeypatch, capsys):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.com\n")
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("example.com\nevil.com\n"))
    rc = main(["filter", "--scope", str(scope_file), "--no-audit"])
    assert rc == 0
    assert _read_entries() == []


def test_cli_normalize_does_not_audit(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.com\n")
    rc = main(["normalize", "--scope", str(scope_file)])
    assert rc == 0
    # normalize doesn't call is_in_scope, so nothing should be logged
    assert _read_entries() == []
