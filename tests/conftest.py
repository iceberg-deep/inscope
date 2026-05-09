"""Test isolation: redirect audit log to a tmp path so tests never write to ~/.inscope."""
import pytest


@pytest.fixture(autouse=True)
def _isolate_audit_log(tmp_path, monkeypatch):
    monkeypatch.setenv("INSCOPE_AUDIT_LOG", str(tmp_path / "audit.log"))
