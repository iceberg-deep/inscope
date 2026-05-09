"""Tests for the --json flag on check, normalize, and filter."""
import io
import json

import pytest

from inscope.cli import main


SCOPE_BODY = (
    "*.example.com\n"
    "10.0.0.0/24\n"
    "!auth.example.com\n"
)


@pytest.fixture
def scope_file(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text(SCOPE_BODY)
    return p


# ---- check --json ---------------------------------------------------------


def test_check_json_in_scope_schema(scope_file, capsys):
    rc = main(["check", "--scope", str(scope_file), "--target", "api.example.com", "--json"])
    captured = capsys.readouterr()
    assert rc == 0
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert set(payload.keys()) == {"target", "in_scope", "matched_entry", "scope_hash"}
    assert payload["target"] == "api.example.com"
    assert payload["in_scope"] is True
    assert payload["matched_entry"] == {
        "kind": "wildcard",
        "value": "example.com",
        "excluded": False,
    }
    assert isinstance(payload["scope_hash"], str)
    assert len(payload["scope_hash"]) == 64


def test_check_json_out_of_scope_no_match(scope_file, capsys):
    rc = main(["check", "--scope", str(scope_file), "--target", "evil.com", "--json"])
    captured = capsys.readouterr()
    assert rc == 1
    payload = json.loads(captured.out)
    assert payload["target"] == "evil.com"
    assert payload["in_scope"] is False
    assert payload["matched_entry"] is None


def test_check_json_excluded_match(scope_file, capsys):
    rc = main(["check", "--scope", str(scope_file), "--target", "auth.example.com", "--json"])
    captured = capsys.readouterr()
    assert rc == 1
    payload = json.loads(captured.out)
    assert payload["in_scope"] is False
    assert payload["matched_entry"] == {
        "kind": "domain",
        "value": "auth.example.com",
        "excluded": True,
    }


def test_check_json_suppresses_human_readable(scope_file, capsys):
    main(["check", "--scope", str(scope_file), "--target", "api.example.com", "--json"])
    out = capsys.readouterr().out
    assert "[+]" not in out
    assert "[-]" not in out
    assert "IN scope" not in out
    assert "OUT of scope" not in out
    # exactly one line of JSON
    lines = [ln for ln in out.splitlines() if ln]
    assert len(lines) == 1
    json.loads(lines[0])


def test_check_json_preserves_exit_codes(scope_file):
    assert main(["check", "--scope", str(scope_file), "--target", "api.example.com", "--json"]) == 0
    assert main(["check", "--scope", str(scope_file), "--target", "evil.com", "--json"]) == 1
    assert main(["check", "--scope", str(scope_file), "--target", "auth.example.com", "--json"]) == 1


# ---- normalize --json -----------------------------------------------------


def test_normalize_json_schema(scope_file, capsys):
    rc = main(["normalize", "--scope", str(scope_file), "--json"])
    captured = capsys.readouterr()
    assert rc == 0
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert set(payload.keys()) == {"included", "excluded", "scope_hash"}
    assert isinstance(payload["included"], list)
    assert isinstance(payload["excluded"], list)
    for entry in payload["included"] + payload["excluded"]:
        assert set(entry.keys()) == {"kind", "value", "raw"}
        assert isinstance(entry["kind"], str)
        assert isinstance(entry["value"], str)
        assert isinstance(entry["raw"], str)

    kinds = {(e["kind"], e["value"]) for e in payload["included"]}
    assert ("wildcard", "example.com") in kinds
    assert ("cidr", "10.0.0.0/24") in kinds

    assert payload["excluded"] == [
        {"kind": "domain", "value": "auth.example.com", "raw": "!auth.example.com"}
    ]
    assert isinstance(payload["scope_hash"], str)
    assert len(payload["scope_hash"]) == 64


def test_normalize_json_suppresses_human_readable(scope_file, capsys):
    main(["normalize", "--scope", str(scope_file), "--json"])
    out = capsys.readouterr().out
    assert "# Included" not in out
    assert "# Excluded" not in out
    lines = [ln for ln in out.splitlines() if ln]
    assert len(lines) == 1
    json.loads(lines[0])


def test_normalize_json_preserves_exit_code(scope_file):
    assert main(["normalize", "--scope", str(scope_file), "--json"]) == 0


# ---- filter --json --------------------------------------------------------


def test_filter_json_emits_jsonl(scope_file, monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO("api.example.com\nevil.com\nauth.example.com\n"),
    )
    rc = main(["filter", "--scope", str(scope_file), "--json"])
    captured = capsys.readouterr()
    assert rc == 0
    assert captured.err == ""
    lines = [ln for ln in captured.out.splitlines() if ln]
    assert len(lines) == 3
    parsed = [json.loads(ln) for ln in lines]
    for obj in parsed:
        assert set(obj.keys()) == {"target", "in_scope"}
        assert isinstance(obj["target"], str)
        assert isinstance(obj["in_scope"], bool)
    assert parsed[0] == {"target": "api.example.com", "in_scope": True}
    assert parsed[1] == {"target": "evil.com", "in_scope": False}
    assert parsed[2] == {"target": "auth.example.com", "in_scope": False}


def test_filter_json_each_line_is_valid_json(scope_file, monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO("a.example.com\nb.example.com\nbad.example\n"),
    )
    main(["filter", "--scope", str(scope_file), "--json"])
    out = capsys.readouterr().out
    for line in out.splitlines():
        if line:
            json.loads(line)  # raises if invalid


def test_filter_json_skips_blank_lines(scope_file, monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO("api.example.com\n\n\nevil.com\n"),
    )
    main(["filter", "--scope", str(scope_file), "--json"])
    out = capsys.readouterr().out
    lines = [ln for ln in out.splitlines() if ln]
    assert len(lines) == 2


def test_filter_json_suppresses_human_readable(scope_file, monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO("api.example.com\nevil.com\n"),
    )
    main(["filter", "--scope", str(scope_file), "--json"])
    out = capsys.readouterr().out
    # plain-text mode would have written the bare target "api.example.com" on its own line
    for line in out.splitlines():
        if not line:
            continue
        # every non-blank line must be JSON, not a bare target
        obj = json.loads(line)
        assert isinstance(obj, dict)


def test_filter_json_preserves_exit_code(scope_file, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("api.example.com\n"))
    assert main(["filter", "--scope", str(scope_file), "--json"]) == 0
