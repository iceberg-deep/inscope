"""Tests for the inscope HTTP server."""
import json
import os
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from inscope import __version__
from inscope.server import make_server


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


def _start(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def _stop(server):
    server.shutdown()
    server.server_close()


@pytest.fixture
def server(scope_file):
    s = make_server(scope_file, host="127.0.0.1", port=0)
    _start(s)
    yield s
    _stop(s)


def _base_url(server) -> str:
    host, port = server.server_address[:2]
    return f"http://{host}:{port}"


def _request(server, method, path, body=None, token=None):
    url = _base_url(server) + path
    headers = {}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req)
        return resp.status, resp.read().decode(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers)


# ---- /healthz ------------------------------------------------------------


def test_healthz_shape(server):
    status, body, _ = _request(server, "GET", "/healthz")
    assert status == 200
    payload = json.loads(body)
    assert set(payload.keys()) == {"status", "scope_hash", "version"}
    assert payload["status"] == "ok"
    assert isinstance(payload["scope_hash"], str)
    assert len(payload["scope_hash"]) == 64
    assert payload["version"] == __version__


# ---- /scope --------------------------------------------------------------


def test_get_scope_shape(server):
    status, body, _ = _request(server, "GET", "/scope")
    assert status == 200
    payload = json.loads(body)
    assert set(payload.keys()) == {"included", "excluded", "scope_hash"}
    for entry in payload["included"] + payload["excluded"]:
        assert set(entry.keys()) == {"kind", "value", "raw"}
    kinds = {(e["kind"], e["value"]) for e in payload["included"]}
    assert ("wildcard", "example.com") in kinds
    assert ("cidr", "10.0.0.0/24") in kinds
    assert payload["excluded"] == [
        {"kind": "domain", "value": "auth.example.com", "raw": "!auth.example.com"}
    ]


# ---- /check --------------------------------------------------------------


def test_post_check_in_scope(server):
    status, body, _ = _request(server, "POST", "/check", {"target": "api.example.com"})
    assert status == 200
    payload = json.loads(body)
    assert set(payload.keys()) == {"target", "in_scope", "matched_entry", "scope_hash"}
    assert payload["target"] == "api.example.com"
    assert payload["in_scope"] is True
    assert payload["matched_entry"] == {
        "kind": "wildcard",
        "value": "example.com",
        "excluded": False,
    }


def test_post_check_excluded(server):
    status, body, _ = _request(server, "POST", "/check", {"target": "auth.example.com"})
    assert status == 200
    payload = json.loads(body)
    assert payload["in_scope"] is False
    assert payload["matched_entry"]["excluded"] is True


def test_post_check_no_match(server):
    status, body, _ = _request(server, "POST", "/check", {"target": "evil.com"})
    assert status == 200
    payload = json.loads(body)
    assert payload["in_scope"] is False
    assert payload["matched_entry"] is None


def test_post_check_missing_target(server):
    status, _, _ = _request(server, "POST", "/check", {})
    assert status == 400


def test_post_check_invalid_json(server):
    url = _base_url(server) + "/check"
    req = urllib.request.Request(
        url,
        data=b"{not json",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req)
        assert False, "expected HTTPError"
    except urllib.error.HTTPError as e:
        assert e.code == 400


# ---- /filter -------------------------------------------------------------


def test_post_filter_jsonl(server):
    status, body, headers = _request(server, "POST", "/filter", {
        "targets": ["api.example.com", "auth.example.com", "evil.com"]
    })
    assert status == 200
    lines = [ln for ln in body.splitlines() if ln]
    assert len(lines) == 3
    parsed = [json.loads(ln) for ln in lines]
    for obj in parsed:
        assert set(obj.keys()) == {"target", "in_scope"}
    assert parsed[0] == {"target": "api.example.com", "in_scope": True}
    assert parsed[1] == {"target": "auth.example.com", "in_scope": False}
    assert parsed[2] == {"target": "evil.com", "in_scope": False}


def test_post_filter_each_line_is_valid_json(server):
    _, body, _ = _request(server, "POST", "/filter", {
        "targets": ["a.example.com", "b.example.com"]
    })
    for line in body.splitlines():
        if line:
            json.loads(line)


def test_post_filter_invalid_targets(server):
    status, _, _ = _request(server, "POST", "/filter", {"targets": "not a list"})
    assert status == 400
    status, _, _ = _request(server, "POST", "/filter", {"targets": ["ok", 42]})
    assert status == 400


# ---- 404 / unknown routes ------------------------------------------------


def test_unknown_get_route(server):
    status, _, _ = _request(server, "GET", "/nope")
    assert status == 404


def test_unknown_post_route(server):
    status, _, _ = _request(server, "POST", "/nope", {})
    assert status == 404


# ---- auth ----------------------------------------------------------------


@pytest.fixture
def auth_server(scope_file):
    s = make_server(scope_file, host="127.0.0.1", port=0, token="secret")
    _start(s)
    yield s
    _stop(s)


def test_auth_healthz_does_not_require_token(auth_server):
    status, _, _ = _request(auth_server, "GET", "/healthz")
    assert status == 200


def test_auth_no_token_returns_401(auth_server):
    status, _, _ = _request(auth_server, "GET", "/scope")
    assert status == 401
    status, _, _ = _request(auth_server, "POST", "/check", {"target": "api.example.com"})
    assert status == 401
    status, _, _ = _request(auth_server, "POST", "/filter", {"targets": ["api.example.com"]})
    assert status == 401


def test_auth_valid_token_returns_200(auth_server):
    status, _, _ = _request(auth_server, "GET", "/scope", token="secret")
    assert status == 200
    status, _, _ = _request(auth_server, "POST", "/check", {"target": "api.example.com"}, token="secret")
    assert status == 200
    status, _, _ = _request(auth_server, "POST", "/filter", {"targets": ["api.example.com"]}, token="secret")
    assert status == 200


def test_auth_wrong_token_returns_403(auth_server):
    status, _, _ = _request(auth_server, "GET", "/scope", token="wrong")
    assert status == 403
    status, _, _ = _request(auth_server, "POST", "/check", {"target": "api.example.com"}, token="wrong")
    assert status == 403


# ---- audit logging through the HTTP path --------------------------------


def _audit_log() -> Path:
    return Path(os.environ["INSCOPE_AUDIT_LOG"])


def _read_audit_entries() -> list[dict]:
    log = _audit_log()
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]


def test_audit_logged_on_check(server):
    _request(server, "POST", "/check", {"target": "api.example.com"})
    entries = _read_audit_entries()
    assert len(entries) == 1
    assert entries[0]["target"] == "api.example.com"
    assert entries[0]["result"] is True


def test_audit_logged_per_target_in_filter(server):
    _request(server, "POST", "/filter", {
        "targets": ["a.example.com", "b.example.com", "evil.com"]
    })
    entries = _read_audit_entries()
    assert len(entries) == 3
    assert [e["target"] for e in entries] == ["a.example.com", "b.example.com", "evil.com"]


def test_no_audit_disables_logging(scope_file):
    s = make_server(scope_file, host="127.0.0.1", port=0, audit=False)
    _start(s)
    try:
        _request(s, "POST", "/check", {"target": "api.example.com"})
        _request(s, "POST", "/filter", {"targets": ["a.example.com", "b.example.com"]})
    finally:
        _stop(s)
    assert _read_audit_entries() == []


def test_healthz_does_not_audit(server):
    _request(server, "GET", "/healthz")
    assert _read_audit_entries() == []


# ---- --reload picks up scope file changes --------------------------------


def test_reload_picks_up_changes_mid_process(scope_file):
    s = make_server(scope_file, host="127.0.0.1", port=0, reload=True)
    _start(s)
    try:
        _, body, _ = _request(s, "POST", "/check", {"target": "evil.com"})
        assert json.loads(body)["in_scope"] is False

        _, healthz_before, _ = _request(s, "GET", "/healthz")
        hash_before = json.loads(healthz_before)["scope_hash"]

        scope_file.write_text("evil.com\n")

        _, body, _ = _request(s, "POST", "/check", {"target": "evil.com"})
        payload = json.loads(body)
        assert payload["in_scope"] is True
        assert payload["matched_entry"]["kind"] == "domain"

        _, healthz_after, _ = _request(s, "GET", "/healthz")
        hash_after = json.loads(healthz_after)["scope_hash"]
        assert hash_before != hash_after
    finally:
        _stop(s)


def test_no_reload_caches_initial_scope(scope_file):
    s = make_server(scope_file, host="127.0.0.1", port=0, reload=False)
    _start(s)
    try:
        scope_file.write_text("evil.com\n")
        _, body, _ = _request(s, "POST", "/check", {"target": "evil.com"})
        assert json.loads(body)["in_scope"] is False
    finally:
        _stop(s)
