"""HTTP API for scope questions. Stdlib only."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

from . import Scope, ScopeEntry, __version__


def _entry_match_dict(entry: ScopeEntry) -> dict:
    return {"kind": entry.kind, "value": entry.value, "excluded": entry.excluded}


def _entry_full_dict(entry: ScopeEntry) -> dict:
    return {"kind": entry.kind, "value": entry.value, "raw": entry.raw}


def make_server(
    scope_path,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    audit: bool = True,
    reload: bool = False,
    token: Optional[str] = None,
) -> ThreadingHTTPServer:
    """Build a configured ThreadingHTTPServer. Caller invokes serve_forever()."""
    scope_path = Path(scope_path)
    initial_scope = Scope.from_file(scope_path, audit=audit)
    state = {"scope": initial_scope}

    def get_scope() -> Scope:
        if reload:
            return Scope.from_file(scope_path, audit=audit)
        return state["scope"]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def _write(self, status: int, body: str, content_type: str = "application/json") -> None:
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _send_json(self, status: int, payload: dict) -> None:
            self._write(status, json.dumps(payload) + "\n", "application/json")

        def _send_jsonl(self, status: int, items: list) -> None:
            body = "".join(json.dumps(it) + "\n" for it in items)
            self._write(status, body, "application/x-ndjson")

        def _send_error(self, status: int, message: str) -> None:
            self._send_json(status, {"error": message})

        def _check_auth(self) -> Optional[int]:
            """Return None if authorized, else the HTTP status to respond with."""
            if token is None:
                return None
            header = self.headers.get("Authorization", "") or ""
            if not header:
                return 401
            if not header.startswith("Bearer "):
                return 403
            if header[len("Bearer "):] != token:
                return 403
            return None

        def _read_json_body(self):
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length == 0:
                return None
            raw = self.rfile.read(length)
            return json.loads(raw)

        def do_GET(self):
            try:
                if self.path == "/healthz":
                    scope = get_scope()
                    self._send_json(200, {
                        "status": "ok",
                        "scope_hash": scope.source_hash,
                        "version": __version__,
                    })
                    return

                err = self._check_auth()
                if err is not None:
                    self._send_error(err, "unauthorized" if err == 401 else "forbidden")
                    return

                if self.path == "/scope":
                    scope = get_scope()
                    self._send_json(200, {
                        "included": [_entry_full_dict(e) for e in scope.included()],
                        "excluded": [_entry_full_dict(e) for e in scope.excluded()],
                        "scope_hash": scope.source_hash,
                    })
                    return

                self._send_error(404, "not found")
            except Exception as exc:
                self._send_error(500, f"internal error: {exc}")

        def do_POST(self):
            try:
                err = self._check_auth()
                if err is not None:
                    self._send_error(err, "unauthorized" if err == 401 else "forbidden")
                    return

                try:
                    body = self._read_json_body()
                except json.JSONDecodeError:
                    self._send_error(400, "invalid json")
                    return

                if self.path == "/check":
                    if not isinstance(body, dict) or not isinstance(body.get("target"), str):
                        self._send_error(400, "missing or invalid 'target'")
                        return
                    target = body["target"]
                    scope = get_scope()
                    in_scope, matched = scope.evaluate(target)
                    self._send_json(200, {
                        "target": target,
                        "in_scope": in_scope,
                        "matched_entry": _entry_match_dict(matched) if matched is not None else None,
                        "scope_hash": scope.source_hash,
                    })
                    return

                if self.path == "/filter":
                    if (
                        not isinstance(body, dict)
                        or not isinstance(body.get("targets"), list)
                        or not all(isinstance(t, str) for t in body["targets"])
                    ):
                        self._send_error(400, "missing or invalid 'targets' (must be list of strings)")
                        return
                    scope = get_scope()
                    results = [
                        {"target": t, "in_scope": scope.is_in_scope(t)}
                        for t in body["targets"]
                    ]
                    self._send_jsonl(200, results)
                    return

                self._send_error(404, "not found")
            except Exception as exc:
                self._send_error(500, f"internal error: {exc}")

    return ThreadingHTTPServer((host, port), Handler)


def run_server(
    scope_path,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    audit: bool = True,
    reload: bool = False,
    token: Optional[str] = None,
) -> int:
    """Run server until interrupted. Returns process exit code."""
    server = make_server(
        scope_path,
        host=host,
        port=port,
        audit=audit,
        reload=reload,
        token=token,
    )
    bound_host, bound_port = server.server_address[:2]
    print(f"[+] inscope serve listening on http://{bound_host}:{bound_port} (scope={scope_path})")
    if token:
        print("[+] bearer token required for all endpoints except /healthz")
    if reload:
        print("[+] --reload: scope file will be re-read on every request")
    if not audit:
        print("[+] audit logging disabled for this run")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] shutting down")
    finally:
        server.server_close()
    return 0
