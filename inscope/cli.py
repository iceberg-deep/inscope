"""Command-line interface for inscope."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import Scope, ScopeEntry, __version__


def _entry_match_dict(entry: ScopeEntry) -> dict:
    return {"kind": entry.kind, "value": entry.value, "excluded": entry.excluded}


def _entry_full_dict(entry: ScopeEntry) -> dict:
    return {"kind": entry.kind, "value": entry.value, "raw": entry.raw}


def _emit_json(payload: dict) -> None:
    json.dump(payload, sys.stdout)
    sys.stdout.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="inscope",
        description="Scope parsing and creep elimination for pentests and bug bounty engagements.",
    )
    parser.add_argument("--version", action="version", version=f"inscope {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="Check whether a target is in scope.")
    p_check.add_argument("--scope", required=True, help="Path to scope file.")
    p_check.add_argument("--target", required=True, help="Target to validate (domain, IP, or URL).")
    p_check.add_argument("--no-audit", action="store_true", help="Disable audit logging for this check.")
    p_check.add_argument("--json", action="store_true", help="Emit a single JSON object to stdout instead of human-readable output.")

    p_norm = sub.add_parser("normalize", help="Print the parsed and normalized scope.")
    p_norm.add_argument("--scope", required=True, help="Path to scope file.")
    p_norm.add_argument("--json", action="store_true", help="Emit a single JSON object to stdout instead of human-readable output.")

    p_filter = sub.add_parser("filter", help="Read targets from stdin, write only in-scope ones to stdout.")
    p_filter.add_argument("--scope", required=True, help="Path to scope file.")
    p_filter.add_argument("--no-audit", action="store_true", help="Disable audit logging for this run.")
    p_filter.add_argument("--json", action="store_true", help="Emit one JSON object per input target to stdout (jsonl) instead of in-scope-only lines.")

    p_serve = sub.add_parser("serve", help="Run an HTTP API answering scope questions.")
    p_serve.add_argument("--scope", required=True, help="Path to scope file.")
    p_serve.add_argument("--host", default="127.0.0.1", help="Host to bind (default 127.0.0.1).")
    p_serve.add_argument("--port", type=int, default=8765, help="Port to bind (default 8765).")
    p_serve.add_argument("--reload", action="store_true", help="Re-read the scope file on every request (development).")
    p_serve.add_argument("--token", default=None, help="Optional bearer token. If set, required for all endpoints except /healthz.")
    p_serve.add_argument("--no-audit", action="store_true", help="Disable audit logging for this run.")

    args = parser.parse_args(argv)

    scope_path = Path(args.scope)
    if not scope_path.exists():
        print(f"[!] Scope file not found: {scope_path}", file=sys.stderr)
        return 2

    audit_enabled = not getattr(args, "no_audit", False)

    if args.cmd == "serve":
        from .server import run_server
        return run_server(
            scope_path,
            host=args.host,
            port=args.port,
            audit=audit_enabled,
            reload=args.reload,
            token=args.token,
        )

    scope = Scope.from_file(scope_path, audit=audit_enabled)
    json_mode = getattr(args, "json", False)

    if args.cmd == "check":
        in_scope, matched = scope.evaluate(args.target)
        if json_mode:
            _emit_json({
                "target": args.target,
                "in_scope": in_scope,
                "matched_entry": _entry_match_dict(matched) if matched is not None else None,
                "scope_hash": scope.source_hash,
            })
        else:
            if in_scope:
                print(f"[+] {args.target} is IN scope")
            else:
                print(f"[-] {args.target} is OUT of scope")
        return 0 if in_scope else 1

    if args.cmd == "normalize":
        if json_mode:
            _emit_json({
                "included": [_entry_full_dict(e) for e in scope.included()],
                "excluded": [_entry_full_dict(e) for e in scope.excluded()],
                "scope_hash": scope.source_hash,
            })
        else:
            print("# Included")
            for e in scope.included():
                print(f"  {e}")
            print("# Excluded")
            for e in scope.excluded():
                print(f"  {e}")
        return 0

    if args.cmd == "filter":
        for line in sys.stdin:
            target = line.strip()
            if not target:
                continue
            if json_mode:
                in_scope = scope.is_in_scope(target)
                _emit_json({"target": target, "in_scope": in_scope})
            elif scope.is_in_scope(target):
                print(target)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
