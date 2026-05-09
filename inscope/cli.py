"""Command-line interface for inscope."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import Scope, __version__


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

    p_norm = sub.add_parser("normalize", help="Print the parsed and normalized scope.")
    p_norm.add_argument("--scope", required=True, help="Path to scope file.")

    p_filter = sub.add_parser("filter", help="Read targets from stdin, write only in-scope ones to stdout.")
    p_filter.add_argument("--scope", required=True, help="Path to scope file.")
    p_filter.add_argument("--no-audit", action="store_true", help="Disable audit logging for this run.")

    args = parser.parse_args(argv)

    scope_path = Path(args.scope)
    if not scope_path.exists():
        print(f"[!] Scope file not found: {scope_path}", file=sys.stderr)
        return 2

    audit_enabled = not getattr(args, "no_audit", False)
    scope = Scope.from_file(scope_path, audit=audit_enabled)

    if args.cmd == "check":
        ok = scope.is_in_scope(args.target)
        if ok:
            print(f"[+] {args.target} is IN scope")
            return 0
        print(f"[-] {args.target} is OUT of scope")
        return 1

    if args.cmd == "normalize":
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
            if target and scope.is_in_scope(target):
                print(target)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
