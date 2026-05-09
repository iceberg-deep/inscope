# inscope

> Scope parsing and creep elimination for pentests and bug bounty engagements.

**v0.2.0 is out** — every CLI subcommand now speaks `--json` (jsonl from `filter`), so you can pipe scope decisions straight into `jq` and the rest of your tooling. [Release notes →](https://github.com/iceberg-deep/inscope/releases/tag/v0.2.0)

Every engagement starts with a scope document. Most live in a Slack message, a PDF, a copy-paste from a program page, or an email thread that got forwarded twice. `inscope` normalizes that mess into something machine-readable, then gives you a guard rail against drifting out of scope mid-test.

This is a discipline tool as much as a parser. Stay in your lane, prove it.

## Install

```bash
git clone https://github.com/iceberg-deep/inscope.git
cd inscope
pip install -e .
```

Stdlib only. No external dependencies.

## Usage

### As a library

```python
from inscope import Scope

scope = Scope.from_file("scope.txt")

scope.is_in_scope("api.example.com")      # True
scope.is_in_scope("auth.example.com")     # False (excluded)
scope.is_in_scope("10.0.0.42")            # True (matches CIDR)

# Filter a target list down to in-scope only
in_scope = scope.filter(["api.example.com", "evil.com", "10.0.0.5"])
```

### As a CLI

```bash
# Single target check
inscope check --scope scope.txt --target api.example.com

# Print the parsed and normalized scope
inscope normalize --scope scope.txt

# Filter targets from stdin (great for piping recon output)
cat targets.txt | inscope filter --scope scope.txt
subfinder -d example.com | inscope filter --scope scope.txt | httpx
```

### JSON output

Pass `--json` to any subcommand to get machine-readable output on stdout. Exit codes are unchanged (`check` returns `0` if in scope, `1` if out, `2` for errors; the others return `0`).

```bash
$ inscope check --scope scope.txt --target api.example.com --json
{"target": "api.example.com", "in_scope": true, "matched_entry": {"kind": "wildcard", "value": "example.com", "excluded": false}, "scope_hash": "9f86d0..."}

$ inscope normalize --scope scope.txt --json
{"included": [{"kind": "wildcard", "value": "example.com", "raw": "*.example.com"}, ...], "excluded": [...], "scope_hash": "9f86d0..."}

# filter emits JSON Lines (one object per input target)
$ printf 'api.example.com\nauth.example.com\nevil.com\n' | inscope filter --scope scope.txt --json
{"target": "api.example.com", "in_scope": true}
{"target": "auth.example.com", "in_scope": false}
{"target": "evil.com", "in_scope": false}

# pipe into jq for ad-hoc reports
$ cat targets.txt | inscope filter --scope scope.txt --json | jq -r 'select(.in_scope) | .target'
```

### Server mode

Run a small HTTP API around a scope file — useful when multiple tools or teammates need to ask "is this in scope?" against a single source of truth.

```bash
inscope serve --scope scope.txt
# [+] inscope serve listening on http://127.0.0.1:8765 (scope=scope.txt)
```

Endpoints:

| Method | Path       | Body                          | Response                                                                             |
| ------ | ---------- | ----------------------------- | ------------------------------------------------------------------------------------ |
| GET    | `/healthz` | —                             | `{"status": "ok", "scope_hash": "...", "version": "..."}`                            |
| GET    | `/scope`   | —                             | same shape as `inscope normalize --json`                                             |
| POST   | `/check`   | `{"target": "api.example.com"}` | same shape as `inscope check --json`                                                |
| POST   | `/filter`  | `{"targets": ["a", "b", ...]}`  | JSON Lines, one `{"target", "in_scope"}` per input target                          |

```bash
curl -s http://127.0.0.1:8765/healthz
curl -s http://127.0.0.1:8765/scope | jq
curl -s -XPOST http://127.0.0.1:8765/check  -d '{"target":"api.example.com"}'
curl -s -XPOST http://127.0.0.1:8765/filter -d '{"targets":["api.example.com","auth.example.com","evil.com"]}'
```

Flags:

- `--host` / `--port` — bind address (default `127.0.0.1:8765`).
- `--reload` — re-read the scope file on every request (development only).
- `--token <value>` — require `Authorization: Bearer <value>` on all endpoints except `/healthz`. Missing header → `401`, wrong value → `403`.
- `--no-audit` — disable audit logging for this run. By default every `/check` call and every target inside `/filter` writes to the audit log just like the CLI does.

```bash
# with auth
inscope serve --scope scope.txt --token "$INSCOPE_TOKEN"
curl -s -H "Authorization: Bearer $INSCOPE_TOKEN" http://127.0.0.1:8765/scope
```

> **Local-only by default; not hardened for public internet exposure.** The server binds to `127.0.0.1`, has no rate limiting, and `--token` is a thin shared-secret check over plaintext HTTP. If you need to expose it beyond localhost, put it behind a reverse proxy that terminates TLS, enforces auth, and applies rate limits — and revisit whether the bearer token is sufficient for your threat model.

## Scope file format

Plain text, one entry per line. Lines starting with `#` are comments. Lines starting with `!` are exclusions.

```
# In scope
*.example.com
example.com
api.example.org
192.168.1.0/24
https://app.example.com

# Out of scope
!auth.example.com
!admin.example.com
!10.0.99.0/24
```

Supported entry types:

| Kind     | Example                          |
| -------- | -------------------------------- |
| Domain   | `example.com`                    |
| Wildcard | `*.example.com`                  |
| IP       | `192.168.1.10`                   |
| CIDR     | `10.0.0.0/24`                    |
| URL      | `https://api.example.com/v2`     |
| Excluded | prefix any of the above with `!` |

Exclusions always take precedence over inclusions.

## Why this exists

Hitting an out-of-scope target is one of the fastest ways to lose trust on an engagement, void a bug bounty payout, or create real legal exposure. The default solution is a half-finished private script that lives in `~/tools/scope.py` and never quite handles wildcards correctly. This is the version that does.

## Roadmap

- [ ] JSON / YAML scope file support
- [ ] Bugcrowd and HackerOne API import (pull scope directly from program)
- [ ] Burp Suite scope export (`--burp-json`)
- [ ] Diff mode (compare two scope versions, flag what changed)
- [ ] Target expansion (CIDR -> hosts, wildcard resolution via DNS)

## License

MIT
