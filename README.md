# Thoth

A modular, multiplayer **website / subdomain enumeration** platform. Organise targets into
per-client **workspaces**, run pluggable modules against them, and share results live. Its
directory fuzzer follows [**dirsearch**](https://github.com/maurosoria/dirsearch)
(uses its `dicc.txt` and conventions), and a **dedup ledger** means the same path is never
re-fuzzed twice — no duplicated work between runs or teammates.

> For authorized security testing only. Only scan hosts you have permission to test.

## Features

- **Workspaces** per engagement, with one-command **wipe**.
- **Subdomains** — paste/upload a list (lowercased, de-duped, sorted); multi-threaded
  **Check all live** colour-codes each.
- **Enrichment** — resolves each host's **IP → ASN → owner/country** (Team Cymru) and detects
  **WAF/CDN**, server, and tech.
- **Directory fuzzing** (dirsearch-style) — recursive, wildcard/404-aware, `dicc.txt` by
  default, with a **dedup ledger** and a **force re-scan** escape hatch.
- **Results** — rich filters (status, exclude-status/size, WAF, hide dead/3xx), clickable
  paths, and a full **response viewer** (through your proxy).
- **Analysis** — ASN ownership, WAF vendors, tech, servers, and countries across the estate.
- **Tasks** with live progress + persisted CLI-style output; live updates via SSE; Burp
  proxy support; per-subdomain notes; 6 UI themes.

## Quick start (no Docker)

SQLite, no external services. On Windows just run `start.bat`; otherwise:

```bash
python -m venv .venv && . .venv/bin/activate   # Win: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
export FLASK_APP=wsgi.py FLASK_DEBUG=1          # Win: $env:FLASK_APP="wsgi.py"; $env:FLASK_DEBUG="1"
flask seed                                      # dev account magna:magna (debug only)
flask run --debug
```

Open http://127.0.0.1:5000, sign in **magna / magna**, add subdomains, **Check all live**,
then fuzz. For real concurrency/multiplayer: `docker compose up --build` (Postgres + Redis +
Celery).

> **`magna:magna` is a local-dev convenience only** — `flask seed` refuses it outside debug
> mode. For any real deployment run `flask seed --email you@example.com` (a strong random
> password is generated and printed once).

## Dedup & re-scanning

The fuzzer records every path it requests per `(workspace, host, parent_path)`, so re-runs
**skip already-tested paths**. A re-run that finds nothing was usually fully deduped (the
subdomain page shows coverage). To test anyway: **Force re-scan**, **Fuzz (force)**, or
**Clear ledger**.

## Wordlists

Resolution order: a directory you point it at (`*.txt`) → `wordlists/dicc.txt` →
`wordlists/common.txt`. Honours dirsearch's `%EXT%` placeholder, so dropping dirsearch's real
`db/dicc.txt` in as `wordlists/dicc.txt` works verbatim.

## Tests

```bash
python -m pytest
```

Temp DB + mock target server (no network), tasks run inline. Covers the fuzzer (hits,
wildcard suppression, dedup + force, sizing, `%EXT%`), alive (fingerprint/WAF/concurrency),
ASN parsing, and routes (import, wipe-cascade, access control, filters).

## Credits

Default wordlist and fuzzing conventions from
[dirsearch](https://github.com/maurosoria/dirsearch) (GPL-2.0; `dicc.txt` retains its
license) · IP-to-ASN via [Team Cymru](https://www.team-cymru.com/ip-asn-mapping) · UI
inspired by [DotDitto](https://github.com/magna-sec/DotDitto). Add a `LICENSE` before
publishing (bundling GPL `dicc.txt` has redistribution implications).
