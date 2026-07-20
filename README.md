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
  **Check all live** colour-codes each, and sweeps **8080/8443** so alt-port admin panels
  and dev copies get flagged on the host.
- **Enrichment** — resolves each host's **IP → ASN → owner/country** (Team Cymru) and detects
  **WAF/CDN**, server, and tech — with a fingerprint set **you can extend**. See
  [Fingerprints](#fingerprints).
- **Screenshots** — headless-browser capture of one subdomain or the whole estate, with a
  filterable gallery. See [Screenshots](#screenshots).
- **Directory fuzzing** (dirsearch-style) — recursive, wildcard/404-aware, `dicc.txt` by
  default, with a **dedup ledger** and a **force re-scan** escape hatch.
- **Import real dirsearch output** — paste or upload a run you did outside Thoth; it becomes
  findings *and* ledger entries, so nothing gets re-fuzzed. See [Importing](#importing-real-dirsearch-output).
- **Results** — rich filters (status, exclude-status/size, WAF, hide dead/3xx) that **stick
  across refreshes**, clickable paths, and a full **response viewer** (through your proxy).
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

## Fingerprints

Alive checks label the tech behind each host (nginx, WordPress, Salesforce, Shopify…).
When you hit something Thoth doesn't know, add it rather than filing it away: the
**Fingerprints** page — or the inline form on any subdomain page — takes a label, where to
look, and the text to look for:

| Match location | Searches |
| --- | --- |
| page body | first 20KB of the response body |
| any response header | the whole `name: value` header block |
| Server header | `Server` only |
| X-Powered-By | `X-Powered-By` only |
| cookie name | names of cookies set by the response |

Matching is a case-insensitive substring test, so rules are predictable and can't blow up
a scan. Signatures are **global**, not per-workspace — recognising a platform is knowledge
the whole team keeps — and apply from the **next** alive check, so re-run
**Check all live** to relabel hosts you've already scanned. Any operator can add one;
deleting a shared rule is admin-only.

## Screenshots

**Screenshots** tab (or the 📷 button on a subdomain) renders each site in a headless
browser and stores the PNG under `DATA_DIR/workspaces/<id>/screenshots/`, so a workspace
wipe takes the images with it. Like fuzzing, hosts already captured are skipped unless you
tick **Re-capture**; hosts last seen dead are skipped by default.

A renderer must be present. Thoth prefers **Playwright** and falls back to any local
**Chrome/Chromium/Edge/Brave**:

```bash
pip install playwright && python -m playwright install chromium   # optional, best quality
```

Playwright is the only backend that can do **full page** capture; the Chrome fallback
captures the viewport. Neither is a hard dependency — if a browser is somewhere unusual,
point `THOTH_CHROME` at the binary. The Docker image ships no browser, so install one (or
Playwright) in it if you want screenshots there.

## Importing real dirsearch output

Already fuzzed a host with the actual dirsearch? On the subdomain page, **Import dirsearch
results** takes a paste (or an uploaded report) and turns it into findings plus **dedup
ledger** entries, so a later fuzz in Thoth won't redo that work. Terminal output and every
`--format` are understood: `json`, `csv`, `md`, `plain`, `simple`. It's recorded as a
completed task, and it warns if the output looks like it came from a different host.

## Wordlists

Resolution order: a directory you point it at (`*.txt`) → `wordlists/dicc.txt` →
`wordlists/common.txt`. Honours dirsearch's `%EXT%` placeholder, so dropping dirsearch's real
`db/dicc.txt` in as `wordlists/dicc.txt` works verbatim.

## Tests

```bash
python -m pytest
```

Temp DB + mock target server (no network), tasks run inline. Covers the fuzzer (hits,
wildcard suppression, dedup + force, sizing, `%EXT%`), alive (fingerprint/WAF/concurrency,
alt-port sweep), custom fingerprint signatures (matching, management, access control),
screenshots (capture bookkeeping, skip rules, image serving — against a stub renderer, so
no browser needed), dirsearch import parsing, ASN parsing, and routes (import,
wipe-cascade, access control, filters).

## Credits

Default wordlist and fuzzing conventions from
[dirsearch](https://github.com/maurosoria/dirsearch) (GPL-2.0; `dicc.txt` retains its
license) · IP-to-ASN via [Team Cymru](https://www.team-cymru.com/ip-asn-mapping) · UI
inspired by [DotDitto](https://github.com/magna-sec/DotDitto). Add a `LICENSE` before
publishing (bundling GPL `dicc.txt` has redistribution implications).
