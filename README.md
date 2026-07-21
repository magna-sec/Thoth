<p align="center">
  <img src="docs/thoth.svg" alt="Thoth — cyber enumeration platform" width="560">
</p>

# Thoth

A modular, multiplayer **cyber enumeration platform**. Organise engagements into per-client
**workspaces**, then plug in **capabilities**: *modules* that run against targets (subdomain
discovery, liveness, directory fuzzing, screenshots, IIS short-name enumeration…) and
*parsers* that ingest artifacts you already have (PAC files, `dsregcmd /status`…). Everything
auto-registers — drop a file in and it appears. Subdomain enumeration is the core; the
platform grows around it. See the [Plugins](#plugins) catalogue.

Its directory fuzzer follows [**dirsearch**](https://github.com/maurosoria/dirsearch)
(uses its `dicc.txt` and conventions), and a **dedup ledger** means the same path is never
re-fuzzed twice — no duplicated work between runs or teammates.

> For authorized security testing only. Only scan hosts you have permission to test.
> Thoth only touches a target during an **explicit** run (alive, dnsbrute, dirsearch,
> screenshot, iistilde) or a manual **Check live** — browsing the UI, viewing a subdomain,
> and every parser (PAC, dsregcmd, nmap, nessus, Conditional Access, nuclei) make **no**
> outbound requests.

## Features

- **Workspaces** per engagement, with one-command **wipe**.
- **Scope guard** — an allow/deny list per engagement, enforced before every request. See
  [Scope](#scope).
- **Discovery** — wildcard-aware DNS brute force that also permutates the subdomains you
  already have. See [Discovery](#discovery).
- **Subdomains** — paste/upload lists (lowercased, de-duped, sorted); multi-threaded
  **Check all live** colour-codes each, sweeps **8080/8443** so alt-port admin panels and
  dev copies get flagged, and falls back to `http` when `https` doesn't answer (so
  port-80-only hosts aren't silently recorded dead).
- **Export** — findings, host inventory, bare URLs or a parameter wordlist, as CSV / JSON /
  Markdown / TXT. See [Exports](#exports).
- **Enrichment** — resolves each host's **IP → ASN → owner/country** (Team Cymru) and detects
  **WAF/CDN**, server, and tech — with a fingerprint set **you can extend**. See
  [Fingerprints](#fingerprints).
- **Screenshots** — headless-browser capture of one subdomain or the whole estate, with a
  filterable gallery. See [Screenshots](#screenshots).
- **Directory fuzzing** (dirsearch-style) — recursive, wildcard/404-aware, `dicc.txt` by
  default, with a **dedup ledger** and a **force re-scan** escape hatch.
- **Import real dirsearch output** — paste or upload a run you did outside Thoth; it becomes
  findings *and* ledger entries, so nothing gets re-fuzzed. See [Importing](#importing-real-dirsearch-output).
- **Import nuclei results** — paste/upload nuclei JSONL or JSON; each finding is matched to
  its subdomain by host and surfaced as a severity-ranked **Vulnerabilities** panel. See
  [Nuclei](#nuclei-and-bulk-actions).
- **IIS tilde enumeration** — recover 8.3 short names from exposed IIS hosts.
  See [IIS tilde](#iis-tilde-enumeration).
- **Recon artifacts** — paste `dsregcmd /status`, a PAC file, an nmap scan or a `.nessus`
  export; Thoth parses each into a readable view (join/tenant state; proxies + DIRECT
  estate + misconfigs; hosts/ports/services; vulnerabilities by severity). See
  [Artifacts](#recon-artifacts).
- **Results** — rich filters (status, exclude-status/size, WAF, hide dead/3xx) that **stick
  across refreshes** and clickable paths that open in your own browser.
- **Analysis** — ASN ownership, WAF vendors, tech, servers, and countries across the estate.
- **Tasks** with live progress + persisted CLI-style output, and a **Stop** button — the
  task finishes its in-flight requests and unwinds, keeping the findings and dedup entries
  it already recorded, so a re-run carries on rather than starting over. Live updates via
  SSE; Burp proxy support; per-subdomain notes; 7 UI themes.

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

## Scope

Set an engagement scope in **Directory Fuzzing → Settings**. One rule per line:

```
example.com          exact host
*.example.com        any subdomain, and the apex
!vendor.example.com  explicit deny — always wins
```

No allow rules means no restriction (existing workspaces are unaffected). Once any allow
rule exists, **only** matching hosts are ever requested. It's enforced centrally — in the
task runner and the quick-check — rather than per module, so a new module can't forget it.
Tasks skip out-of-scope hosts and say so in the run log, discovery
drops them before resolving, and the Subdomains tab greys them with an
**out of scope** badge.

## Discovery

**Subdomains → Discover** brute-forces DNS for a root domain. It is:

- **wildcard-aware** — resolves random labels first and suppresses answers matching the
  wildcard, so a `*.example.com` zone doesn't "find" your entire wordlist;
- **permutation-driven** — `api.example.com` generates `api-dev`, `dev-api`, `api2`,
  `api-staging`… which beats a generic list on estates named by humans;
- **deduped** — every label tried is remembered per (workspace, domain), so re-runs and
  teammates never repeat work, with a **Force** escape hatch;
- **scope-bound** — a discovered name outside scope is dropped, not added.

Custom resolvers and wordlists are optional; with neither, it uses the system resolver and
a built-in list. Discovered hosts become subdomains, ready for alive/fuzz/screenshot.

## Exports

Four datasets × four formats, from the Results tab (whole workspace) or a subdomain's
**Pages** tab (that host only):

| Dataset | What you get |
| --- | --- |
| `findings` | every result: host, URL, status, size, redirect, server, title, tech, WAF |
| `hosts` | the inventory: IP, ASN/owner/country, WAF, tech, tags, open ports, in-scope |
| `urls` | bare URLs, one per line — the shape other tools eat |
| `params` | distinct parameter names seen, commonest first — a param wordlist |

CSV/JSON/Markdown for humans and spreadsheets, TXT (tab-separated, or plain lines for
`urls`/`params`) for pipes.

## Nuclei

The **nuclei** parser plugin (add it from the workspace **Plugins** tab) takes the output of a nuclei
run — `nuclei -jsonl` or `nuclei -json`, pasted or uploaded. Each finding is matched to its
subdomain **by host**; findings for hosts that aren't subdomains in the workspace are
reported, not invented. Matches carry their **severity** and show up as a ranked
**Vulnerabilities** panel on the subdomain page (critical → info) — the results go straight
onto the subdomains rather than being stored as a separate artifact. Both nuclei field
spellings (`template-id` / `templateID`, `matched-at` / `matched_at`) are understood.

## IIS tilde enumeration

For IIS hosts, **IIS tilde ▶** (subdomain page) or **Scan N IIS host(s) for tilde ▶**
(Subdomains tab, appears when any host is fingerprinted as IIS) recovers **8.3 short names**
via the classic tilde (`~`) disclosure — inspired by PortSwigger's
[iis-tilde-enumeration-scanner](https://github.com/portswigger/iis-tilde-enumeration-scanner).
Two phases:

1. **Detect** — a wildcard that should match if any short name exists (`/*~1*/…`) vs an
   improbable control; exposed only when their HTTP statuses differ in the tell-tale way
   (classically 404 match / 400 miss). A patched server answers both identically.
2. **Enumerate** — extend a prefix a character at a time (`/A*~1*/…` → `/AD*~1*/…`),
   keeping matching branches up to the 6-char stem, then the 3-char extension, probing
   `~2…~9` for collisions. Recovered names (`ADMIN~1.ASP`) show under the Vulnerabilities
   panel.

Read-only and bounded by a per-host request budget; skips non-IIS hosts unless forced;
stoppable mid-run (findings so far are kept); governed by the [engagement scope](#scope).
**For authorized testing only.**

## Plugins

Thoth is plug-and-play: every capability is a plugin that **auto-registers at startup**, so
adding one is a one-file change and it appears throughout the UI. The **Plugins** page
(top nav) is the live catalogue. Two kinds:

- **Modules** — run against a workspace's targets and produce findings. `alive`, `dnsbrute`,
  `dirsearch`, `screenshot`, `iistilde`. Drop `app/modules/yours.py` with a `@register`
  class extending `Module`.
- **Parsers** — ingest an artifact you already have and either render it (`pac`, `dsregcmd`,
  `nmap`, `nessus`, `roadrecon-cap`) or fold it onto the workspace's subdomains (`nuclei`, a `kind = "findings"` parser
  that writes each finding to the matching host's Vulnerabilities panel). Drop
  `app/plugins/yours_plugin.py` with a `@register_parser` class extending `ParserPlugin`
  (a `detect()`, a `parse()`, and either a render partial under `templates/plugins/` or an
  `ingest()`).

No registry edits, no route wiring — the framework discovers it. The upload picker,
auto-detect, the catalogue, and per-artifact rendering all populate from the registry.

**Plugins are enabled per workspace.** When you create a workspace you pick which plugins the
engagement needs (all on by default); the owner/admin can change the selection later in the
workspace **Settings**. Disabled plugins are enforced server-side (their runs and imports are
rejected) and hidden from the UI — tabs, buttons and the artifact picker only show what's
enabled.

## Recon artifacts

The workspace **Plugins** tab is the hub for the parser plugins: it shows which capabilities
are enabled for the engagement (with inline enable/disable for the owner/admin), an **Import**
form, and the **saved artifacts** list. Imports are parsed into a tidy, per-artifact view —
nothing is executed, it's pure text parsing:

- **`dsregcmd /status`** — a device's Entra ID (Azure AD) / domain join state. A plain-English
  headline (e.g. *Hybrid Azure AD joined to Contoso*), a **Notable** panel of security-relevant
  findings (PRT present, MDM enrolment, non-TPM device key), an at-a-glance grid, and the full
  boxed sections as tables.
- **PAC files** (`FindProxyForURL`) — the reconstructed **rules** (condition → PROXY/DIRECT, in
  order), the proxy servers, and the internal hostnames/domains/subnets routed **DIRECT** (the
  estate that bypasses the proxy — recon gold). Plus a **Misconfigurations** panel that flags:
  credentials in a proxy string, a proxy on a public IP, DNS-leak helpers (`isInNet`/`dnsResolve`
  on the host), `0.0.0.0/0` or public ranges routed DIRECT, **proxy-failure fallback to DIRECT**
  (`"PROXY x; DIRECT"` bypasses egress control if the proxy is down), `myIpAddress()`-based
  routing, SOCKS4, secrets in the file, risky defaults, and internal-estate disclosure (PAC/WPAD
  is often served unauthenticated). Parsed statically — the rule pairing is a best-effort read of
  typical PAC structure, not a JS interpreter.
- **nmap** (`-oX` XML, `-oG` greppable, or the normal report) — live hosts, open ports, services
  and versions, with notable services (SMB, LDAP, Kerberos, RDP, databases…) highlighted.
- **Nessus** (`.nessus` export) — scanned hosts and their vulnerabilities ranked by severity
  (critical → info), with CVSS, CVEs, a filterable critical/high table, and per-host detail.
- **Conditional Access** (ROADrecon dump or a Graph export) — every Entra ID CA policy shown
  clearly (state, who/what/conditions/grant), plus a **Coverage gaps** panel that flags the
  classic holes CA reviews look for: legacy auth not blocked, MFA not required for all users,
  admins unprotected, exclusion "backdoors", MFA scoped to browsers only, and
  trusted-location IP bypasses.

Paste or upload; the type is auto-detected (or pick it). Saved per workspace and wiped with
it. Large lists (e.g. a PAC's hundreds of DIRECT hosts) render as bounded, filterable
clouds rather than a wall of chips.

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

Captures are labelled when they look like a server default (**IIS default**, **nginx
default**, **Parked**, **Placeholder**…) — these are the bulk of any estate and the least
worth looking at, so the gallery can hide them in one click. Byte-identical captures are
counted (`×12`), which collapses "the same holding page on twelve hosts" into one glance.

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
alt-port sweep, scheme fallback), the scope guard (matching rules and that nothing out of
scope is requested), DNS discovery (wildcard suppression, permutations, dedup, scope) with
a fake resolver, exports (all datasets and formats), custom fingerprint signatures,
default-page detection, screenshots (capture bookkeeping, skip rules, image serving —
against a stub renderer, so no browser needed), dirsearch import parsing, nuclei parsing +
host-matched import, IIS 8.3 short-name enumeration (against a faithful fake
IIS server — detection, name recovery, collisions, budget), the parser plugins (dsregcmd,
PAC incl. misconfig detection, nmap XML/greppable/normal), per-workspace plugin
enable/disable + enforcement, the plugin framework (registry, auto-detect, drop-in), task
stopping/cancellation, URL/tree analysis, ASN parsing, and routes (import, wipe-cascade,
access control, filters).

## Credits

Default wordlist and fuzzing conventions from
[dirsearch](https://github.com/maurosoria/dirsearch) (GPL-2.0; `dicc.txt` retains its
license) · IP-to-ASN via [Team Cymru](https://www.team-cymru.com/ip-asn-mapping) · UI
inspired by [DotDitto](https://github.com/magna-sec/DotDitto). Add a `LICENSE` before
publishing (bundling GPL `dicc.txt` has redistribution implications).
