"""IIS 8.3 short-name (tilde) enumeration.

Old/misconfigured IIS leaks the existence — and, character by character, the **names** — of
files and directories, because it answers differently for a wildcard 8.3 "short name"
(``SECRET~1.TXT``) that matches something on disk than for one that can't. That differential
is the vulnerability; walking it recovers the short names.

Inspired by PortSwigger's iis-tilde-enumeration-scanner. Two phases:

  1. **Detect** — send a wildcard that should match if any short name exists
     (``/*~1*/…``) and an improbable control; the host is exposed only when their HTTP
     statuses differ in the tell-tale way (classically 404 for the match, 400 for the miss).
  2. **Enumerate** — extend a prefix one character at a time (``/A*~1*/…`` → ``/AD*~1*/…``
     → …), keeping branches that still match, up to the 6-character stem, then the 3-char
     extension, and probing ``~2…~9`` for name collisions. The recovered short names
     (e.g. ``ADMIN~1.ASP``) are enough to guess or brute-force the full long names.

Read-only, bounded (a request budget and cancellation), and governed by the engagement
scope like every module. **For authorized testing only.**
"""
import random
import string

import requests

from .base import Module, TaskCancelled, register

# 8.3 short names are upper-cased; the vast majority of real names use just these. Symbols
# are legal but rare, so they're left out to keep the request count sane.
NAME_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
EXT_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
MAX_STEM = 6
MAX_EXT = 3
MAX_TILDE_INDEX = 9

# Suffix that turns the tilde expression into its own path segment (``/{expr}/.aspx``) and
# invokes a handler that yields the 404/400 split. All start with "/" on purpose.
_SUFFIXES = ("/.aspx", "/a.aspx", "/a.asp")


class _BudgetExceeded(Exception):
    """The per-host request budget ran out mid-enumeration."""


def _looks_like_iis(target):
    hay = " ".join(filter(None, [
        target.last_server, target.last_tech, target.manual_tech or ""])).lower()
    return "iis" in hay or "microsoft" in hay or "asp.net" in hay


def _status(session, url, timeout, verify):
    try:
        return session.get(url, timeout=timeout, allow_redirects=False,
                           verify=verify).status_code
    except requests.RequestException:
        return None


def detect(base_url, session, timeout=8, verify=False):
    """Phase 1. Returns a dict; ``vulnerable`` is the headline, plus the ``found``/``miss``
    statuses and the working ``suffix`` that phase 2 reuses."""
    rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    attempts = []
    for suffix in _SUFFIXES:
        magic = _status(session, f"{base_url}/*~1*{suffix}", timeout, verify)
        control = _status(session, f"{base_url}/{rnd}*~1*{suffix}", timeout, verify)
        attempts.append({"suffix": suffix, "magic": magic, "control": control})
        # Statuses differ AND a 400 is involved — IIS accepting the matched short name
        # while rejecting the invalid one. Both-equal = patched, or a server that just
        # dislikes the characters: not vulnerable.
        if (magic is not None and control is not None and magic != control
                and 400 in (magic, control)):
            return {"vulnerable": True, "found": magic, "miss": control,
                    "suffix": suffix, "magic_status": magic, "control_status": control,
                    "attempts": attempts}
    last = attempts[-1] if attempts else {"magic": None, "control": None}
    return {"vulnerable": False, "found": None, "miss": None, "suffix": _SUFFIXES[0],
            "magic_status": last.get("magic"), "control_status": last.get("control"),
            "attempts": attempts}


def enumerate_names(base_url, session, found, suffix, timeout=8, verify=False,
                    budget=6000, cancel=lambda: False, on_name=None):
    """Phase 2. Walk the differential to recover short names.

    Returns ``(names, requests_made, truncated)``. ``names`` are strings like
    ``ADMIN~1.ASP``. Stops cleanly when the budget is spent (``truncated=True``) or the
    run is cancelled.
    """
    state = {"n": 0}
    names, seen = [], set()

    def hit(expr):
        if cancel():
            raise TaskCancelled          # propagates to the task runner → 'cancelled'
        if state["n"] >= budget:
            raise _BudgetExceeded
        state["n"] += 1
        return _status(session, f"{base_url}/{expr}{suffix}", timeout, verify) == found

    def record(name):
        if name not in seen:
            seen.add(name)
            names.append(name)
            if on_name:
                on_name(name)

    def scan_ext(stem, idx, ext_prefix):
        results = []
        for c in EXT_CHARSET:
            cand = ext_prefix + c
            if not hit(f"{stem}~{idx}.{cand}*"):   # any extension starting with cand
                continue
            if len(cand) >= MAX_EXT or hit(f"{stem}~{idx}.{cand}"):  # complete extension
                results.append(cand)
            if len(cand) < MAX_EXT:
                results.extend(scan_ext(stem, idx, cand))
        return results

    def finalize(stem, idx):
        exts = scan_ext(stem, idx, "")
        for e in exts:
            record(f"{stem}~{idx}.{e}")
        # A name with no extension (directory, or extensionless file).
        if hit(f"{stem}~{idx}") or not exts:
            record(f"{stem}~{idx}")

    def scan_stem(prefix, idx):
        # Is `prefix` itself a complete stem (name is exactly these chars)?
        if prefix and hit(f"{prefix}~{idx}*"):
            finalize(prefix, idx)
        if len(prefix) < MAX_STEM:
            for c in NAME_CHARSET:
                if hit(f"{prefix}{c}*~{idx}*"):    # some stem starts with prefix+c
                    scan_stem(prefix + c, idx)

    truncated = False
    try:
        scan_stem("", 1)
        # Collisions: probe higher tilde indices for the stems we already found.
        for stem in {n.split("~", 1)[0] for n in list(names)}:
            for idx in range(2, MAX_TILDE_INDEX + 1):
                if hit(f"{stem}~{idx}*"):
                    finalize(stem, idx)
    except _BudgetExceeded:
        truncated = True
    names.sort()
    return names, state["n"], truncated


@register
class IisTildeModule(Module):
    name = "iistilde"
    version = "0.2"
    description = "Enumerate IIS 8.3 short names via tilde (~) disclosure."
    supports_batch = True
    reports_progress = True

    def config_schema(self):
        return [
            {"name": "timeout", "type": "number", "default": 8, "label": "Timeout (s)"},
            {"name": "verify_tls", "type": "bool", "default": False, "label": "Verify TLS"},
            {"name": "enumerate", "type": "bool", "default": True,
             "label": "Enumerate names (not just detect)"},
            {"name": "budget", "type": "number", "default": 6000,
             "label": "Max requests per host"},
            {"name": "only_iis", "type": "bool", "default": True,
             "label": "Only test hosts fingerprinted as IIS",
             "help": "Untick to test every selected host regardless of server"},
        ]

    def run(self, target, config, ctx):
        self.run_all([target], config, ctx)

    def run_all(self, targets, config, ctx):
        timeout = float(config.get("timeout", 8) or 8)
        verify = bool(config.get("verify_tls", False))
        only_iis = bool(config.get("only_iis", True))
        do_enum = bool(config.get("enumerate", True))
        budget = int(config.get("budget", 6000) or 6000)

        session = requests.Session()
        session.headers["User-Agent"] = "Thoth-iistilde/0.2"
        if ctx.proxies:
            session.proxies.update(ctx.proxies)

        ctx.set_progress(0, len(targets))
        vuln = tested = skipped = 0
        for i, target in enumerate(targets):
            ctx.raise_if_cancelled()
            if only_iis and not _looks_like_iis(target):
                skipped += 1
                ctx.log(f"skip   {target.host} — not fingerprinted as IIS "
                        f"(run alive first, or untick 'Only test IIS hosts')")
                ctx.set_progress(i + 1, len(targets))
                continue

            tested += 1
            det = detect(target.base_url, session, timeout, verify)
            if not det["vulnerable"]:
                ctx.finding(target, path="/", status_code=det["magic_status"],
                            module=self.name, vulnerable=False, severity="info",
                            title="IIS tilde check — not vulnerable",
                            magic_status=det["magic_status"],
                            control_status=det["control_status"],
                            log=f"ok     {target.host} — not vulnerable "
                                f"({det['magic_status']}/{det['control_status']})")
                ctx.set_progress(i + 1, len(targets))
                continue

            vuln += 1
            ctx.log(f"VULN   {target.host} — 8.3 short-name enumeration exposed "
                    f"(match {det['found']} vs miss {det['miss']})")

            names, reqs, truncated = [], 0, False
            if do_enum:
                names, reqs, truncated = enumerate_names(
                    target.base_url, session, det["found"], det["suffix"], timeout, verify,
                    budget=budget, cancel=lambda: ctx.cancelled,
                    on_name=lambda n: ctx.log(f"  found  {n}"))
                ctx.log(f"  {len(names)} short name(s) recovered in {reqs} request(s)"
                        + (" (budget hit — partial)" if truncated else ""))

            ctx.finding(
                target, path="/", status_code=det["magic_status"], module=self.name,
                vulnerable=True, severity="high" if names else "medium",
                title=(f"IIS 8.3 short-name enumeration — {len(names)} name(s)"
                       if names else "IIS 8.3 short-name enumeration exposed"),
                magic_status=det["magic_status"], control_status=det["control_status"],
                shortnames=names, requests_made=reqs, truncated=truncated,
                description=", ".join(names[:60]))
            ctx.set_progress(i + 1, len(targets))

        ctx.log("")
        ctx.log(f"Task Completed — {vuln} vulnerable, {tested - vuln} not, "
                f"{skipped} skipped (non-IIS)")
