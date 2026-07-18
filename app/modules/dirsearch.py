"""Directory fuzzing module.

A lean, dependency-free fuzzer that follows dirsearch conventions (default db/dicc.txt,
the %EXT% placeholder, wildcard/404 baseline detection, recursion). It records every word
it requests in the TestedPath ledger keyed by (workspace, host, parent_path, word), so the
same path is never re-tested on a re-run or by another operator — the whole point of Thoth.

This is a lean interim engine; dirsearch's vendored Fuzzer/Requester could later be
swapped in behind this same interface without changing anything else.
"""
import os
import random
import string
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from flask import current_app

from ..extensions import db
from ..models import TestedPath
from .base import Module, register

INTERESTING = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500, 501, 503}
DIR_STATUSES = {301, 302, 307, 308, 403}


@register
class DirsearchModule(Module):
    name = "dirsearch"
    version = "0.1"
    description = "Directory/file fuzzing with dedup ledger, wildcard detection, and recursion."
    reports_progress = True

    def config_schema(self):
        return [
            {"name": "extensions", "type": "text", "default": "php,html,txt",
             "label": "Extensions (%EXT%)"},
            {"name": "wordlist_dir", "type": "text", "default": "",
             "label": "Wordlist dir (optional)"},
            {"name": "recursion_depth", "type": "number", "default": 2, "label": "Recursion depth"},
            {"name": "threads", "type": "number", "default": 20, "label": "Threads"},
            {"name": "timeout", "type": "number", "default": 8, "label": "Timeout (s)"},
            {"name": "verify_tls", "type": "bool", "default": False, "label": "Verify TLS"},
            {"name": "verbose", "type": "bool", "default": True, "label": "Verbose output"},
            {"name": "force", "type": "bool", "default": False,
             "label": "Force re-scan (ignore dedup)"},
        ]

    def run(self, target, config, ctx):
        exts = [e.strip().lstrip(".") for e in
                str(config.get("extensions", "php,html,txt")).split(",") if e.strip()]
        candidates = _load_candidates(config.get("wordlist_dir") or "", exts)
        threads = int(config.get("threads", 20) or 20)
        timeout = float(config.get("timeout", 8) or 8)
        verify = bool(config.get("verify_tls", False))
        max_depth = int(config.get("recursion_depth", 2) or 1)
        force = bool(config.get("force", False))

        verbose = bool(config.get("verbose", True))
        session = requests.Session()
        session.headers["User-Agent"] = "Thoth-dirsearch/0.1"
        if ctx.proxies:
            session.proxies.update(ctx.proxies)
        base_url = target.base_url

        # dirsearch-style CLI header.
        if verbose:
            ctx.log(f"Extensions: {', '.join(exts) or 'none'} | HTTP method: GET | "
                    f"Threads: {threads} | Wordlist size: {len(candidates)}"
                    + (f" | Proxy: {ctx.proxy}" if ctx.proxy else ""))
            ctx.log(f"Target: {base_url}/")
            ctx.log("")
            ctx.log(f"Starting: {target.host}")

        stats = {"tested": 0, "hits": 0}
        prog = {"done": 0, "total": 0, "last": 0.0}
        scanned_parents = set()

        def _bump_done():
            prog["done"] += 1
            now = time.monotonic()
            if now - prog["last"] > 0.7:  # throttle DB writes
                prog["last"] = now
                ctx.set_progress(prog["done"], prog["total"])

        def scan(parent_path, depth):
            if parent_path in scanned_parents or depth < 0:
                return
            scanned_parents.add(parent_path)
            if verbose and parent_path != "/":
                ctx.log(f"Added to the queue: {parent_path}")

            tested = {row.word for row in TestedPath.query.filter_by(
                workspace_id=ctx.workspace_id, host=target.host, parent_path=parent_path).all()}
            already = len(tested)
            if force:
                todo = list(candidates)
                if verbose and already:
                    ctx.log(f"Force mode: re-testing {already} already-covered word(s) "
                            f"at {parent_path}")
            else:
                todo = [c for c in candidates if c not in tested]
                if verbose and len(candidates) - len(todo):
                    ctx.log(f"Skipping {len(candidates) - len(todo)} already-tested word(s) "
                            f"at {parent_path} (dedup — enable Force re-scan to test anyway)")
            if not todo:
                return

            prog["total"] += len(todo)
            ctx.set_progress(prog["done"], prog["total"])

            wildcard = _wildcard_baseline(session, base_url, parent_path, timeout, verify)
            if verbose and wildcard:
                ctx.log(f"Wildcard response at {parent_path}: {wildcard[0]} "
                        f"({_humansize(wildcard[1])}) — suppressed")

            results = []
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futs = {ex.submit(_probe, session, base_url, parent_path, c, timeout, verify): c
                        for c in todo}
                for fut in as_completed(futs):
                    results.append(fut.result())
                    _bump_done()
            stats["tested"] += len(results)

            # DB writes happen here in the main thread (session isn't thread-safe).
            discovered_dirs = []
            for cand, path, status, length, location in results:
                if cand not in tested:  # never duplicate a ledger row (force re-tests them)
                    db.session.add(TestedPath(workspace_id=ctx.workspace_id, host=target.host,
                                              parent_path=parent_path, word=cand,
                                              status_code=status))
                if _is_hit(status, length, wildcard):
                    stats["hits"] += 1
                    arrow = f"  ->  {location}" if location else ""
                    line = f"{status} -  {_humansize(length):>9} - {path}{arrow}"
                    ctx.finding(target, path=path, status_code=status,
                                content_length=length, redirect=location,
                                module="dirsearch", log=line if verbose else None)
                    if depth >= 1 and _looks_like_dir(cand, status, path, location):
                        discovered_dirs.append(path.rstrip("/") + "/")
            db.session.commit()

            for d in discovered_dirs:
                scan(d, depth - 1)

        scan("/", max_depth)
        ctx.set_progress(prog["total"], prog["total"])  # 100%
        if verbose:
            ctx.log("")
            ctx.log(f"Task Completed — {stats['tested']} request(s), {stats['hits']} hit(s)")


def _fetch(session, url, timeout, verify):
    """Stream the response and size it from Content-Length (or a small bounded read) so
    we never download whole page bodies — thousands of full-body GETs are what made the
    app crawl during a scan. Returns (status, length, location)."""
    r = session.get(url, timeout=timeout, allow_redirects=False, verify=verify, stream=True)
    try:
        cl = r.headers.get("Content-Length")
        if cl is not None and cl.isdigit():
            length = int(cl)
        else:
            length = len(r.raw.read(2048, decode_content=True) or b"")
        return r.status_code, length, r.headers.get("Location")
    finally:
        r.close()


def _probe(session, base_url, parent_path, cand, timeout, verify):
    path = _join(parent_path, cand)
    try:
        status, length, location = _fetch(session, base_url + path, timeout, verify)
        return cand, path, status, length, location
    except requests.RequestException:
        return cand, path, None, None, None


def _wildcard_baseline(session, base_url, parent_path, timeout, verify):
    """Request a random path; if the server answers non-404, treat that (status,length)
    as the wildcard signature so we can suppress matching false positives."""
    rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    path = _join(parent_path, rnd)
    try:
        status, length, _ = _fetch(session, base_url + path, timeout, verify)
        if status not in (404, None):
            return (status, length)
    except requests.RequestException:
        return None
    return None


def _is_hit(status, length, wildcard):
    if status is None or status == 404 or status not in INTERESTING:
        return False
    if wildcard and (status, length) == wildcard:
        return False
    return True


def _looks_like_dir(cand, status, path, location):
    if "." in cand.rsplit("/", 1)[-1]:
        return False
    if status in DIR_STATUSES:
        if location and location.rstrip("/").endswith(path.rstrip("/")):
            return True
        return status == 403
    return status == 200


def _humansize(n):
    if n is None:
        return "?"
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)}{unit}" if unit == "B" else f"{size:.0f}{unit}"
        size /= 1024


def _join(parent_path, cand):
    return (parent_path.rstrip("/") + "/" + cand.lstrip("/"))


def _load_candidates(wordlist_dir, exts):
    """Load words from a directory of *.txt, else wordlists/dicc.txt, else common.txt.
    Expands the dirsearch %EXT% placeholder using the configured extensions."""
    wl_root = current_app.config["WORDLIST_DIR"]
    files = []
    if wordlist_dir and os.path.isdir(wordlist_dir):
        files = [os.path.join(wordlist_dir, f) for f in os.listdir(wordlist_dir)
                 if f.lower().endswith(".txt")]
    if not files:
        dicc = os.path.join(wl_root, "dicc.txt")  # drop dirsearch's real list here
        files = [dicc] if os.path.exists(dicc) else [os.path.join(wl_root, "common.txt")]

    seen, candidates = set(), []

    def push(word):
        word = word.strip().lstrip("/")
        if word and word not in seen:
            seen.add(word)
            candidates.append(word)

    for fp in files:
        try:
            with open(fp, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "%EXT%" in line:
                        for e in exts:
                            push(line.replace("%EXT%", e))
                    else:
                        push(line)  # plain words used as-is (dirsearch default)
        except OSError:
            continue
    return candidates
