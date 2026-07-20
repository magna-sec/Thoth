"""Screenshot module — headless-browser captures of one subdomain or the whole estate.

Rendering needs a real browser, so two backends are tried in order:

  1. **Playwright** (``pip install playwright && python -m playwright install chromium``) —
     best fidelity and the only backend that can do full-page capture.
  2. **A Chrome/Chromium/Edge/Brave binary** driven with ``--headless --screenshot``. No
     Python dependency and usually already installed on an operator's box. Set
     ``THOTH_CHROME=/path/to/binary`` to skip discovery.

PNGs are written to ``DATA_DIR/workspaces/<id>/screenshots/`` so a workspace wipe removes
them along with everything else. Every capture is recorded as a Finding whose ``extra_json``
carries the file name — the gallery and the domain page just render findings, and the
usual "already done" skip applies unless *force* is set.
"""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from pathlib import Path

from flask import current_app

from ..defaultpages import classify as classify_default
from ..extensions import db
from ..models import Finding, Run
from .alive import _do_probe, load_signatures
from .base import Module, register

UA = "Thoth-screenshot/0.1"


class CaptureError(RuntimeError):
    """A single capture failed, or no renderer is available at all."""


def screenshot_dir(workspace_id, create=False):
    """Where a workspace's PNGs live. Inside DATA_DIR/workspaces/<id> so wipe cleans up.

    Always absolute: Flask's send_from_directory resolves a relative directory against the
    app package dir, which would serve 404s for files that are really on disk.
    """
    d = (Path(current_app.config["DATA_DIR"]).resolve()
         / "workspaces" / str(workspace_id) / "screenshots")
    if create:
        d.mkdir(parents=True, exist_ok=True)
    return d


def shot_name(target_id, run_id):
    """Deterministic, path-safe file name (the serving route only allows this shape)."""
    return f"t{target_id}_r{run_id}.png"


# --------------------------------------------------------------------------- backends

_CHROME_NAMES = ("chrome", "google-chrome", "google-chrome-stable", "chromium",
                 "chromium-browser", "msedge", "microsoft-edge", "brave", "brave-browser")

_WINDOWS_PATHS = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
)

_MAC_PATHS = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
)


def chrome_binary():
    """Locate a Chromium-family browser, or None."""
    override = os.environ.get("THOTH_CHROME")
    if override:
        return override if os.path.exists(override) else None
    for name in _CHROME_NAMES:
        found = shutil.which(name)
        if found:
            return found
    extra = _WINDOWS_PATHS if sys.platform == "win32" else (
        _MAC_PATHS if sys.platform == "darwin" else ())
    for path in extra:
        if os.path.exists(path):
            return path
    return None


class Backend:
    """A renderer: ``capture(url, out_path)`` writes a PNG or raises CaptureError.

    ``parallel`` says whether it is safe to call from a thread pool. Playwright's sync API
    binds its objects to the creating thread, so that backend runs one page at a time;
    the Chrome CLI spawns an independent process per shot and parallelises fine.
    """

    def __init__(self, name, capture, parallel, full_page_supported):
        self.name = name
        self.capture = capture
        self.parallel = parallel
        self.full_page_supported = full_page_supported


@contextmanager
def open_backend(width, height, timeout, proxy=None, verify_tls=False, full_page=False):
    """Yield a ready Backend, preferring Playwright. Raises CaptureError if neither exists."""
    try:
        from playwright.sync_api import Error as PWError
        from playwright.sync_api import sync_playwright
    except ImportError:
        sync_playwright = None

    if sync_playwright is not None:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                args=["--ignore-certificate-errors", "--hide-scrollbars"],
                proxy={"server": proxy} if proxy else None)
            context = browser.new_context(viewport={"width": width, "height": height},
                                          ignore_https_errors=not verify_tls, user_agent=UA)

            def capture(url, out_path):
                page = context.new_page()
                try:
                    page.goto(url, timeout=timeout * 1000, wait_until="load")
                    page.screenshot(path=str(out_path), full_page=full_page)
                except PWError as e:
                    raise CaptureError(str(e).strip().splitlines()[0]) from e
                finally:
                    page.close()

            try:
                yield Backend("playwright", capture, parallel=False, full_page_supported=True)
            finally:
                context.close()
                browser.close()
        return

    binary = chrome_binary()
    if not binary:
        raise CaptureError(
            "No renderer found. Install Playwright (pip install playwright && "
            "python -m playwright install chromium) or a Chrome/Chromium/Edge browser, "
            "or set THOTH_CHROME to its path.")

    def capture(url, out_path):
        _chrome_capture(binary, url, out_path, width, height, timeout, proxy, verify_tls)

    yield Backend(f"chrome ({os.path.basename(binary)})", capture,
                  parallel=True, full_page_supported=False)


def _chrome_capture(binary, url, out_path, width, height, timeout, proxy, verify_tls):
    """One headless Chrome invocation. Retries the legacy --headless flag for Chrome <112."""
    last = None
    for headless in ("--headless=new", "--headless"):
        with tempfile.TemporaryDirectory(prefix="thoth-shot-") as profile:
            args = [binary, headless, "--disable-gpu", "--hide-scrollbars", "--no-sandbox",
                    "--disable-dev-shm-usage", "--no-first-run", "--no-default-browser-check",
                    f"--user-data-dir={profile}", f"--user-agent={UA}",
                    f"--window-size={width},{height}",
                    f"--virtual-time-budget={int(timeout * 1000)}",
                    f"--screenshot={out_path}", url]
            if not verify_tls:
                args.insert(2, "--ignore-certificate-errors")
            if proxy:
                args.insert(2, f"--proxy-server={proxy}")
            try:
                proc = subprocess.run(args, capture_output=True, timeout=timeout + 15)
            except subprocess.TimeoutExpired:
                raise CaptureError(f"renderer timed out after {timeout + 15:.0f}s") from None
            except OSError as e:
                raise CaptureError(f"cannot run {binary}: {e}") from e
            if out_path.exists() and out_path.stat().st_size:
                return
            last = (proc.stderr or proc.stdout or b"").decode("utf-8", "ignore").strip()
    raise CaptureError((last or "no image produced").splitlines()[-1][:300])


# ---------------------------------------------------------------------------- module


@register
class ScreenshotModule(Module):
    name = "screenshot"
    version = "0.1"
    description = "Headless-browser screenshot of one subdomain or every subdomain."
    supports_batch = True
    reports_progress = True

    def config_schema(self):
        return [
            {"name": "width", "type": "number", "default": 1440, "label": "Viewport width"},
            {"name": "height", "type": "number", "default": 900, "label": "Viewport height"},
            {"name": "timeout", "type": "number", "default": 20, "label": "Timeout (s)"},
            {"name": "threads", "type": "number", "default": 4, "label": "Threads"},
            {"name": "full_page", "type": "bool", "default": False,
             "label": "Full page (Playwright only)"},
            {"name": "skip_dead", "type": "bool", "default": True,
             "label": "Skip hosts last seen dead"},
            {"name": "verify_tls", "type": "bool", "default": False, "label": "Verify TLS"},
            {"name": "force", "type": "bool", "default": False,
             "label": "Re-capture hosts that already have a screenshot"},
        ]

    def run(self, target, config, ctx):
        self.run_all([target], config, ctx)

    def run_all(self, targets, config, ctx):
        width = int(config.get("width", 1440) or 1440)
        height = int(config.get("height", 900) or 900)
        timeout = float(config.get("timeout", 20) or 20)
        threads = max(1, int(config.get("threads", 4) or 4))
        full_page = bool(config.get("full_page", False))
        verify = bool(config.get("verify_tls", False))
        force = bool(config.get("force", False))

        todo, skipped = self._select(targets, config, ctx, force)
        ctx.set_progress(0, len(todo))
        ctx.log(f"Viewport: {width}x{height} | Timeout: {timeout:.0f}s | Threads: {threads}"
                + (f" | Proxy: {ctx.proxy}" if ctx.proxy else ""))
        for reason, hosts in skipped.items():
            ctx.log(f"Skipping {len(hosts)} host(s) — {reason}")
        if not todo:
            ctx.log("Nothing to capture.")
            ctx.set_progress(0, 0)
            return

        signatures = load_signatures()  # main thread only — see alive.load_signatures
        out_dir = screenshot_dir(ctx.workspace_id, create=True)
        by_id = {t.id: t for t in todo}
        jobs = [(t.id, t.base_url, out_dir / shot_name(t.id, ctx.run.id)) for t in todo]

        with open_backend(width, height, timeout, ctx.proxy, verify, full_page) as backend:
            ctx.log(f"Renderer: {backend.name}")
            if full_page and not backend.full_page_supported:
                ctx.log("Full-page capture needs Playwright — capturing the viewport instead.")

            def work(url, out_path):
                """Runs in a worker thread: no ORM here, only HTTP + the browser."""
                probe = _do_probe(url, timeout, verify, ctx.proxies, signatures)
                try:
                    backend.capture(url, out_path)
                except CaptureError as e:
                    return probe, None, str(e)
                data = out_path.read_bytes()
                return probe, {"bytes": len(data),
                               "sha256": hashlib.sha256(data).hexdigest()}, None

            done = 0
            # Findings are written here, on the main thread — the ORM session isn't
            # thread-safe (same split as the alive module).
            if backend.parallel and threads > 1 and len(jobs) > 1:
                with ThreadPoolExecutor(max_workers=min(threads, len(jobs))) as ex:
                    futs = {ex.submit(work, url, path): (tid, path)
                            for tid, url, path in jobs}
                    for fut in ctx.each_completed(ex, futs):
                        tid, path = futs[fut]
                        self._record(ctx, by_id[tid], path, *fut.result(), width=width,
                                     height=height, full_page=full_page,
                                     backend=backend.name)
                        done += 1
                        ctx.set_progress(done, len(jobs))
            else:
                for tid, url, path in jobs:
                    ctx.raise_if_cancelled()  # sequential (Playwright) backend
                    self._record(ctx, by_id[tid], path, *work(url, path), width=width,
                                 height=height, full_page=full_page, backend=backend.name)
                    done += 1
                    ctx.set_progress(done, len(jobs))

        captured = sum(1 for _, _, p in jobs if p.exists())
        ctx.log("")
        ctx.log(f"Task Completed — {captured}/{len(jobs)} screenshot(s) captured")

    def _select(self, targets, config, ctx, force):
        """Drop dead hosts and (unless forced) ones already captured in an earlier run."""
        skipped = {}
        todo = list(targets)
        if bool(config.get("skip_dead", True)):
            dead = [t for t in todo if t.last_alive is False]
            if dead:
                skipped["last seen dead (untick 'Skip hosts last seen dead' to include)"] = dead
                todo = [t for t in todo if t.last_alive is not False]
        if not force and todo:
            seen = {tid for (tid,) in db.session.query(Finding.target_id)
                    .join(Run, Finding.run_id == Run.id)
                    .filter(Finding.workspace_id == ctx.workspace_id,
                            Run.module == self.name,
                            Finding.target_id.in_([t.id for t in todo])).distinct()}
            already = [t for t in todo if t.id in seen]
            if already:
                skipped["already captured (tick Force to re-capture)"] = already
                todo = [t for t in todo if t.id not in seen]
        return todo, skipped

    def _record(self, ctx, target, path, probe, shot, error, **meta):
        """Emit one finding for a capture attempt (success or failure)."""
        extra = dict(probe["extra"], module=self.name, **meta)
        # Label server defaults / parked pages so the gallery can push them aside — they
        # are the bulk of any estate's captures and the least worth looking at.
        label = classify_default(extra.get("title"), extra.get("server"),
                                 probe.get("content_length"))
        if label:
            extra["default_page"] = label
        if shot:
            extra.update(screenshot=path.name, **shot)
            size = f"{shot['bytes'] / 1024:.0f}KB"
            line = f"{probe['status_code'] or '---'} - {size:>9} - {target.host} → {path.name}"
        else:
            extra["screenshot_error"] = error
            line = f"FAILED - {target.host} - {error}"
        ctx.finding(target, path="/", status_code=probe["status_code"],
                    content_length=probe["content_length"], redirect=probe["redirect"],
                    log=line, **extra)
