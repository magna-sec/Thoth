"""Alive / reachability module + a reusable single-domain probe."""
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests

from ..enrich import enrich
from .base import Module, register


def _do_probe(url, timeout, verify, proxies):
    """Pure HTTP probe of a URL — no ORM/DB touch, so it is safe to call from worker
    threads. Returns the normalized result dict."""
    started = time.monotonic()
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, verify=verify,
                         proxies=proxies, headers={"User-Agent": "Thoth/0.1"})
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {
            "status_code": r.status_code,
            "content_length": len(r.content),
            "redirect": r.url if r.url != url else None,
            "extra": {
                "server": r.headers.get("Server"),
                "powered_by": r.headers.get("X-Powered-By"),
                "tech": _fingerprint(r),
                "waf": _detect_waf(r),
                "title": _title(r.text),
                "elapsed_ms": elapsed_ms,
                "alive": True,
            },
        }
    except requests.RequestException as e:
        return {"status_code": None, "content_length": None, "redirect": None,
                "extra": {"alive": False, "error": type(e).__name__}}


def _apply(target, result):
    """Write a probe result onto the target's cached last_* fields (main thread only)."""
    now = datetime.utcnow()
    target.last_status_code = result["status_code"]
    target.last_alive = result["extra"]["alive"]
    target.last_checked_at = now
    if result["extra"]["alive"]:
        target.last_alive_at = now
        target.last_waf = ", ".join(result["extra"].get("waf") or []) or None
        target.last_server = (result["extra"].get("server") or None)
        target.last_title = (result["extra"].get("title") or None)
        target.last_tech = ", ".join(result["extra"].get("tech") or []) or None


def _apply_enrich(target, info):
    """Store resolved IP + ASN/owner/country on the target (only overwrite when found)."""
    if info.get("ip"):
        target.ip = info["ip"]
    if info.get("asn"):
        target.asn = info["asn"]
        target.asn_name = info.get("asn_name")
        target.country = info.get("country")


def probe(target, timeout=8, verify=False, proxies=None):
    """Probe a single target and update its cached fields (used by the quick-check)."""
    result = _do_probe(target.base_url, timeout, verify, proxies)
    _apply(target, result)
    return result


def _detect_waf(r):
    """Best-effort WAF/CDN detection from headers, cookies, and body signatures."""
    headers = {k.lower(): (v or "") for k, v in r.headers.items()}
    server = headers.get("server", "").lower()
    cookies = " ".join(r.cookies.keys()).lower()
    body = r.text[:8000].lower()
    hits = []

    def add(name):
        if name not in hits:
            hits.append(name)

    if "cf-ray" in headers or "cloudflare" in server or "attention required! | cloudflare" in body:
        add("Cloudflare")
    if "x-akamai-transformed" in headers or "akamai" in server or "akamaighost" in server:
        add("Akamai")
    if "x-iinfo" in headers or "incap_ses" in cookies or "visid_incap" in cookies \
            or "incapsula" in server or "request unsuccessful. incapsula" in body:
        add("Imperva Incapsula")
    if "x-sucuri-id" in headers or "x-sucuri-cache" in headers or "sucuri" in server:
        add("Sucuri")
    if "x-amz-cf-id" in headers or "cloudfront" in server:
        add("AWS CloudFront")
    if "awselb" in cookies or "x-amzn-waf" in " ".join(headers):
        add("AWS WAF/ELB")
    if "big-ip" in server or "bigip" in cookies or "ts01" in cookies or "f5" in server:
        add("F5 BIG-IP")
    if "mod_security" in server or "mod_security" in body or "modsecurity" in body:
        add("ModSecurity")
    if "fortiweb" in server or "fortigate" in server or "fortiwafsid" in cookies:
        add("FortiWeb")
    if "barracuda" in server or "barra_counter_session" in cookies:
        add("Barracuda")
    if "denied by" in body and "waf" in body:
        add("Generic WAF")
    return hits


# Lightweight header/body signatures. The dedicated fingerprint module (M5) will
# extend this; for now it gives the domain page real tech chips from a single GET.
_SIGS = [
    ("Microsoft-IIS", "IIS"), ("Apache", "Apache"), ("nginx", "nginx"),
    ("cloudflare", "Cloudflare"), ("gws", "Google"), ("openresty", "OpenResty"),
    ("LiteSpeed", "LiteSpeed"),
]
_POWERED = [("ASP.NET", "ASP.NET"), ("PHP", "PHP"), ("Express", "Express"),
            ("Next.js", "Next.js")]
_BODY = [("__NEXT_DATA__", "Next.js"), ("data-reactroot", "React"), ("react", "React"),
         ("ng-version", "Angular"), ("wp-content", "WordPress"), ("Drupal", "Drupal"),
         ("__NUXT__", "Nuxt"), ("vue", "Vue")]


def _fingerprint(r):
    found = []
    server = r.headers.get("Server", "")
    powered = r.headers.get("X-Powered-By", "")
    body = r.text[:20000]
    for needle, label in _SIGS:
        if needle.lower() in server.lower() and label not in found:
            found.append(label)
    for needle, label in _POWERED:
        if needle.lower() in powered.lower() and label not in found:
            found.append(label)
    if r.headers.get("X-Generator"):
        found.append(r.headers["X-Generator"].split("/")[0].strip())
    for needle, label in _BODY:
        if needle.lower() in body.lower() and label not in found:
            found.append(label)
    return found


@register
class AliveModule(Module):
    name = "alive"
    version = "0.1"
    description = "Check host reachability and capture status, final URL, and server header."
    supports_batch = True       # probe all subdomains concurrently
    reports_progress = True

    def config_schema(self):
        return [
            {"name": "timeout", "type": "number", "default": 10, "label": "Timeout (s)"},
            {"name": "verify_tls", "type": "bool", "default": False, "label": "Verify TLS"},
            {"name": "threads", "type": "number", "default": 30, "label": "Threads"},
        ]

    def run(self, target, config, ctx):
        res = probe(target, timeout=float(config.get("timeout", 10)),
                    verify=bool(config.get("verify_tls", False)), proxies=ctx.proxies)
        _apply_enrich(target, enrich(target.host))
        ctx.finding(target, path="/", status_code=res["status_code"],
                    content_length=res["content_length"], redirect=res["redirect"],
                    **res["extra"])

    def run_all(self, targets, config, ctx):
        """Multi-threaded liveness + ASN enrichment across all subdomains. Network work
        happens in worker threads (no ORM); results are applied on the main thread."""
        timeout = float(config.get("timeout", 10))
        verify = bool(config.get("verify_tls", False))
        proxies = ctx.proxies
        threads = int(config.get("threads", 30) or 30)
        jobs = [(t.id, t.base_url, t.host) for t in targets]
        by_id = {t.id: t for t in targets}
        total = len(jobs)
        ctx.set_progress(0, total)

        def work(url, host):
            return _do_probe(url, timeout, verify, proxies), enrich(host)

        results = {}
        done = 0
        with ThreadPoolExecutor(max_workers=min(threads, max(1, total))) as ex:
            futs = {ex.submit(work, url, host): tid for tid, url, host in jobs}
            for fut in as_completed(futs):
                results[futs[fut]] = fut.result()
                done += 1
                if done % 5 == 0:
                    ctx.set_progress(done, total)

        for tid, (res, info) in results.items():
            t = by_id[tid]
            _apply(t, res)
            _apply_enrich(t, info)
            ctx.finding(t, path="/", status_code=res["status_code"],
                        content_length=res["content_length"], redirect=res["redirect"],
                        **res["extra"])
        ctx.set_progress(total, total)


def _title(html):
    lo = html.lower()
    i = lo.find("<title")
    if i == -1:
        return None
    start = html.find(">", i) + 1
    end = lo.find("</title>", start)
    if start <= 0 or end == -1:
        return None
    return html[start:end].strip()[:200]
