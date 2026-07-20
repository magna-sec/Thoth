"""Alive / reachability module + a reusable single-domain probe."""
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests

from ..enrich import enrich
from .base import Module, register

# Alt-HTTP ports worth a look on every host: admin panels, dev copies, and app servers
# hide here far more often than on 80/443.
DEFAULT_EXTRA_PORTS = (8080, 8443)


def _do_probe(url, timeout, verify, proxies, signatures=None):
    """Pure HTTP probe of a URL — no ORM/DB touch, so it is safe to call from worker
    threads. `signatures` is pre-loaded custom fingerprint data (see load_signatures()).
    Returns the normalized result dict."""
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
                "tech": _fingerprint(r, signatures),
                "waf": _detect_waf(r),
                "title": _title(r.text),
                "elapsed_ms": elapsed_ms,
                "alive": True,
            },
        }
    except requests.RequestException as e:
        return {"status_code": None, "content_length": None, "redirect": None,
                "extra": {"alive": False, "error": type(e).__name__}}


def parse_ports(raw):
    """Parse a '8080, 8443' style config value into a list of valid port numbers."""
    if raw is None:
        return list(DEFAULT_EXTRA_PORTS)
    ports = []
    for chunk in str(raw).replace(";", ",").split(","):
        chunk = chunk.strip()
        if not chunk.isdigit():
            continue
        port = int(chunk)
        if 0 < port < 65536 and port not in ports:
            ports.append(port)
    return ports


def _scheme_for_port(port):
    """8443/9443/443 speak TLS by convention; everything else we try as plain HTTP."""
    return "https" if str(port).endswith("443") else "http"


def _port_open(host, port, timeout):
    """Cheap TCP connect test, so a closed port costs one RTT instead of a full HTTP wait."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _probe_ports(host, ports, timeout, verify, proxies, skip=(), signatures=None):
    """Check alt-HTTP ports on a host. Returns one dict per port that answered.

    Pure network work (no ORM), so this is safe inside a worker thread.
    """
    found = []
    for port in ports:
        if port in skip:
            continue
        scheme = _scheme_for_port(port)
        # Through a proxy we cannot pre-check the socket ourselves — let the proxy try.
        if not proxies and not _port_open(host, port, min(timeout, 5)):
            continue
        res = _do_probe(f"{scheme}://{host}:{port}", timeout, verify, proxies, signatures)
        if res["status_code"] is None:
            continue
        found.append({
            "port": port,
            "scheme": scheme,
            "url": f"{scheme}://{host}:{port}",
            "status_code": res["status_code"],
            "title": res["extra"].get("title"),
            "server": res["extra"].get("server"),
            "tech": res["extra"].get("tech"),
        })
    return found


def _apply(target, result):
    """Write a probe result onto the target's cached last_* fields (main thread only)."""
    now = datetime.utcnow()
    target.last_status_code = result["status_code"]
    target.last_alive = result["extra"]["alive"]
    target.last_checked_at = now
    ports = result["extra"].get("open_ports")
    if ports is not None:  # None = ports weren't checked, so don't clear a previous result
        target.open_ports = ", ".join(str(p["port"]) for p in ports) or None
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


def probe(target, timeout=8, verify=False, proxies=None, extra_ports=DEFAULT_EXTRA_PORTS):
    """Probe a single target and update its cached fields (used by the quick-check).

    Also sweeps the alt-HTTP ports so "Check live" marks 8080/8443 exposure.
    """
    signatures = load_signatures()
    result = _do_probe(target.base_url, timeout, verify, proxies, signatures)
    if extra_ports:
        result["extra"]["open_ports"] = _probe_ports(
            target.host, extra_ports, timeout, verify, proxies,
            skip=(target.port,) if target.port else (), signatures=signatures)
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


# Built-in signatures as (field, needle, label). Operators extend this set at runtime from
# the Fingerprints page — see load_signatures() — and both go through the same matcher.
BUILTIN_SIGNATURES = [
    # Web servers / CDNs (Server header)
    ("server", "Microsoft-IIS", "IIS"), ("server", "Apache", "Apache"),
    ("server", "nginx", "nginx"), ("server", "cloudflare", "Cloudflare"),
    ("server", "gws", "Google"), ("server", "openresty", "OpenResty"),
    ("server", "LiteSpeed", "LiteSpeed"),
    # Application stacks (X-Powered-By)
    ("powered_by", "ASP.NET", "ASP.NET"), ("powered_by", "PHP", "PHP"),
    ("powered_by", "Express", "Express"), ("powered_by", "Next.js", "Next.js"),
    # Front-end frameworks / CMS (body)
    ("body", "__NEXT_DATA__", "Next.js"), ("body", "data-reactroot", "React"),
    ("body", "react", "React"), ("body", "ng-version", "Angular"),
    ("body", "wp-content", "WordPress"), ("body", "Drupal", "Drupal"),
    ("body", "__NUXT__", "Nuxt"), ("body", "vue", "Vue"),
    # Hosted platforms — the ones that hide behind a generic Server header
    ("cookie", "BrowserId", "Salesforce"), ("body", "sfdcPage", "Salesforce"),
    ("body", "force.com", "Salesforce"), ("header", "x-salesforce", "Salesforce"),
    ("body", "cdn.shopify.com", "Shopify"), ("header", "x-shopify", "Shopify"),
    ("body", "hs-scripts.com", "HubSpot"),
    ("body", "static.parastorage.com", "Wix"),
    ("body", "cdn.sanity.io", "Sanity"),
    ("header", "x-served-by: cache", "Fastly"),
    ("header", "x-vercel-id", "Vercel"),
    ("header", "x-nf-request-id", "Netlify"),
    ("header", "x-atlassian", "Atlassian"),
    ("body", "ServiceNow", "ServiceNow"),
    ("body", "SharePoint", "SharePoint"),
    ("header", "x-drupal-cache", "Drupal"),
]


def load_signatures():
    """Custom signatures from the DB as (field, needle, label) tuples.

    Must be called on the main thread — the result is plain data that worker threads can
    then match against without touching the ORM.
    """
    from ..models import Signature
    try:
        return [(s.field, s.needle, s.label) for s in Signature.query.all()]
    except Exception:  # noqa: BLE001 - a missing table must never break a scan
        return []


def _haystacks(r):
    """The searchable surfaces of a response, lowercased once for all signatures."""
    return {
        "server": (r.headers.get("Server") or "").lower(),
        "powered_by": (r.headers.get("X-Powered-By") or "").lower(),
        "header": "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower(),
        "cookie": " ".join(r.cookies.keys()).lower(),
        "body": r.text[:20000].lower(),
    }


def _fingerprint(r, signatures=None):
    """Label the tech behind a response. `signatures` adds operator-defined rules on top
    of the built-ins (pass the result of load_signatures())."""
    found = []
    hay = _haystacks(r)
    for field, needle, label in list(BUILTIN_SIGNATURES) + list(signatures or []):
        surface = hay.get(field)
        if surface and needle.lower() in surface and label not in found:
            found.append(label)
    generator = r.headers.get("X-Generator")
    if generator:
        label = generator.split("/")[0].strip()
        if label and label not in found:
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
            {"name": "extra_ports", "type": "text", "default": "8080,8443",
             "label": "Also check ports", "help": "Blank to check only the primary port"},
        ]

    def run(self, target, config, ctx):
        res = probe(target, timeout=float(config.get("timeout", 10)),
                    verify=bool(config.get("verify_tls", False)), proxies=ctx.proxies,
                    extra_ports=parse_ports(config.get("extra_ports")))
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
        ports = parse_ports(config.get("extra_ports"))
        # Loaded once, on this thread: worker threads must not touch the ORM.
        signatures = load_signatures()
        jobs = [(t.id, t.base_url, t.host, t.port) for t in targets]
        by_id = {t.id: t for t in targets}
        total = len(jobs)
        ctx.set_progress(0, total)
        if ports:
            ctx.log(f"Also checking port(s) {', '.join(str(p) for p in ports)} on each host")
        if signatures:
            ctx.log(f"Using {len(signatures)} custom fingerprint signature(s)")

        def work(url, host, own_port):
            res = _do_probe(url, timeout, verify, proxies, signatures)
            if ports:
                res["extra"]["open_ports"] = _probe_ports(
                    host, ports, timeout, verify, proxies,
                    skip=(own_port,) if own_port else (), signatures=signatures)
            return res, enrich(host)

        results = {}
        done = 0
        with ThreadPoolExecutor(max_workers=min(threads, max(1, total))) as ex:
            futs = {ex.submit(work, url, host, own_port): tid
                    for tid, url, host, own_port in jobs}
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
            for p in (res["extra"].get("open_ports") or []):
                ctx.log(f"{p['status_code']} - open port {p['port']} on {t.host} "
                        f"({p['url']}{' — ' + p['title'] if p['title'] else ''})")
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
