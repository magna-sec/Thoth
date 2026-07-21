"""Statically extract intel — and flag misconfigurations — from a PAC file.

A PAC file is JavaScript (``FindProxyForURL(url, host)``), but it's a goldmine of recon on
its own: the proxy servers an org routes through, and the internal hostnames, domains and
subnets it sends **DIRECT** (the estate that bypasses the proxy). We never execute it; we
read the structure statically, reconstruct the condition→action rules, and check for the
misconfigurations PAC files commonly ship with.

The rule reconstruction is a best-effort read of typical PAC layout (a run of conditions
then a ``return``), which is right for the overwhelming majority of files but isn't a JS
interpreter.
"""
import ipaddress
import re

_PROXY_TOKEN = re.compile(r'(PROXY|HTTPS|SOCKS5|SOCKS4|SOCKS)\s+([^";]+)', re.I)

# (helper, regex capturing the host pattern) — the conditions that match on the host/url.
_MATCHERS = [
    ("dnsDomainIs", re.compile(r'dnsDomainIs\s*\([^,]+,\s*["\']([^"\']+)["\']', re.I)),
    ("shExpMatch", re.compile(r'shExpMatch\s*\([^,]+,\s*["\']([^"\']+)["\']', re.I)),
    ("localHostOrDomainIs",
     re.compile(r'localHostOrDomainIs\s*\([^,]+,\s*["\']([^"\']+)["\']', re.I)),
]
_ISINNET = re.compile(
    r'isInNet\s*\(\s*([^,]+?)\s*,\s*["\']([0-9.]+)["\']\s*,\s*["\']([0-9.]+)["\']', re.I)
_HELPERS = re.compile(
    r'\b(dnsDomainIs|shExpMatch|isInNet|localHostOrDomainIs|isPlainHostName|'
    r'dnsResolve|myIpAddress|isResolvable|dnsDomainLevels|weekdayRange|'
    r'timeRange|dateRange)\b')


def _mask_to_prefix(mask):
    try:
        return sum(bin(int(o)).count("1") for o in mask.split("."))
    except ValueError:
        return None


def _proxy_endpoints(body):
    """['PROXY 10.0.0.1:8080', …] from a return body (may have ';' fallbacks)."""
    out = []
    for kind, chunk in _PROXY_TOKEN.findall(body):
        for endpoint in chunk.split(";"):
            endpoint = endpoint.strip().strip("\"'")
            if endpoint:
                out.append(f"{kind.upper()} {endpoint}")
    return out


def _uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _conditions_in(line):
    """Readable conditions on this line, e.g. ('dnsDomainIs', 'intranet.corp')."""
    conds = []
    for helper, rx in _MATCHERS:
        for pat in rx.findall(line):
            conds.append((helper, pat))
    for arg, ip, mask in _ISINNET.findall(line):
        prefix = _mask_to_prefix(mask)
        conds.append(("isInNet", f"{ip}/{prefix}" if prefix is not None else f"{ip} {mask}"))
    if re.search(r'isPlainHostName\s*\(', line, re.I):
        conds.append(("isPlainHostName", ""))
    return conds


def _scan_rules(text):
    """Reconstruct ordered condition→action rules by pairing a run of conditions with the
    ``return`` that follows them."""
    rules, buffer = [], []
    for line in text.replace("\r\n", "\n").split("\n"):
        buffer.extend(_conditions_in(line))
        if re.search(r"\breturn\b", line):
            m = re.search(r'return\s+(.+?);?\s*$', line)
            body = m.group(1).strip().strip("\"'") if m else ""
            if re.search(r'\bDIRECT\b', line, re.I) and not _PROXY_TOKEN.search(line):
                action, proxies = "DIRECT", []
            elif _PROXY_TOKEN.search(line):
                proxies = _uniq(_proxy_endpoints(line))
                action = "PROXY"
            else:
                action, proxies = (body or "?"), []
            rules.append({"conditions": buffer, "action": action, "proxies": proxies})
            buffer = []
    return rules


def _is_public_ip(host):
    try:
        return not ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def _findings(text, rules, proxies):
    """Common PAC misconfigurations, most severe first."""
    out = []

    def add(sev, title, detail):
        out.append({"severity": sev, "title": title, "detail": detail})

    lower = text.lower()

    # 1. Credentials embedded in a proxy endpoint.
    for p in proxies:
        if "@" in p.split(None, 1)[-1]:
            add("high", "Credentials in proxy string",
                f"{p} embeds credentials in the PAC — readable by anyone who can fetch it.")
            break

    # 2. Proxy hosted on a public IP.
    for p in proxies:
        host = p.split(None, 1)[-1].split(":")[0].split("@")[-1]
        if _is_public_ip(host):
            add("medium", "Proxy on a public IP",
                f"{p} points at a public address — confirm it's an intended egress, not a "
                f"data path off-net.")

    # 3. DNS-leak helpers: resolving the requested host on every request leaks internal
    #    names to DNS and slows browsing. isInNet(myIpAddress(),…) is fine; on the host it
    #    is the classic anti-pattern.
    if re.search(r'isinnet\s*\(\s*host', lower) or re.search(r'dnsresolve\s*\(\s*host', lower) \
            or re.search(r'isresolvable\s*\(\s*host', lower):
        add("medium", "Resolves every hostname (DNS leak)",
            "isInNet/dnsResolve/isResolvable on the requested host forces a DNS lookup for "
            "every request — leaking internal hostnames to DNS servers and slowing browsing.")

    # 4. Overly broad wildcard rule.
    for r in rules:
        for helper, pat in r["conditions"]:
            if pat in ("*", "*.*", "http://*", "https://*"):
                add("medium", "Wildcard rule matches everything",
                    f"A rule matches '{pat}' → {r['action']}, overriding more specific "
                    f"rules below it.")
                break

    # 5. Default action (the last, unconditional return).
    default = next((r for r in reversed(rules) if not r["conditions"]), None)
    if default:
        if default["action"] == "DIRECT":
            add("low", "Default is DIRECT",
                "Traffic not matched by any rule bypasses the proxy entirely — no egress "
                "control or logging for anything the rules miss.")
    else:
        add("low", "No default return",
            "No unconditional fallback return — behaviour for unmatched hosts is undefined "
            "and browser-dependent.")

    # 6. Nothing goes DIRECT — even internal/loopback is proxied.
    if proxies and not any(r["action"] == "DIRECT" for r in rules):
        add("info", "No DIRECT rules",
            "Every request (including internal and loopback) is sent through the proxy.")

    # 7. Loopback / plain hostnames not excluded.
    if proxies and "isplainhostname" not in lower and "127.0.0.1" not in text \
            and "localhost" not in lower:
        add("info", "Loopback not excluded",
            "No isPlainHostName / localhost rule — intranet short-names and loopback may be "
            "sent through the proxy.")

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    out.sort(key=lambda f: order.get(f["severity"], 9))
    return out


def parse_pac(text):
    """Parse a PAC file. Returns extracted intel + reconstructed rules + misconfig findings.
    Raises ValueError if the text isn't a PAC file."""
    text = text or ""
    if "FindProxyForURL" not in text and "return" not in text:
        raise ValueError("This doesn't look like a PAC file "
                         "(no FindProxyForURL / return statements).")

    rules = _scan_rules(text)
    proxies = _uniq(p for r in rules for p in r["proxies"])
    # Also catch proxies declared in variables/arrays outside a return.
    proxies = _uniq(proxies + _proxy_endpoints(text))

    direct, proxied, all_pats, subnets = [], [], [], []
    for r in rules:
        for helper, pat in r["conditions"]:
            label = pat if helper != "isPlainHostName" else "(plain hostname)"
            all_pats.append(label)
            if helper == "isInNet":
                subnets.append(pat)
            (direct if r["action"] == "DIRECT" else proxied).append(label)

    default = next((r for r in reversed(rules) if not r["conditions"]), None)
    return {
        "proxies": proxies,
        "rules": rules,
        "default_action": (default["action"] if default else None),
        "findings": _findings(text, rules, proxies),
        "direct_patterns": _uniq(direct),
        "proxied_patterns": _uniq(proxied),
        "domains": _uniq(p for p in all_pats if not re.match(r"^[0-9]", p)),
        "subnets": _uniq(subnets),
        "helpers": _uniq(_HELPERS.findall(text)),
        "direct_returns": sum(1 for r in rules if r["action"] == "DIRECT"),
        "proxy_returns": sum(1 for r in rules if r["action"] == "PROXY"),
        "lines": len([ln for ln in text.split("\n") if ln.strip()]),
    }


def looks_like_pac(text):
    return "FindProxyForURL" in (text or "")
