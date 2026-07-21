"""Statically extract intel from a PAC (Proxy Auto-Config) file.

A PAC file is JavaScript (``FindProxyForURL(url, host)``), but it's a goldmine of recon on
its own: the proxy servers an org routes through, and — more valuably — the internal
hostnames, domains and subnets it sends **DIRECT** (i.e. the estate that bypasses the
proxy). We never execute it; we read the structure statically.

The condition→action pairing is a best-effort approximation of typical PAC layout (a run of
conditions followed by a ``return``), which is right for the overwhelming majority of files
but isn't a JS interpreter.
"""
import re

_PROXY_TOKEN = re.compile(r'(PROXY|HTTPS|SOCKS5|SOCKS4|SOCKS)\s+([^";]+)', re.I)
_HOST_MATCHERS = (
    re.compile(r'dnsDomainIs\s*\([^,]+,\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'shExpMatch\s*\([^,]+,\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'localHostOrDomainIs\s*\([^,]+,\s*["\']([^"\']+)["\']', re.I),
)
_ISINNET = re.compile(
    r'isInNet\s*\([^,]+,\s*["\']([0-9.]+)["\']\s*,\s*["\']([0-9.]+)["\']', re.I)
_HELPERS = re.compile(
    r'\b(dnsDomainIs|shExpMatch|isInNet|localHostOrDomainIs|isPlainHostName|'
    r'dnsResolve|myIpAddress|isResolvable|dnsDomainLevels|weekdayRange|'
    r'timeRange|dateRange)\b')


def _mask_to_prefix(mask):
    try:
        return sum(bin(int(o)).count("1") for o in mask.split("."))
    except ValueError:
        return None


def _proxies_in(text):
    out = []
    for kind, body in _PROXY_TOKEN.findall(text):
        for endpoint in body.split(";"):
            endpoint = endpoint.strip().strip('"\'')
            if endpoint:
                out.append(f"{kind.upper()} {endpoint}")
    return out


def _patterns_in(text):
    pats = []
    for rx in _HOST_MATCHERS:
        pats.extend(rx.findall(text))
    for ip, mask in _ISINNET.findall(text):
        prefix = _mask_to_prefix(mask)
        pats.append(f"{ip}/{prefix}" if prefix is not None else f"{ip} mask {mask}")
    return pats


def _uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def parse_pac(text):
    """Parse a PAC file. Returns a dict of extracted intel; raises ValueError if the text
    isn't a PAC file at all."""
    text = text or ""
    if "FindProxyForURL" not in text and "return" not in text:
        raise ValueError("This doesn't look like a PAC file "
                         "(no FindProxyForURL / return statements).")

    proxies = _uniq(_proxies_in(text))
    all_patterns = _uniq(_patterns_in(text))
    subnets = [p for p in all_patterns if re.match(r"^[0-9]", p)]
    domains = [p for p in all_patterns if p not in subnets]

    # Best-effort condition -> action pairing: collect matcher patterns until a `return`.
    direct, proxied, buffer = [], [], []
    direct_returns = proxy_returns = 0
    for raw in text.replace("\r\n", "\n").split("\n"):
        for rx in _HOST_MATCHERS:
            buffer.extend(rx.findall(raw))
        for ip, mask in _ISINNET.findall(raw):
            prefix = _mask_to_prefix(mask)
            buffer.append(f"{ip}/{prefix}" if prefix is not None else f"{ip} mask {mask}")
        if re.search(r"\breturn\b", raw):
            if re.search(r'DIRECT', raw, re.I):
                direct_returns += 1
                direct.extend(buffer)
            elif _PROXY_TOKEN.search(raw):
                proxy_returns += 1
                proxied.extend(buffer)
            buffer = []

    return {
        "proxies": proxies,
        "direct_patterns": _uniq(direct),      # the internal estate that bypasses the proxy
        "proxied_patterns": _uniq(proxied),
        "domains": domains,                    # every host/domain pattern referenced
        "subnets": subnets,
        "helpers": _uniq(_HELPERS.findall(text)),
        "direct_returns": direct_returns,
        "proxy_returns": proxy_returns,
        "lines": len([ln for ln in text.split("\n") if ln.strip()]),
    }


def looks_like_pac(text):
    return "FindProxyForURL" in (text or "")
