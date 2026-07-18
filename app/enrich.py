"""IP resolution + IP-to-ASN enrichment via Team Cymru's free DNS service.

Team Cymru answers TXT queries with no API key:
  <reversed-ipv4>.origin.asn.cymru.com  -> "ASN | prefix | CC | registry | allocated"
  AS<asn>.asn.cymru.com                 -> "ASN | CC | registry | allocated | AS-NAME"

All lookups are best-effort, bounded, and cached — never raise into a request/task.
"""
import functools
import socket
import threading

try:
    import dns.resolver
    _HAVE_DNS = True
except Exception:  # pragma: no cover - dnspython optional
    _HAVE_DNS = False


def resolve_ip(host, timeout=3.0):
    """First resolved address for a host (IPv4 preferred), bounded by a timeout."""
    out = []

    def work():
        try:
            infos = socket.getaddrinfo(host, None)
            ipv4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
            out.append((ipv4 or [i[4][0] for i in infos])[0])
        except OSError:
            pass

    th = threading.Thread(target=work, daemon=True)
    th.start()
    th.join(timeout)
    return out[0] if out else None


def _txt(name, timeout=3.0):
    if not _HAVE_DNS:
        return None
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout + 1
        ans = resolver.resolve(name, "TXT")
        for rdata in ans:
            return "".join(s.decode() if isinstance(s, bytes) else s
                           for s in rdata.strings)
    except Exception:
        return None
    return None


def _parse_origin(txt):
    """'15169 | 8.8.8.0/24 | US | arin | 1992' -> {asn, prefix, country}."""
    parts = [p.strip() for p in (txt or "").split("|")]
    if len(parts) < 3 or not parts[0]:
        return {}
    return {"asn": parts[0].split()[0], "prefix": parts[1], "country": parts[2]}


def _parse_asname(txt):
    """'15169 | US | arin | 1992 | GOOGLE, US' -> 'GOOGLE, US'."""
    parts = [p.strip() for p in (txt or "").split("|")]
    return parts[-1] if parts and parts[-1] else None


def _rev4(ip):
    return ".".join(reversed(ip.split(".")))


@functools.lru_cache(maxsize=8192)
def asn_for_ip(ip):
    if not ip or ":" in ip or ip.count(".") != 3:
        return {}
    return _parse_origin(_txt(f"{_rev4(ip)}.origin.asn.cymru.com"))


@functools.lru_cache(maxsize=8192)
def asn_name(asn):
    if not asn:
        return None
    return _parse_asname(_txt(f"AS{asn}.asn.cymru.com"))


def enrich(host):
    """Resolve host -> IP -> ASN/owner/country. Returns a dict; fields may be None."""
    info = {"ip": None, "asn": None, "asn_name": None, "country": None}
    ip = resolve_ip(host)
    info["ip"] = ip
    origin = asn_for_ip(ip) if ip else {}
    if origin.get("asn"):
        info["asn"] = origin["asn"]
        info["country"] = origin.get("country")
        info["asn_name"] = asn_name(origin["asn"])
    return info
