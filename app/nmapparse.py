"""Parse nmap output — XML (``-oX``), greppable (``-oG``), or the normal report.

XML is the canonical machine format and is parsed in full (hosts, hostnames, ports,
services, versions, OS guess). The greppable and normal formats are handled as a fallback
so a quick copy-paste still works.
"""
import re
from xml.etree import ElementTree as ET

INTERESTING = {
    "ftp", "ssh", "telnet", "smtp", "http", "https", "http-proxy", "rpcbind", "netbios-ssn",
    "microsoft-ds", "smb", "ldap", "ldaps", "kerberos-sec", "ms-sql-s", "mysql",
    "postgresql", "oracle", "rdp", "ms-wbt-server", "vnc", "redis", "mongodb", "winrm",
    "docker", "kubernetes", "elasticsearch", "memcached", "snmp",
}


def looks_like_nmap(text):
    t = text or ""
    return ("<nmaprun" in t or "Nmap scan report for" in t
            or bool(re.search(r"^Host:\s+\S+.*Ports:", t, re.M)))


def _svc(port_el):
    s = port_el.find("service")
    if s is None:
        return {"name": "", "product": "", "version": "", "extra": ""}
    return {
        "name": s.get("name", ""),
        "product": s.get("product", ""),
        "version": s.get("version", ""),
        "extra": s.get("extrainfo", ""),
    }


def _parse_xml(text):
    root = ET.fromstring(text)
    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") == "down":
            continue
        addrs = [a.get("addr") for a in h.findall("address")
                 if a.get("addrtype") in ("ipv4", "ipv6")]
        macs = [a.get("addr") for a in h.findall("address") if a.get("addrtype") == "mac"]
        names = [n.get("name") for n in h.findall("hostnames/hostname") if n.get("name")]
        ports = []
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") == "closed":
                continue
            ports.append({
                "port": int(p.get("portid")),
                "proto": p.get("protocol", "tcp"),
                "state": st.get("state", ""),
                **_svc(p),
            })
        ports.sort(key=lambda x: (x["proto"], x["port"]))
        os_match = h.find("os/osmatch")
        hosts.append({
            "address": addrs[0] if addrs else (macs[0] if macs else "?"),
            "addresses": addrs,
            "mac": macs[0] if macs else "",
            "hostnames": names,
            "os": os_match.get("name") if os_match is not None else "",
            "ports": ports,
        })
    return hosts


def _parse_greppable(text):
    """`nmap -oG` lines: 'Host: 10.0.0.1 (name)  Ports: 22/open/tcp//ssh///, …'."""
    hosts = []
    for line in text.splitlines():
        m = re.match(r"Host:\s+(\S+)\s+\(([^)]*)\).*?Ports:\s*(.+)", line)
        if not m:
            continue
        addr, name, ports_str = m.groups()
        ports = []
        for spec in ports_str.split(","):
            f = spec.strip().split("/")
            if len(f) >= 5 and f[1] == "open":
                ports.append({"port": int(f[0]), "proto": f[2], "state": "open",
                              "name": f[4], "product": "", "version": "", "extra": ""})
        hosts.append({"address": addr, "addresses": [addr], "mac": "",
                      "hostnames": [name] if name else [], "os": "", "ports": ports})
    return hosts


def _parse_normal(text):
    """The human 'Nmap scan report for …' format."""
    hosts, current = [], None
    for line in text.splitlines():
        m = re.match(r"Nmap scan report for (\S+)\s*(?:\(([\d.]+)\))?", line)
        if m:
            name, ip = m.groups()
            addr = ip or name
            current = {"address": addr, "addresses": [addr], "mac": "",
                       "hostnames": [name] if ip else [], "os": "", "ports": []}
            hosts.append(current)
            continue
        pm = re.match(r"(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)", line)
        if pm and current is not None:
            port, proto, state, name, rest = pm.groups()
            if state != "closed":
                current["ports"].append({"port": int(port), "proto": proto, "state": state,
                                         "name": name, "product": rest.strip(),
                                         "version": "", "extra": ""})
    return [h for h in hosts if h["ports"] or h["hostnames"]]


def parse_nmap(text):
    """Parse nmap output in any supported format. Returns ``{"hosts", "summary"}``.
    Raises ValueError if it isn't nmap output."""
    text = (text or "").strip()
    if not text:
        raise ValueError("Nothing to parse — paste nmap output first.")

    hosts = None
    if "<nmaprun" in text:
        try:
            hosts = _parse_xml(text)
        except ET.ParseError as e:
            raise ValueError(f"Malformed nmap XML: {e}") from e
    elif re.search(r"^Host:\s+\S+.*Ports:", text, re.M):
        hosts = _parse_greppable(text)
    elif "Nmap scan report for" in text:
        hosts = _parse_normal(text)

    if not hosts:
        raise ValueError("No nmap hosts found. Paste XML (-oX), greppable (-oG), or the "
                         "normal scan report.")

    all_ports = [p for h in hosts for p in h["ports"]]
    services = {}
    for p in all_ports:
        if p["name"]:
            services[p["name"]] = services.get(p["name"], 0) + 1
    interesting = sorted({p["name"] for p in all_ports if p["name"] in INTERESTING})
    summary = {
        "hosts": len(hosts),
        "open_ports": len(all_ports),
        "services": sorted(services.items(), key=lambda kv: (-kv[1], kv[0])),
        "interesting": interesting,
    }
    hosts.sort(key=lambda h: h["address"])
    return {"hosts": hosts, "summary": summary}
