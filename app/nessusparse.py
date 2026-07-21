"""Parse a Nessus ``.nessus`` export (XML) into a tidy, severity-ranked view.

A ``.nessus`` file is ``NessusClientData_v2`` XML: one ``<ReportHost>`` per scanned host,
each with ``<HostProperties>`` (ip / fqdn / OS) and a ``<ReportItem>`` per finding
(pluginName, severity 0–4, CVSS, CVEs, synopsis, solution). We surface the vulnerabilities
that matter — critical/high first — with per-host detail. Pure XML parsing, no requests.
"""
from xml.etree import ElementTree as ET

# Nessus severity is an integer 0–4.
SEV_LABEL = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
SEV_KEYS = ("critical", "high", "medium", "low", "info")


def looks_like_nessus(text):
    t = text or ""
    return "NessusClientData" in t or ("<ReportHost" in t and "<ReportItem" in t)


def _text(el, *tags):
    for tag in tags:
        c = el.find(tag)
        if c is not None and c.text and c.text.strip():
            return c.text.strip()
    return ""


def _cvss(ri):
    return _text(ri, "cvss3_base_score", "cvss_base_score")


def parse_nessus(text):
    """Parse a .nessus export. Returns ``{"hosts", "summary", "notable"}``.
    Raises ValueError if it isn't a Nessus file."""
    text = (text or "").strip()
    if not text:
        raise ValueError("Nothing to parse — paste a .nessus export first.")
    if "NessusClientData" not in text and "<ReportHost" not in text:
        raise ValueError("This doesn't look like a Nessus (.nessus) export.")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise ValueError(f"Malformed Nessus XML: {e}") from e

    hosts = []
    totals = {k: 0 for k in SEV_KEYS}
    grand_total = 0
    for rh in root.iter("ReportHost"):
        props = {}
        hp = rh.find("HostProperties")
        if hp is not None:
            for tag in hp.findall("tag"):
                if tag.get("name"):
                    props[tag.get("name")] = (tag.text or "").strip()
        name = rh.get("name") or props.get("host-fqdn") or props.get("host-ip") or "?"

        findings, counts = [], {k: 0 for k in SEV_KEYS}
        for ri in rh.findall("ReportItem"):
            sev = int(ri.get("severity", "0") or 0)
            label = SEV_LABEL.get(sev, "info")
            findings.append({
                "severity": label, "sev": sev,
                "plugin_id": ri.get("pluginID", ""),
                "name": ri.get("pluginName", ""),
                "family": ri.get("pluginFamily", ""),
                "port": ri.get("port", "0"),
                "protocol": ri.get("protocol", "tcp"),
                "svc": ri.get("svc_name", ""),
                "cvss": _cvss(ri),
                "cves": [c.text.strip() for c in ri.findall("cve") if c.text],
                "synopsis": _text(ri, "synopsis")[:800],
                "solution": _text(ri, "solution")[:800],
            })
            counts[label] += 1
            totals[label] += 1
            grand_total += 1

        findings.sort(key=lambda f: (-f["sev"], f["name"]))
        hosts.append({
            "name": name, "ip": props.get("host-ip", ""),
            "fqdn": props.get("host-fqdn", ""),
            "os": props.get("operating-system", ""),
            "sev_counts": counts, "findings": findings,
        })

    if not hosts:
        raise ValueError("No Nessus hosts found in that file.")

    hosts.sort(key=lambda h: (-max((f["sev"] for f in h["findings"]), default=0), h["name"]))

    def _cvss_num(v):
        try:
            return float(v)
        except (TypeError, ValueError):
            return 0.0

    notable = [{**f, "host": h["name"]} for h in hosts for f in h["findings"]
               if f["sev"] >= 3]
    notable.sort(key=lambda f: (-f["sev"], -_cvss_num(f["cvss"]), f["name"]))

    return {"hosts": hosts, "notable": notable[:300],
            "summary": {"hosts": len(hosts), "total": grand_total, "sev": totals}}
