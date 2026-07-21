"""Nessus (.nessus) parser plugin."""
from ..nessusparse import looks_like_nessus, parse_nessus
from .base import ParserPlugin, register_parser


@register_parser
class NessusPlugin(ParserPlugin):
    name = "nessus"
    title = "Nessus scan"
    description = ("Nessus (.nessus) export: scanned hosts and their vulnerabilities ranked "
                   "by severity, with CVSS, CVEs, and remediation.")
    glyph = "🛡️"
    placeholder = "Paste a .nessus XML export"
    partial = "plugins/nessus.html"

    def detect(self, text):
        return looks_like_nessus(text)

    def parse(self, text):
        return parse_nessus(text)

    def summary(self, d):
        sev = d.get("summary", {}).get("sev", {})
        bits = [f"{d.get('summary', {}).get('hosts', 0)} host(s)"]
        for k in ("critical", "high", "medium"):
            if sev.get(k):
                bits.append(f"{sev[k]} {k}")
        return " · ".join(bits)
