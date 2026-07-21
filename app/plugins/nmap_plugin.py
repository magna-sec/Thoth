"""nmap output parser plugin."""
from ..nmapparse import looks_like_nmap, parse_nmap
from .base import ParserPlugin, register_parser


@register_parser
class NmapPlugin(ParserPlugin):
    name = "nmap"
    title = "nmap scan"
    description = ("nmap output (XML -oX, greppable -oG, or the normal report): live hosts, "
                   "open ports, services and versions, with notable services highlighted.")
    glyph = "📡"
    placeholder = "Paste nmap XML (-oX), greppable (-oG), or the normal scan report"
    partial = "plugins/nmap.html"

    def detect(self, text):
        return looks_like_nmap(text)

    def parse(self, text):
        return parse_nmap(text)

    def summary(self, d):
        s = d.get("summary", {})
        bits = [f"{s.get('hosts', 0)} host(s)", f"{s.get('open_ports', 0)} open port(s)"]
        if s.get("interesting"):
            bits.append(", ".join(s["interesting"][:6]))
        return " · ".join(bits)
