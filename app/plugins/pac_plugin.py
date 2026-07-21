"""PAC-file parser plugin."""
from ..pacparse import looks_like_pac, parse_pac
from .base import ParserPlugin, register_parser


@register_parser
class PacPlugin(ParserPlugin):
    name = "pac"
    title = "PAC file"
    description = ("Proxy auto-config (FindProxyForURL): the proxy servers, and the "
                   "internal estate routed DIRECT (bypassing the proxy) — plus every "
                   "host/domain/subnet referenced. Parsed statically, never executed.")
    glyph = "🌐"
    placeholder = "Paste the contents of a proxy.pac (function FindProxyForURL(url, host) …)"
    partial = "plugins/pac.html"

    def detect(self, text):
        return looks_like_pac(text)

    def parse(self, text):
        return parse_pac(text)

    def summary(self, d):
        return (f"{len(d.get('proxies', []))} proxy(ies) · "
                f"{len(d.get('direct_patterns', []))} DIRECT · "
                f"{len(d.get('domains', []))} pattern(s)")
