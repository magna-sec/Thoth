"""ROADrecon / Entra ID Conditional Access parser plugin."""
from ..capparse import looks_like_cap, parse_cap
from .base import ParserPlugin, register_parser


@register_parser
class RoadreconCapPlugin(ParserPlugin):
    name = "roadrecon-cap"
    title = "Conditional Access (ROADrecon)"
    description = ("Entra ID Conditional Access policies (a ROADrecon dump or a Graph "
                   "export): each policy shown clearly, plus the classic coverage gaps — "
                   "legacy auth not blocked, MFA-for-all missing, admins unprotected, "
                   "exclusion backdoors, browser-only MFA, trusted-location bypass.")
    glyph = "🛂"
    placeholder = 'Paste Conditional Access policy JSON (e.g. {"value":[{"displayName":…}]})'
    partial = "plugins/roadrecon.html"
    collect = ("roadrecon auth -u user@tenant -p PASS && roadrecon gather   # ROADtools\n"
               "# or via Graph:  Get-MgIdentityConditionalAccessPolicy | ConvertTo-Json -Depth 8")

    def detect(self, text):
        return looks_like_cap(text)

    def parse(self, text):
        return parse_cap(text)

    def summary(self, d):
        s = d.get("summary", {})
        bits = [f"{s.get('total', 0)} policy(ies)", f"{s.get('enabled', 0)} enabled"]
        gaps = [f for f in d.get("findings", []) if f["severity"] in ("critical", "high")]
        if gaps:
            bits.append(f"{len(gaps)} high-risk gap(s)")
        return " · ".join(bits)
