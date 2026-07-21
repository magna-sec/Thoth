"""dsregcmd /status parser plugin."""
from ..dsregcmd import looks_like_dsregcmd, parse_dsregcmd
from .base import ParserPlugin, register_parser


@register_parser
class DsregcmdPlugin(ParserPlugin):
    name = "dsregcmd"
    title = "dsregcmd status"
    description = ("Windows device / Entra ID (Azure AD) state from dsregcmd /status: "
                   "join type, tenant, MDM enrolment URL, and SSO/PRT status.")
    glyph = "🪟"
    placeholder = "Paste dsregcmd /status output"
    partial = "plugins/dsregcmd.html"

    def detect(self, text):
        return looks_like_dsregcmd(text)

    def parse(self, text):
        data = parse_dsregcmd(text)
        if not data["sections"]:
            raise ValueError("No dsregcmd sections found in that text.")
        return data

    def summary(self, d):
        by_key = {s["key"]: s for s in d.get("summary", [])}
        bits = []
        tenant = by_key.get("TenantName", {}).get("value")
        if tenant:
            bits.append(tenant)
        joined = [k.replace("Joined", "") for k in
                  ("AzureAdJoined", "DomainJoined", "EnterpriseJoined", "WorkplaceJoined")
                  if by_key.get(k, {}).get("bool")]
        if joined:
            bits.append("joined: " + ", ".join(joined))
        return " · ".join(bits) or f"{len(d.get('sections', []))} section(s)"
