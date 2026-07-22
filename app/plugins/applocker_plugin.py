"""AppLocker policy parser plugin."""
from ..applockerparse import looks_like_applocker, parse_applocker
from .base import ParserPlugin, register_parser

# PowerShell to pull the effective policy as XML (what this plugin parses).
_COLLECT = r"""# Effective AppLocker policy as XML — paste/upload the output:
Get-AppLockerPolicy -Effective -Xml | Out-File -Encoding utf8 applocker.xml

# Or dump it straight to the console:
(Get-AppLockerPolicy -Effective -Xml)"""


@register_parser
class ApplockerPlugin(ParserPlugin):
    name = "applocker"
    title = "AppLocker policy"
    description = ("Windows AppLocker policy (Get-AppLockerPolicy -Effective -Xml): every "
                   "rule collection and rule, plus the classic bypass gaps — collections not "
                   "enforced, %WINDIR%/%PROGRAMFILES% writable-subdir allows, explicit "
                   "writable-path allows, and wildcard publisher rules.")
    glyph = "🔒"
    placeholder = "Paste the AppLocker policy XML (Get-AppLockerPolicy -Effective -Xml)"
    partial = "plugins/applocker.html"
    collect = _COLLECT

    def detect(self, text):
        return looks_like_applocker(text)

    def parse(self, text):
        return parse_applocker(text)

    def summary(self, d):
        s = d.get("summary", {})
        gaps = [f for f in d.get("findings", []) if f["severity"] in ("critical", "high")]
        bits = [f"{s.get('collections', 0)} collection(s)",
                f"{s.get('enforced', 0)} enforced"]
        if gaps:
            bits.append(f"{len(gaps)} high-risk gap(s)")
        return " · ".join(bits)
