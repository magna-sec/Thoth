"""web.config parser plugin — extract connection strings, secrets, keys and URLs from one
or more ASP.NET / IIS configuration files."""
from ..webconfigparse import looks_like_webconfig, parse_webconfig
from .base import ParserPlugin, register_parser

# PowerShell to gather every web.config under a site, with a header per file so the parser
# can name each one. Concatenated output pastes/uploads straight into the plugin.
_COLLECT = r"""# Dump every web.config under the IIS webroot (run on the target host):
Get-ChildItem C:\inetpub\wwwroot -Recurse -Filter web.config -ErrorAction SilentlyContinue |
  ForEach-Object { "===== $($_.FullName) ====="; Get-Content -Raw $_.FullName }

# Single app:  Get-Content -Raw C:\inetpub\wwwroot\<app>\web.config"""


@register_parser
class WebConfigPlugin(ParserPlugin):
    name = "webconfig"
    title = "web.config"
    description = ("ASP.NET / IIS web.config files (upload several at once): connection "
                   "strings and their SQL passwords, appSettings secrets/API keys, a static "
                   "machineKey (ViewState/forms-auth forgery), Forms-auth and impersonation "
                   "credentials, SMTP creds, hardening flags (debug, customErrors=Off, "
                   "trace), and every URL referenced.")
    glyph = "⚙️"
    placeholder = "Paste a web.config (or several, concatenated) — <configuration>…"
    partial = "plugins/webconfig.html"
    collect = _COLLECT

    def detect(self, text):
        return looks_like_webconfig(text)

    def parse(self, text):
        return parse_webconfig(text)

    def summary(self, d):
        s = d.get("summary", {})
        bits = [f"{s.get('files', 0)} file(s)",
                f"{s.get('connection_strings', 0)} conn-string(s)"]
        if s.get("secrets"):
            bits.append(f"{s['secrets']} secret(s)")
        if s.get("urls"):
            bits.append(f"{s['urls']} URL(s)")
        return " · ".join(bits)
