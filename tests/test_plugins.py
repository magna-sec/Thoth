"""The parser-plugin framework: registry, auto-detect, drop-in, and the catalogue."""
from app.plugins import (ParserPlugin, all_parsers, detect_parser, get_parser,
                         register_parser)
from app.plugins.base import PARSER_REGISTRY


def test_builtin_parsers_are_registered():
    assert set(all_parsers()) >= {"pac", "dsregcmd"}
    assert get_parser("pac").title == "PAC file"
    assert get_parser("nope") is None


def test_detect_routes_to_the_right_plugin():
    assert detect_parser("function FindProxyForURL(url, host){return 'DIRECT';}").name == "pac"
    assert detect_parser("AzureAdJoined : YES\nTenantId : x").name == "dsregcmd"
    assert detect_parser("just prose") is None


def test_a_new_plugin_is_fully_drop_in():
    """The whole promise: define a @register_parser class and it works everywhere —
    registry, auto-detect, parse — with no other wiring."""
    @register_parser
    class WhoamiPlugin(ParserPlugin):
        name = "whoami-test"
        title = "whoami"
        partial = "plugins/whoami.html"

        def detect(self, text):
            return "USER INFORMATION" in (text or "").upper()

        def parse(self, text):
            return {"lines": [ln for ln in text.splitlines() if ln.strip()]}

        def summary(self, d):
            return f"{len(d['lines'])} line(s)"

    try:
        assert "whoami-test" in all_parsers()
        plugin = detect_parser("USER INFORMATION\ncontoso\\alice")
        assert plugin.name == "whoami-test"
        data = plugin.parse("USER INFORMATION\ncontoso\\alice")
        assert data["lines"] == ["USER INFORMATION", "contoso\\alice"]
        assert plugin.summary(data) == "2 line(s)"
    finally:
        PARSER_REGISTRY.pop("whoami-test", None)   # don't leak into other tests


def test_detect_survives_a_broken_plugin():
    @register_parser
    class BrokenPlugin(ParserPlugin):
        name = "broken-test"
        title = "broken"

        def detect(self, text):
            raise RuntimeError("boom")

        def parse(self, text):
            return {}

    try:
        # A plugin whose detect() throws must not stop the others from matching.
        assert detect_parser("function FindProxyForURL(u,h){return 'DIRECT'}").name == "pac"
    finally:
        PARSER_REGISTRY.pop("broken-test", None)


def test_catalog_lists_modules_and_parsers(client):
    page = client.get("/plugins/").data.decode()
    assert "Plugins" in page
    for module in ("alive", "dnsbrute", "dirsearch", "screenshot", "iistilde"):
        assert module in page
    assert "PAC file" in page and "dsregcmd status" in page
    assert "Write a plugin" in page                # the authoring guidance


def test_catalog_requires_login(app):
    assert app.test_client().get("/plugins/").status_code in (302, 401)


def test_nav_links_to_plugins(client, workspace):
    assert 'href="/plugins/"' in client.get(f"/workspaces/{workspace}").data.decode()
