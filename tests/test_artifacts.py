"""Parsing and displaying recon artifacts: dsregcmd /status and PAC files."""
import io

import pytest

from app.dsregcmd import looks_like_dsregcmd, parse_dsregcmd
from app.extensions import db
from app.models import Artifact, Workspace
from app.pacparse import looks_like_pac, parse_pac

DSREGCMD = """
+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+

             AzureAdJoined : YES
          EnterpriseJoined : NO
              DomainJoined : NO
                  DeviceId : 2b8f1c33-1111-2222-3333-444455556666
                DeviceName : LAPTOP-CONTOSO

+----------------------------------------------------------------------+
| Tenant Details                                                       |
+----------------------------------------------------------------------+

                TenantName : Contoso Ltd
                  TenantId : aaaabbbb-cccc-dddd-eeee-ffff00001111
                       Idp : login.windows.net
                    MdmUrl : https://enrollment.manage.microsoft.com/enrollmentserver/

+----------------------------------------------------------------------+
| SSO State                                                            |
+----------------------------------------------------------------------+

                AzureAdPrt : YES
"""

PAC = """
function FindProxyForURL(url, host) {
    if (isPlainHostName(host) ||
        dnsDomainIs(host, "intranet.contoso.com") ||
        shExpMatch(host, "*.internal.contoso.com") ||
        isInNet(host, "10.0.0.0", "255.0.0.0"))
        return "DIRECT";

    if (dnsDomainIs(host, "partner.example.net"))
        return "PROXY proxy1.contoso.com:8080; PROXY proxy2.contoso.com:8080";

    return "PROXY defaultproxy.contoso.com:3128";
}
"""


def test_dsregcmd_sections_and_summary():
    data = parse_dsregcmd(DSREGCMD)
    titles = [s["title"] for s in data["sections"]]
    assert titles == ["Device State", "Tenant Details", "SSO State"]

    device = data["sections"][0]["items"]
    assert {"key": "AzureAdJoined", "value": "YES"} in device
    tenant = {it["key"]: it["value"] for it in data["sections"][1]["items"]}
    assert tenant["TenantName"] == "Contoso Ltd"
    assert tenant["MdmUrl"].startswith("https://enrollment")

    summary = {s["key"]: s for s in data["summary"]}
    assert summary["AzureAdJoined"]["bool"] is True
    assert summary["DomainJoined"]["bool"] is False
    assert summary["TenantName"]["value"] == "Contoso Ltd"
    assert summary["TenantName"]["bool"] is None   # not a yes/no field


def test_dsregcmd_detection_heuristic():
    assert looks_like_dsregcmd(DSREGCMD)
    assert not looks_like_dsregcmd("just some text")


def test_dsregcmd_handles_blank_and_colon_values():
    data = parse_dsregcmd("| Device State |\n   MdmUrl : \n   Weird : a : b\n")
    # A value that itself contains ' : ' splits only on the first.
    items = {it["key"]: it["value"] for it in data["sections"][0]["items"]}
    assert items["MdmUrl"] == ""
    assert items["Weird"] == "a : b"


def test_pac_extracts_proxies_direct_and_subnets():
    d = parse_pac(PAC)
    assert "PROXY proxy1.contoso.com:8080" in d["proxies"]
    assert "PROXY defaultproxy.contoso.com:3128" in d["proxies"]
    # DIRECT block: the internal estate that bypasses the proxy.
    assert "intranet.contoso.com" in d["direct_patterns"]
    assert "*.internal.contoso.com" in d["direct_patterns"]
    assert "10.0.0.0/8" in d["direct_patterns"]           # mask -> prefix
    assert "partner.example.net" in d["proxied_patterns"]
    assert "10.0.0.0/8" in d["subnets"]
    assert d["direct_returns"] == 1 and d["proxy_returns"] == 2
    assert "dnsDomainIs" in d["helpers"] and "isInNet" in d["helpers"]


def test_pac_reconstructs_rules_and_default():
    d = parse_pac(PAC)
    assert len(d["rules"]) == 3
    assert d["rules"][0]["action"] == "DIRECT"
    assert d["rules"][1]["action"] == "PROXY"
    assert d["default_action"] == "PROXY"            # last unconditional return


def test_pac_flags_common_misconfigs():
    bad = """function FindProxyForURL(url, host) {
        if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";
        if (shExpMatch(host, "*")) return "PROXY 8.8.8.8:3128";
        return "PROXY user:pass@proxy.corp:8080";
    }"""
    titles = {f["title"] for f in parse_pac(bad)["findings"]}
    assert "Credentials in proxy string" in titles          # user:pass@
    assert "Proxy on a public IP" in titles                 # 8.8.8.8
    assert "Resolves every hostname (DNS leak)" in titles   # isInNet(host,…)
    assert "Wildcard rule matches everything" in titles     # shExpMatch(host,"*")


def test_pac_clean_file_has_few_findings():
    clean = """function FindProxyForURL(url, host) {
        if (isPlainHostName(host) || dnsDomainIs(host, "corp.local")) return "DIRECT";
        return "PROXY proxy.corp.local:8080";
    }"""
    titles = {f["title"] for f in parse_pac(clean)["findings"]}
    assert "Credentials in proxy string" not in titles
    assert "Resolves every hostname (DNS leak)" not in titles


def test_dsregcmd_headline_and_notable():
    from app.dsregcmd import parse_dsregcmd
    hybrid = parse_dsregcmd(
        "| Device State |\nAzureAdJoined : YES\nDomainJoined : YES\n"
        "| Tenant Details |\nTenantName : Contoso\n| SSO State |\nAzureAdPrt : YES\n")
    assert "Hybrid" in hybrid["headline"] and "Contoso" in hybrid["headline"]
    assert any("Primary Refresh Token" in n["title"] for n in hybrid["notable"])

    standalone = parse_dsregcmd("| Device State |\nAzureAdJoined : NO\nDomainJoined : NO\n")
    assert "Not joined" in standalone["headline"]


def test_pac_detection_and_rejection():
    assert looks_like_pac(PAC)
    with pytest.raises(ValueError):
        parse_pac("this is definitely not a pac file")


def test_add_dsregcmd_artifact_route_autodetects_and_opens_it(client, app, workspace):
    # Saving redirects straight to the artifact's own page (follow it and check content).
    page = client.post(f"/workspaces/{workspace}/artifacts",
                       data={"content": DSREGCMD, "kind": "auto"},
                       follow_redirects=True).data.decode()
    with app.app_context():
        art = Artifact.query.filter_by(workspace_id=workspace).one()
        assert art.kind == "dsregcmd"
        assert art.data_json["summary"][0]["key"] == "AzureAdJoined"
    assert "Contoso Ltd" in page                 # landed on the parsed view


def test_add_pac_artifact_via_upload(client, app, workspace):
    client.post(f"/workspaces/{workspace}/artifacts",
                data={"kind": "pac", "file": (io.BytesIO(PAC.encode()), "proxy.pac")},
                content_type="multipart/form-data", follow_redirects=True)
    with app.app_context():
        art = Artifact.query.filter_by(workspace_id=workspace).one()
        assert art.kind == "pac" and art.name == "proxy.pac"
        assert "PROXY defaultproxy.contoso.com:3128" in art.data_json["proxies"]


def test_undetectable_content_is_rejected(client, app, workspace):
    page = client.post(f"/workspaces/{workspace}/artifacts",
                       data={"content": "random text", "kind": "auto"},
                       follow_redirects=True).data.decode()
    assert "Couldn&#39;t tell" in page or "Couldn't tell" in page
    with app.app_context():
        assert Artifact.query.filter_by(workspace_id=workspace).count() == 0


def test_workspace_lists_artifacts_and_detail_pages_render(client, app, workspace):
    client.post(f"/workspaces/{workspace}/artifacts",
                data={"content": DSREGCMD, "kind": "dsregcmd", "name": "laptop"},
                follow_redirects=True)
    client.post(f"/workspaces/{workspace}/artifacts",
                data={"content": PAC, "kind": "pac", "name": "corp.pac"},
                follow_redirects=True)

    # The workspace page LISTS them (compact) on the tab and Overview, not the full dump.
    page = client.get(f"/workspaces/{workspace}").data.decode()
    assert 'data-pane="artifacts"' in page
    assert "laptop" in page and "corp.pac" in page
    assert "Recon artifacts" in page                    # Overview card
    assert "artifact-grid" not in page                  # the full render is NOT dumped here
    assert "defaultproxy.contoso.com:3128" not in page  # proxies only on the detail page

    with app.app_context():
        arts = {a.kind: a.id for a in Artifact.query.filter_by(workspace_id=workspace).all()}

    ds = client.get(f"/workspaces/{workspace}/artifacts/{arts['dsregcmd']}").data.decode()
    assert "Contoso Ltd" in ds and "AzureAdJoined" in ds
    pac = client.get(f"/workspaces/{workspace}/artifacts/{arts['pac']}").data.decode()
    assert "defaultproxy.contoso.com:3128" in pac       # proxy
    assert "intranet.contoso.com" in pac                # DIRECT footprint

    client.post(f"/workspaces/{workspace}/artifacts/{arts['pac']}/delete",
                follow_redirects=True)
    with app.app_context():
        assert Artifact.query.filter_by(workspace_id=workspace).count() == 1


def test_artifact_detail_404_for_other_workspace(client, app, workspace):
    from app.models import Workspace
    with app.app_context():
        other = Workspace(name="Other")
        db.session.add(other)
        db.session.flush()
        art = Artifact(workspace_id=other.id, kind="pac", data_json={})
        db.session.add(art)
        db.session.commit()
        aid = art.id
    assert client.get(f"/workspaces/{workspace}/artifacts/{aid}").status_code == 404


def test_artifacts_wiped_with_workspace(client, app, workspace):
    with app.app_context():
        ws = db.session.get(Workspace, workspace)
        db.session.add(Artifact(workspace_id=ws.id, kind="pac", data_json={}))
        db.session.commit()
    client.post(f"/workspaces/{workspace}/wipe", data={"confirm": "WS"},
                follow_redirects=True)
    with app.app_context():
        assert Artifact.query.count() == 0
