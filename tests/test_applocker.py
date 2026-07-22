"""AppLocker policy parser + bypass/gap analysis."""
import io

import pytest

from app.applockerparse import looks_like_applocker, parse_applocker
from app.extensions import db
from app.models import Artifact

POLICY = r"""<AppLockerPolicy Version="1">
<RuleCollection Type="Appx" EnforcementMode="NotConfigured"/>
<RuleCollection Type="Dll" EnforcementMode="NotConfigured"/>
<RuleCollection Type="Script" EnforcementMode="AuditOnly"/>
<RuleCollection Type="Msi" EnforcementMode="Enabled"/>
<RuleCollection Type="Exe" EnforcementMode="Enabled">
  <FilePathRule Name="(Default Rule) All files in Windows" UserOrGroupSid="S-1-1-0" Action="Allow">
    <Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions></FilePathRule>
  <FilePathRule Name="(Default Rule) All files" UserOrGroupSid="S-1-5-32-544" Action="Allow">
    <Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
  <FilePathRule Name="Custom temp allow" UserOrGroupSid="S-1-1-0" Action="Allow">
    <Conditions><FilePathCondition Path="%WINDIR%\Temp\*"/></Conditions></FilePathRule>
  <FilePublisherRule Name="Allow Microsoft" UserOrGroupSid="S-1-1-0" Action="Allow">
    <Conditions><FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION" ProductName="*" BinaryName="*">
      <BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
</RuleCollection>
</AppLockerPolicy>"""


def test_parses_collections_and_modes():
    d = parse_applocker(POLICY)
    assert d["summary"]["modes"] == {"Exe": "Enabled", "Dll": "NotConfigured",
                                     "Msi": "Enabled", "Script": "AuditOnly",
                                     "Appx": "NotConfigured"}
    exe = [c for c in d["collections"] if c["type"] == "Exe"][0]
    assert exe["allow"] == 4
    pub = [r for r in exe["rules"] if r["kind"] == "publisher"][0]
    assert pub["binary"] == "*" and "MICROSOFT" in pub["publisher"]


def test_flags_the_classic_bypasses():
    titles = {f["title"] for f in parse_applocker(POLICY)["findings"]}
    assert "Dll rules not enforced" in titles                 # NotConfigured
    assert "Script in audit-only mode" in titles              # AuditOnly, not blocking
    assert "Allow rule covers a user-writable path" in titles  # %WINDIR%\Temp\*
    assert "Default broad-folder allow rules" in titles       # %WINDIR%\*
    assert "Wildcard publisher rule" in titles                # Microsoft *


def test_admin_star_rule_not_flagged():
    # The default `*` allow to Administrators is expected — don't flag it as "any executable".
    titles = {f["title"] for f in parse_applocker(POLICY)["findings"]}
    assert "Allows any executable (path '*')" not in titles


def test_detection_and_rejection():
    assert looks_like_applocker(POLICY)
    with pytest.raises(ValueError):
        parse_applocker("not applocker")
    with pytest.raises(ValueError):
        parse_applocker("<AppLockerPolicy></AppLockerPolicy>")     # no collections


def test_plugin_registered_with_collect_command():
    from app.plugins import get_parser
    p = get_parser("applocker")
    assert p is not None and p.kind == "artifact"
    assert "Get-AppLockerPolicy" in p.collect            # provides the PowerShell to pull it


def test_route_renders_and_lists_collect(client, app, workspace):
    page = client.post(f"/workspaces/{workspace}/artifacts",
                       data={"content": POLICY, "kind": "auto"},
                       follow_redirects=True).data.decode()
    with app.app_context():
        art = Artifact.query.filter_by(workspace_id=workspace, kind="applocker").one()
        assert art.data_json["summary"]["collections"] == 5
    assert "Dll rules not enforced" in page and "user-writable path" in page

    # The Plugins-tab Import card advertises the collection command.
    hub = client.get(f"/workspaces/{workspace}").data.decode()
    assert "Get-AppLockerPolicy" in hub and "dsregcmd /status" in hub


def test_upload(client, app, workspace):
    client.post(f"/workspaces/{workspace}/artifacts",
                data={"kind": "applocker",
                      "file": (io.BytesIO(POLICY.encode()), "applocker.xml")},
                content_type="multipart/form-data", follow_redirects=True)
    with app.app_context():
        assert Artifact.query.filter_by(workspace_id=workspace, kind="applocker").count() == 1
