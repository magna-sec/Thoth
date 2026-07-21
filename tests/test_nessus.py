"""Nessus (.nessus) parser plugin."""
import io

import pytest

from app.extensions import db
from app.models import Artifact, Target
from app.nessusparse import looks_like_nessus, parse_nessus

NESSUS = """<?xml version="1.0" ?>
<NessusClientData_v2>
<Report name="scan">
<ReportHost name="10.0.0.5">
  <HostProperties>
    <tag name="host-ip">10.0.0.5</tag>
    <tag name="host-fqdn">dc01.corp.local</tag>
    <tag name="operating-system">Microsoft Windows Server 2019</tag>
  </HostProperties>
  <ReportItem port="445" svc_name="cifs" protocol="tcp" severity="4" pluginID="57608"
      pluginName="SMB Signing not required" pluginFamily="Misc.">
    <risk_factor>Critical</risk_factor>
    <cvss3_base_score>9.8</cvss3_base_score>
    <cve>CVE-2020-1472</cve>
    <synopsis>Signing is not required on the remote SMB server.</synopsis>
    <solution>Enforce message signing.</solution>
  </ReportItem>
  <ReportItem port="0" protocol="tcp" severity="0" pluginID="11219"
      pluginName="Nessus SYN scanner" pluginFamily="Port scanners">
    <risk_factor>None</risk_factor>
  </ReportItem>
</ReportHost>
<ReportHost name="10.0.0.20">
  <HostProperties><tag name="host-ip">10.0.0.20</tag></HostProperties>
  <ReportItem port="443" svc_name="www" protocol="tcp" severity="2" pluginID="1"
      pluginName="TLS Version 1.0 Detected" pluginFamily="Service detection">
    <risk_factor>Medium</risk_factor><cvss_base_score>5.0</cvss_base_score>
  </ReportItem>
</ReportHost>
</Report>
</NessusClientData_v2>"""


def test_parses_hosts_and_severities():
    d = parse_nessus(NESSUS)
    assert d["summary"]["hosts"] == 2
    assert d["summary"]["sev"] == {"critical": 1, "high": 0, "medium": 1, "low": 0, "info": 1}
    # Host with a critical finding sorts first.
    assert d["hosts"][0]["name"] == "10.0.0.5"
    assert d["hosts"][0]["fqdn"] == "dc01.corp.local"
    crit = d["hosts"][0]["findings"][0]
    assert crit["severity"] == "critical" and crit["cvss"] == "9.8"
    assert crit["cves"] == ["CVE-2020-1472"]


def test_notable_is_critical_and_high_only():
    d = parse_nessus(NESSUS)
    assert [f["name"] for f in d["notable"]] == ["SMB Signing not required"]  # not the medium


def test_detection_and_rejection():
    assert looks_like_nessus(NESSUS)
    assert not looks_like_nessus("<nmaprun></nmaprun>")
    with pytest.raises(ValueError):
        parse_nessus("not nessus")
    with pytest.raises(ValueError):
        parse_nessus("<NessusClientData_v2></NessusClientData_v2>")   # no hosts


def test_nessus_is_registered_as_a_parser():
    from app.plugins import get_parser
    p = get_parser("nessus")
    assert p is not None and p.kind == "artifact"
    assert p.summary(parse_nessus(NESSUS)) == "2 host(s) · 1 critical · 1 medium"


def test_nessus_artifact_route_renders(client, app, workspace):
    page = client.post(f"/workspaces/{workspace}/artifacts",
                       data={"content": NESSUS, "kind": "auto"},
                       follow_redirects=True).data.decode()
    with app.app_context():
        art = Artifact.query.filter_by(workspace_id=workspace, kind="nessus").one()
        assert art.data_json["summary"]["hosts"] == 2
    assert "SMB Signing not required" in page
    assert "9.8" in page and "dc01.corp.local" in page and "sev-critical" in page


def test_nessus_upload(client, app, workspace):
    client.post(f"/workspaces/{workspace}/artifacts",
                data={"kind": "nessus", "file": (io.BytesIO(NESSUS.encode()), "scan.nessus")},
                content_type="multipart/form-data", follow_redirects=True)
    with app.app_context():
        assert Artifact.query.filter_by(workspace_id=workspace, kind="nessus").count() == 1
