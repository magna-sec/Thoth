"""nmap parser plugin: XML, greppable, normal formats, and the artifact route."""
import io

import pytest

from app.extensions import db
from app.models import Artifact, Target
from app.nmapparse import looks_like_nmap, parse_nmap

XML = """<?xml version="1.0"?><nmaprun>
<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
<hostnames><hostname name="dc01.corp.local" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="88"><state state="open"/>
  <service name="kerberos-sec" product="Microsoft Windows Kerberos"/></port>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
<port protocol="tcp" portid="3389"><state state="closed"/><service name="ms-wbt-server"/></port>
</ports></host>
<host><status state="down"/><address addr="10.0.0.6" addrtype="ipv4"/></host>
</nmaprun>"""

GREP = ("Host: 192.168.1.10 (web01)\tPorts: 22/open/tcp//ssh//OpenSSH 8.2/, "
        "80/open/tcp//http//nginx/\n")

NORMAL = """Nmap scan report for web02 (192.168.1.11)
Host is up (0.010s latency).
PORT     STATE  SERVICE   VERSION
22/tcp   open   ssh       OpenSSH 7.4
443/tcp  open   https     nginx
8080/tcp closed http-proxy
"""


def test_parses_xml_excludes_down_and_closed():
    d = parse_nmap(XML)
    assert d["summary"]["hosts"] == 1                 # the down host is dropped
    host = d["hosts"][0]
    assert host["address"] == "10.0.0.5"
    assert host["hostnames"] == ["dc01.corp.local"]
    ports = {p["port"] for p in host["ports"]}
    assert ports == {88, 445}                         # 3389 was closed
    assert "kerberos-sec" in d["summary"]["interesting"]


def test_parses_greppable():
    d = parse_nmap(GREP)
    h = d["hosts"][0]
    assert h["address"] == "192.168.1.10" and h["hostnames"] == ["web01"]
    assert {p["port"] for p in h["ports"]} == {22, 80}


def test_parses_normal_report():
    d = parse_nmap(NORMAL)
    h = d["hosts"][0]
    assert h["address"] == "192.168.1.11"
    assert {p["port"] for p in h["ports"]} == {22, 443}   # 8080 closed excluded


def test_detection_and_rejection():
    assert looks_like_nmap(XML) and looks_like_nmap(GREP)
    with pytest.raises(ValueError):
        parse_nmap("not nmap output")
    with pytest.raises(ValueError):
        parse_nmap("<nmaprun></nmaprun>")   # no hosts


def test_nmap_artifact_route_autodetects_and_renders(client, app, workspace):
    page = client.post(f"/workspaces/{workspace}/artifacts",
                       data={"content": XML, "kind": "auto"},
                       follow_redirects=True).data.decode()
    with app.app_context():
        art = Artifact.query.filter_by(workspace_id=workspace, kind="nmap").one()
        assert art.data_json["summary"]["hosts"] == 1
    assert "10.0.0.5" in page and "kerberos-sec" in page


def test_nmap_upload(client, app, workspace):
    client.post(f"/workspaces/{workspace}/artifacts",
                data={"kind": "nmap", "file": (io.BytesIO(GREP.encode()), "scan.gnmap")},
                content_type="multipart/form-data", follow_redirects=True)
    with app.app_context():
        assert Artifact.query.filter_by(workspace_id=workspace, kind="nmap").count() == 1
