"""Exports: the four datasets, the four formats, and the download route."""
import csv
import io
import json

from app.exports import filename, lines_payload, to_csv, to_markdown, to_txt
from app.extensions import db
from app.models import Finding, Target, Workspace


def _seed(app, workspace):
    with app.app_context():
        t = Target(workspace_id=workspace, host="api.acme.test", scheme="https",
                   last_alive=True, last_status_code=200, ip="10.0.0.1", asn="15169",
                   asn_name="GOOGLE, US", country="US", last_waf="Cloudflare",
                   last_server="nginx", last_tech="React", open_ports="8080")
        t.add_manual_tech(["Salesforce"])
        db.session.add(t)
        other = Target(workspace_id=workspace, host="www.acme.test", scheme="https")
        db.session.add(other)
        db.session.flush()
        db.session.add(Finding(workspace_id=workspace, target_id=t.id, path="/search?q=1",
                               status_code=200, content_length=1024,
                               extra_json={"server": "nginx", "title": "Search",
                                           "tech": ["React"], "module": "dirsearch"}))
        db.session.add(Finding(workspace_id=workspace, target_id=t.id, path="/admin",
                               status_code=403, content_length=278,
                               redirect="https://api.acme.test/login"))
        db.session.add(Finding(workspace_id=workspace, target_id=other.id, path="/",
                               status_code=200, content_length=10))
        db.session.commit()
        return t.id


def test_findings_csv_export(client, app, workspace):
    _seed(app, workspace)
    r = client.get(f"/workspaces/{workspace}/export?what=findings&fmt=csv")
    assert r.status_code == 200
    assert r.mimetype == "text/csv"
    assert "attachment" in r.headers["Content-Disposition"]

    rows = list(csv.DictReader(io.StringIO(r.data.decode())))
    assert len(rows) == 3
    row = [x for x in rows if x["path"] == "/search?q=1"][0]
    assert row["host"] == "api.acme.test"
    assert row["url"] == "https://api.acme.test/search?q=1"
    assert row["status"] == "200" and row["length"] == "1024"
    assert row["server"] == "nginx" and row["module"] == "dirsearch"


def test_findings_json_export(client, app, workspace):
    _seed(app, workspace)
    data = json.loads(client.get(
        f"/workspaces/{workspace}/export?what=findings&fmt=json").data)
    assert len(data) == 3 and all("url" in row for row in data)


def test_hosts_export_carries_enrichment_and_scope(client, app, workspace):
    _seed(app, workspace)
    with app.app_context():
        db.session.get(Workspace, workspace).scope = "api.acme.test"
        db.session.commit()

    rows = list(csv.DictReader(io.StringIO(client.get(
        f"/workspaces/{workspace}/export?what=hosts&fmt=csv").data.decode())))
    by_host = {r["host"]: r for r in rows}
    api = by_host["api.acme.test"]
    assert api["asn"] == "15169" and api["country"] == "US"
    assert api["waf"] == "Cloudflare" and api["tags"] == "Salesforce"
    assert api["open_ports"] == "443, 8080" and api["findings"] == "2"
    assert api["in_scope"] == "yes"
    assert by_host["www.acme.test"]["in_scope"] == "no"


def test_urls_and_params_exports(client, app, workspace):
    _seed(app, workspace)
    urls = client.get(f"/workspaces/{workspace}/export?what=urls&fmt=txt").data.decode()
    assert "https://api.acme.test/admin" in urls
    assert urls.splitlines() == sorted(urls.splitlines())   # sorted, ready to pipe

    params = client.get(
        f"/workspaces/{workspace}/export?what=params&fmt=txt").data.decode()
    assert params.strip().splitlines() == ["q"]


def test_export_can_be_scoped_to_one_host(client, app, workspace):
    tid = _seed(app, workspace)
    rows = list(csv.DictReader(io.StringIO(client.get(
        f"/workspaces/{workspace}/export?what=findings&fmt=csv&target_id={tid}"
    ).data.decode())))
    assert {r["host"] for r in rows} == {"api.acme.test"}   # www.acme.test excluded


def test_markdown_and_txt_shapes():
    md = to_markdown(("a", "b"), [{"a": "x|y", "b": "line\nbreak"}])
    assert md.splitlines()[0] == "| a | b |"
    assert "x\\|y" in md and "line break" in md   # pipes escaped, newlines flattened

    txt = to_txt(("a", "b"), [{"a": "1", "b": None}])
    assert txt.splitlines() == ["a\tb", "1\t"]


def test_lines_payload_formats():
    assert lines_payload(["a", "b"], "txt") == "a\nb\n"
    assert json.loads(lines_payload(["a", "b"], "json")) == ["a", "b"]
    assert lines_payload(["a"], "csv").splitlines()[0] == "value"
    assert lines_payload([], "txt") == ""


def test_csv_writes_none_as_empty_not_the_string_none():
    # (A lone empty field is legitimately serialised as "" by the csv module, so assert
    # on the round-trip rather than the raw bytes.)
    out = to_csv(("a", "b"), [{"a": None, "b": "x"}])
    assert list(csv.DictReader(io.StringIO(out))) == [{"a": "", "b": "x"}]


def test_filename_is_descriptive_and_safe():
    name = filename("ACME / Client 1", "findings", "csv")
    assert name.startswith("acme---client-1-findings-") and name.endswith(".csv")
    assert "/" not in name
    assert "api.acme.test" in filename("ws", "urls", "txt", host="api.acme.test")


def test_bad_export_params_rejected(client, workspace):
    assert client.get(f"/workspaces/{workspace}/export?what=nope&fmt=csv").status_code == 400
    assert client.get(f"/workspaces/{workspace}/export?what=hosts&fmt=exe").status_code == 400


def test_export_buttons_rendered(client, app, workspace):
    tid = _seed(app, workspace)
    page = client.get(f"/workspaces/{workspace}").data.decode()
    assert "what=findings" in page and "what=hosts" in page and "what=params" in page
    domain = client.get(f"/workspaces/{workspace}/domains/{tid}").data.decode()
    assert f"target_id={tid}" in domain
