"""Parsing nuclei output and importing it, matched to subdomains by host."""
import io
import json

import pytest

from app.extensions import db
from app.models import Finding, Run, Target
from app.nucleiparse import NucleiParseError, parse_nuclei

JSONL = "\n".join(json.dumps(o) for o in [
    {"template-id": "CVE-2023-1", "info": {"name": "Critical RCE", "severity": "critical",
                                           "tags": ["cve", "rce"]},
     "type": "http", "host": "https://api.acme.test",
     "matched-at": "https://api.acme.test/vuln?x=1"},
    {"template-id": "tech-detect", "info": {"name": "nginx detected", "severity": "info"},
     "host": "https://www.acme.test", "matched-at": "https://www.acme.test/"},
    {"templateID": "old-field", "info": {"name": "Legacy field name", "severity": "low"},
     "matched-at": "https://api.acme.test/legacy"},   # old key spelling
])


def test_parses_jsonl_severity_sorted():
    rows, hosts = parse_nuclei(JSONL)
    assert hosts == {"api.acme.test", "www.acme.test"}
    assert rows[0]["severity"] == "critical"        # most severe first
    assert rows[0]["name"] == "Critical RCE"
    assert rows[0]["host"] == "api.acme.test" and rows[0]["path"] == "/vuln?x=1"
    assert "rce" in rows[0]["tags"]
    assert any(r["template_id"] == "old-field" for r in rows)   # templateID accepted


def test_parses_json_array():
    text = json.dumps([
        {"template-id": "t1", "info": {"name": "A", "severity": "high"},
         "host": "http://a.test", "matched-at": "http://a.test/a"}])
    rows, hosts = parse_nuclei(text)
    assert rows[0]["severity"] == "high" and hosts == {"a.test"}


def test_dedupes_by_host_template_path():
    dupe = "\n".join([JSONL.splitlines()[0]] * 3)
    rows, _ = parse_nuclei(dupe)
    assert len(rows) == 1


def test_bad_severity_and_missing_fields():
    rows, _ = parse_nuclei(json.dumps(
        {"template-id": "t", "info": {"name": "n", "severity": "spicy"},
         "host": "h.test", "matched-at": "h.test/x"}))
    assert rows[0]["severity"] == "unknown"


def test_rejects_junk():
    with pytest.raises(NucleiParseError):
        parse_nuclei("this is not nuclei output at all")
    with pytest.raises(NucleiParseError):
        parse_nuclei("")


def test_import_route_matches_by_host(client, app, workspace):
    with app.app_context():
        db.session.add(Target(workspace_id=workspace, host="api.acme.test", scheme="https"))
        db.session.add(Target(workspace_id=workspace, host="www.acme.test", scheme="https"))
        db.session.commit()

    client.post(f"/workspaces/{workspace}/import-nuclei",
                data={"results": JSONL}, follow_redirects=True)

    with app.app_context():
        run = Run.query.filter_by(workspace_id=workspace, module="nuclei-import").one()
        findings = Finding.query.filter_by(run_id=run.id).all()
        assert len(findings) == 3   # two hosts matched; both api findings + the www one
        crit = [f for f in findings if f.extra_json["severity"] == "critical"][0]
        assert crit.target.host == "api.acme.test"
        assert crit.extra_json["title"] == "Critical RCE"
        assert crit.extra_json["module"] == "nuclei-import"


def test_import_reports_unmatched_hosts(client, app, workspace):
    with app.app_context():
        db.session.add(Target(workspace_id=workspace, host="api.acme.test", scheme="https"))
        db.session.commit()
    # www.acme.test isn't a subdomain here — its finding must be skipped, not invented.
    page = client.post(f"/workspaces/{workspace}/import-nuclei",
                       data={"results": JSONL}, follow_redirects=True).data.decode()
    with app.app_context():
        run = Run.query.filter_by(workspace_id=workspace).one()
        hosts = {f.target.host for f in Finding.query.filter_by(run_id=run.id).all()}
        assert hosts == {"api.acme.test"}
        assert "not a subdomain" in (run.log or "")


def test_import_can_be_scoped_to_selected_subdomains(client, app, workspace):
    with app.app_context():
        api = Target(workspace_id=workspace, host="api.acme.test", scheme="https")
        www = Target(workspace_id=workspace, host="www.acme.test", scheme="https")
        db.session.add_all([api, www])
        db.session.commit()
        api_id = api.id

    client.post(f"/workspaces/{workspace}/import-nuclei",
                data={"results": JSONL, "target_ids": [api_id]}, follow_redirects=True)
    with app.app_context():
        run = Run.query.filter_by(workspace_id=workspace).one()
        hosts = {f.target.host for f in Finding.query.filter_by(run_id=run.id).all()}
        assert hosts == {"api.acme.test"}   # www deselected, so skipped


def test_import_accepts_multiple_files(client, app, workspace):
    with app.app_context():
        db.session.add(Target(workspace_id=workspace, host="api.acme.test", scheme="https"))
        db.session.commit()
    lines = JSONL.splitlines()
    client.post(f"/workspaces/{workspace}/import-nuclei",
                data={"results": "", "file": [
                    (io.BytesIO(lines[0].encode()), "run1.jsonl"),
                    (io.BytesIO(lines[2].encode()), "run2.jsonl"),
                ]}, content_type="multipart/form-data", follow_redirects=True)
    with app.app_context():
        run = Run.query.filter_by(workspace_id=workspace).one()
        assert Finding.query.filter_by(run_id=run.id).count() == 2
        assert run.config_json["source"] == "run1.jsonl, run2.jsonl"


def test_nothing_matched_is_reported(client, app, workspace):
    with app.app_context():
        db.session.add(Target(workspace_id=workspace, host="unrelated.test", scheme="https"))
        db.session.commit()
    page = client.post(f"/workspaces/{workspace}/import-nuclei",
                       data={"results": JSONL}, follow_redirects=True).data.decode()
    assert "No nuclei findings matched" in page


def test_nuclei_is_a_findings_parser_plugin():
    from app.plugins import get_parser
    from app.nucleiparse import looks_like_nuclei
    p = get_parser("nuclei")
    assert p is not None and p.kind == "findings"
    assert looks_like_nuclei(JSONL) and not looks_like_nuclei("just prose")


def test_nuclei_via_artifacts_picker_creates_findings(client, app, workspace):
    """The unified Artifacts picker routes nuclei to subdomain findings, not an Artifact."""
    with app.app_context():
        db.session.add(Target(workspace_id=workspace, host="api.acme.test", scheme="https"))
        db.session.commit()
    client.post(f"/workspaces/{workspace}/artifacts",
                data={"content": JSONL, "kind": "auto"}, follow_redirects=True)
    with app.app_context():
        from app.models import Artifact
        assert Artifact.query.filter_by(workspace_id=workspace).count() == 0   # not stored
        run = Run.query.filter_by(workspace_id=workspace, module="nuclei-import").one()
        hosts = {f.target.host for f in Finding.query.filter_by(run_id=run.id).all()}
        assert hosts == {"api.acme.test"}   # www not a target here, so skipped


def test_disabled_nuclei_rejected_in_picker(client, app, workspace):
    from app.models import Workspace
    with app.app_context():
        db.session.get(Workspace, workspace).enabled_plugins = ["alive"]   # no nuclei
        db.session.commit()
    page = client.post(f"/workspaces/{workspace}/artifacts",
                       data={"content": JSONL, "kind": "nuclei"},
                       follow_redirects=True).data.decode()
    assert "isn&#39;t enabled" in page or "isn't enabled" in page


def test_vulns_surface_on_domain_page(client, app, workspace):
    with app.app_context():
        t = Target(workspace_id=workspace, host="api.acme.test", scheme="https")
        db.session.add(t)
        db.session.commit()
        tid = t.id
    client.post(f"/workspaces/{workspace}/import-nuclei",
                data={"results": JSONL}, follow_redirects=True)
    page = client.get(f"/workspaces/{workspace}/domains/{tid}").data.decode()
    assert "Vulnerabilities" in page
    assert "Critical RCE" in page and "sev-critical" in page
