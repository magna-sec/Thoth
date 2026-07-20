"""Engagement scope: matching rules, and that nothing out of scope is ever requested."""
from app.extensions import db
from app.models import Finding, Run, Target, Workspace
from app.scope import Scope, parse
from app.tasks import run_module_task


def test_empty_scope_allows_everything():
    sc = parse("")
    assert sc.restricted is False
    assert sc.allows("anything.test") is True


def test_exact_and_wildcard_rules():
    sc = parse("example.com\n*.acme.test")
    assert sc.allows("example.com")
    assert sc.allows("acme.test")          # *.x covers the apex — nobody means to exclude it
    assert sc.allows("api.acme.test")
    assert sc.allows("deep.api.acme.test")
    assert not sc.allows("evil.test")
    assert not sc.allows("notexample.com")


def test_deny_beats_allow():
    sc = parse("*.acme.test\n!vendor.acme.test")
    assert sc.allows("api.acme.test")
    assert not sc.allows("vendor.acme.test")


def test_deny_works_without_any_allow_rules():
    sc = parse("!vendor.acme.test")
    assert sc.restricted is False
    assert sc.allows("anything.test")
    assert not sc.allows("vendor.acme.test")


def test_rules_are_normalised():
    sc = parse(" EXAMPLE.com. , https://api.acme.test:8443/path \n# comment\n\n")
    assert sc.allows("example.com")
    assert sc.allows("api.acme.test")


def test_hosts_are_normalised_before_matching():
    sc = parse("example.com")
    assert sc.allows("EXAMPLE.COM")
    assert sc.allows("example.com.")
    assert sc.allows("https://example.com:8443/x")
    assert not sc.allows("")
    assert not sc.allows(None)


def test_reason_explains_refusals():
    sc = parse("*.acme.test\n!vendor.acme.test")
    assert sc.reason("api.acme.test") is None
    assert "!vendor.acme.test" in sc.reason("vendor.acme.test")
    assert "in-scope list" in sc.reason("evil.test")


def test_partition():
    inside, outside = Scope(("*.acme.test",)).partition(["a.acme.test", "b.evil.test"])
    assert inside == ["a.acme.test"] and outside == ["b.evil.test"]


def test_task_runner_skips_out_of_scope_hosts(app, workspace, mock_target, monkeypatch):
    """The central guarantee: a run never touches a host outside the engagement."""
    monkeypatch.setattr("app.modules.alive.enrich", lambda host: {})
    with app.app_context():
        ws = db.session.get(Workspace, workspace)
        ws.scope = "in.test"
        # Both point at the mock server; only one is in scope.
        db.session.add(Target(workspace_id=workspace, host="in.test", scheme="http",
                              port=mock_target.port))
        db.session.add(Target(workspace_id=workspace, host="out.test", scheme="http",
                              port=mock_target.port))
        run = Run(workspace_id=workspace, module="alive",
                  config_json={"timeout": 3, "extra_ports": ""})
        db.session.add(run)
        db.session.commit()
        rid = run.id

        run_module_task.run(rid)
        db.session.remove()

        hosts = {f.target.host for f in Finding.query.filter_by(run_id=rid).all()}
        assert hosts == {"in.test"}                      # out.test was never requested
        log = db.session.get(Run, rid).log or ""
        assert "out-of-scope" in log and "out.test" in log   # and the run says so


def test_check_route_refuses_out_of_scope(client, app, workspace):
    with app.app_context():
        db.session.get(Workspace, workspace).scope = "*.acme.test"
        t = Target(workspace_id=workspace, host="evil.test", scheme="https")
        db.session.add(t)
        db.session.commit()
        tid = t.id
    r = client.post(f"/workspaces/{workspace}/domains/{tid}/check")
    assert r.status_code == 403 and r.get_json()["out_of_scope"] is True


def test_response_viewer_refuses_out_of_scope(client, app, workspace):
    with app.app_context():
        db.session.get(Workspace, workspace).scope = "*.acme.test"
        t = Target(workspace_id=workspace, host="evil.test", scheme="https")
        db.session.add(t)
        db.session.commit()
        tid = t.id
    r = client.get(f"/workspaces/{workspace}/response?target_id={tid}&path=/")
    assert r.status_code == 403 and "Out of scope" in r.get_json()["error"]


def test_scope_saved_and_shown(client, app, workspace):
    with app.app_context():
        db.session.add(Target(workspace_id=workspace, host="evil.test", scheme="https"))
        db.session.commit()
    page = client.post(f"/workspaces/{workspace}/settings",
                       data={"proxy": "", "scope": "*.acme.test"},
                       follow_redirects=True).data.decode()
    assert "out of scope" in page          # flash warns about the existing subdomain
    with app.app_context():
        assert db.session.get(Workspace, workspace).scope == "*.acme.test"
    assert "out of scope" in client.get(f"/workspaces/{workspace}").data.decode()
