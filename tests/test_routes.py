"""Route/integration tests: import, wipe cascade, access control, dedup controls, filters."""
from app.extensions import db
from app.models import (Finding, Note, Run, Target, TestedPath, User, Workspace,
                        WorkspaceMember)


def test_import_lowercases_dedupes_sorts(client, app, workspace):
    client.post(f"/workspaces/{workspace}/domains",
                data={"targets": "B.example.com\nA.Example.com\na.example.com"},
                follow_redirects=True)
    with app.app_context():
        hosts = [t.host for t in Target.query.filter_by(workspace_id=workspace)
                 .order_by(Target.host)]
    assert hosts == ["a.example.com", "b.example.com"]  # lowercased, deduped, sorted


def test_wipe_cascades(client, app, workspace):
    with app.app_context():
        t = Target(workspace_id=workspace, host="x.test", scheme="https")
        db.session.add(t)
        db.session.flush()
        db.session.add(Finding(workspace_id=workspace, target_id=t.id, path="/"))
        db.session.add(Note(workspace_id=workspace, target_id=t.id, body="n"))
        db.session.add(TestedPath(workspace_id=workspace, host="x.test", parent_path="/",
                                  word="admin"))
        db.session.commit()
    client.post(f"/workspaces/{workspace}/wipe", data={"confirm": "WS"},
                follow_redirects=True)
    with app.app_context():
        assert db.session.get(Workspace, workspace) is None
        assert Target.query.count() == 0
        assert Finding.query.count() == 0
        assert TestedPath.query.count() == 0


def test_non_admin_restrictions(client, app, workspace):
    with app.app_context():
        u = User(email="operator", is_admin=False)
        u.set_password("pw")
        db.session.add(u)
        db.session.commit()
    op = _login(app, "operator", "pw")
    # A non-admin CAN access and work in a shared workspace...
    assert op.get(f"/workspaces/{workspace}").status_code == 200
    # ...but CANNOT create workspaces, wipe, or manage users.
    assert op.post("/workspaces/new", data={"name": "X"}).status_code == 403
    assert op.post(f"/workspaces/{workspace}/wipe",
                   data={"confirm": "WS"}).status_code == 403
    assert op.get("/users").status_code == 403
    assert op.post("/users", data={"email": "z"}).status_code == 403


def test_admin_creates_users(client, app):
    # `client` is the seeded admin (magna).
    client.post("/users", data={"email": "newop", "password": "pw"}, follow_redirects=True)
    client.post("/users", data={"email": "boss", "password": "pw", "is_admin": "on"},
                follow_redirects=True)
    with app.app_context():
        assert User.query.filter_by(email="newop").first().is_admin is False
        assert User.query.filter_by(email="boss").first().is_admin is True


def test_open_registration_removed(client):
    assert client.get("/register").status_code == 404


def test_clear_ledger_domain_and_workspace(client, app, workspace):
    with app.app_context():
        t = Target(workspace_id=workspace, host="h.test", scheme="https")
        db.session.add(t)
        db.session.flush()
        tid = t.id
        for w in ("a", "b", "c"):
            db.session.add(TestedPath(workspace_id=workspace, host="h.test",
                                      parent_path="/", word=w))
        db.session.commit()
    client.post(f"/workspaces/{workspace}/domains/{tid}/clear-ledger", follow_redirects=True)
    with app.app_context():
        assert TestedPath.query.filter_by(workspace_id=workspace).count() == 0


def test_rerun_forces_dirsearch(client, app, workspace):
    with app.app_context():
        run = Run(workspace_id=workspace, module="dirsearch",
                  config_json={"_targets": [1], "recursion_depth": 1}, status="done")
        db.session.add(run)
        db.session.commit()
        rid = run.id
    client.post(f"/workspaces/{workspace}/runs/{rid}/rerun", follow_redirects=True)
    with app.app_context():
        new = Run.query.filter(Run.id != rid, Run.workspace_id == workspace).first()
        assert new is not None and new.config_json.get("force") is True


def test_results_filters_present(client, workspace):
    page = client.get(f"/workspaces/{workspace}").data.decode()
    for needle in ('id="rf-host"', 'id="rf-exstatus"', 'id="rf-exsize"', 'id="rf-hideredir"'):
        assert needle in page


def test_checkall_creates_alive_run(client, app, workspace):
    with app.app_context():
        db.session.add(Target(workspace_id=workspace, host="a.test", scheme="https"))
        db.session.commit()
    client.post(f"/workspaces/{workspace}/checkall", follow_redirects=True)
    with app.app_context():
        assert Run.query.filter_by(workspace_id=workspace, module="alive").count() == 1


def test_activity_endpoint(client, workspace):
    d = client.get(f"/workspaces/{workspace}/activity").get_json()
    assert set(d) >= {"active", "running", "findings", "runs"}


def test_fuzz_coverage_shown(client, app, workspace):
    with app.app_context():
        t = Target(workspace_id=workspace, host="cov.test", scheme="https")
        db.session.add(t)
        db.session.flush()
        tid = t.id
        for parent in ("/", "/status/"):
            for i in range(5):
                db.session.add(TestedPath(workspace_id=workspace, host="cov.test",
                                          parent_path=parent, word=f"w{i}"))
        db.session.commit()
    # Subdomain page lists which base paths were already fuzzed.
    dp = client.get(f"/workspaces/{workspace}/domains/{tid}").data.decode()
    assert "Directory fuzz coverage" in dp and "/status/" in dp
    # Fuzz tab annotates the host with a coverage badge.
    page = client.get(f"/workspaces/{workspace}").data.decode()
    assert "Already fuzzed" in page


def _login(app, email, password):
    c = app.test_client()
    c.post("/login", data={"email": email, "password": password})
    return c
