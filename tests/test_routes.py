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


def test_admin_sets_own_and_others_password(client, app):
    # `client` is the seeded admin (magna). Create another user to reset.
    client.post("/users", data={"email": "alice", "password": "oldpass12"},
                follow_redirects=True)
    with app.app_context():
        magna = User.query.filter_by(email="magna").first()
        alice = User.query.filter_by(email="alice").first()
        magna_id, alice_id = magna.id, alice.id

    # Admin resets Alice's password; she can log in with the new one.
    client.post(f"/users/{alice_id}/password", data={"password": "alice-new-1"},
                follow_redirects=True)
    assert _login(app, "alice", "alice-new-1").get("/workspaces/").status_code == 200

    # Admin changes their OWN password from the Users page, then re-auths with it.
    client.post(f"/users/{magna_id}/password", data={"password": "magna-new-9"},
                follow_redirects=True)
    fresh = app.test_client()
    fresh.post("/login", data={"email": "magna", "password": "magna-new-9"})
    assert fresh.get("/users").status_code == 200
    # The old password no longer works.
    stale = app.test_client()
    stale.post("/login", data={"email": "magna", "password": "magna"})
    assert stale.get("/users").status_code in (302, 401)


def test_set_password_rejects_short(client, app):
    with app.app_context():
        mid = User.query.filter_by(email="magna").first().id
    page = client.post(f"/users/{mid}/password", data={"password": "short"},
                       follow_redirects=True).data.decode()
    assert "at least 8" in page


def test_login_is_recorded_and_shown(client, app):
    from app.models import LoginEvent, User
    # `client` fixture already logged in magna once.
    with app.app_context():
        magna = User.query.filter_by(email="magna").first()
        assert LoginEvent.query.filter_by(user_id=magna.id).count() >= 1
        assert magna.last_login is not None
        mid = magna.id

    # The Users list shows a last-login column…
    lst = client.get("/users").data.decode()
    assert "Last login" in lst
    # …and each user is clickable to a detail page with sign-in history.
    detail = client.get(f"/users/{mid}").data.decode()
    assert "Sign-in history" in detail and "Sign-ins" in detail


def test_user_detail_requires_admin(app):
    with app.app_context():
        op = User(email="operator", is_admin=False)
        op.set_password("operator-pw")
        db.session.add(op)
        db.session.commit()
        oid = op.id
    op_client = _login(app, "operator", "operator-pw")
    assert op_client.get(f"/users/{oid}").status_code == 403


def test_set_password_requires_admin(client, app):
    with app.app_context():
        op = User(email="operator", is_admin=False)
        op.set_password("operator-pw")
        db.session.add(op)
        db.session.commit()
        oid = op.id
    op_client = _login(app, "operator", "operator-pw")
    assert op_client.post(f"/users/{oid}/password",
                          data={"password": "whatever12"}).status_code == 403


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


def test_filters_are_persisted_and_resettable(client, app, workspace):
    """Sticky filters need persist.js loaded before the filter scripts, plus a visible
    escape hatch on every filter bar."""
    with app.app_context():
        t = Target(workspace_id=workspace, host="f.test", scheme="https")
        db.session.add(t)
        db.session.commit()
        tid = t.id

    page = client.get(f"/workspaces/{workspace}").data.decode()
    assert page.index("js/persist.js") < page.index("js/results.js")
    assert page.index("js/persist.js") < page.index("js/table.js")
    assert 'id="rf-reset"' in page and 'id="df-reset"' in page

    domain = client.get(f"/workspaces/{workspace}/domains/{tid}").data.decode()
    assert domain.index("js/persist.js") < domain.index("js/domain-page.js")


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
