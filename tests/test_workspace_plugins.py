"""Per-workspace plugin selection: model default, creation, management, enforcement, UI."""
from app.extensions import db
from app.models import Run, Target, User, Workspace, WorkspaceMember


def test_default_is_all_enabled():
    ws = Workspace(name="x")
    assert ws.enabled_plugins is None
    assert ws.plugin_enabled("screenshot") and ws.plugin_enabled("pac")


def test_explicit_selection_restricts():
    ws = Workspace(name="x", enabled_plugins=["alive", "pac"])
    assert ws.plugin_enabled("alive") and ws.plugin_enabled("pac")
    assert not ws.plugin_enabled("screenshot") and not ws.plugin_enabled("dnsbrute")


def test_create_workspace_stores_selected_plugins(client, app):
    client.post("/workspaces/new",
                data={"name": "Scoped", "configure_plugins": "1",
                      "plugins": ["alive", "dnsbrute", "pac"]}, follow_redirects=True)
    with app.app_context():
        ws = Workspace.query.filter_by(name="Scoped").one()
        assert set(ws.enabled_plugins) == {"alive", "dnsbrute", "pac"}
        assert ws.plugin_enabled("alive") and not ws.plugin_enabled("screenshot")


def test_create_without_marker_keeps_all(client, app):
    # A create that doesn't submit the picker leaves NULL = all enabled.
    client.post("/workspaces/new", data={"name": "Plain"}, follow_redirects=True)
    with app.app_context():
        assert Workspace.query.filter_by(name="Plain").one().enabled_plugins is None


def test_disabled_module_run_is_rejected(client, app, workspace):
    with app.app_context():
        ws = db.session.get(Workspace, workspace)
        ws.enabled_plugins = ["alive"]          # screenshot NOT enabled
        db.session.add(Target(workspace_id=workspace, host="a.test", scheme="https"))
        db.session.commit()
    page = client.post("/runs/start",
                       data={"workspace_id": workspace, "module": "screenshot"},
                       follow_redirects=True).data.decode()
    assert "isn&#39;t enabled" in page or "isn't enabled" in page
    with app.app_context():
        assert Run.query.filter_by(workspace_id=workspace, module="screenshot").count() == 0


def test_disabled_parser_import_is_rejected(client, app, workspace):
    with app.app_context():
        db.session.get(Workspace, workspace).enabled_plugins = ["alive"]  # no pac
        db.session.commit()
    page = client.post(f"/workspaces/{workspace}/artifacts",
                       data={"kind": "pac",
                             "content": "function FindProxyForURL(u,h){return 'DIRECT';}"},
                       follow_redirects=True).data.decode()
    assert "isn&#39;t enabled" in page or "isn't enabled" in page


def test_disabled_check_all_is_rejected(client, app, workspace):
    with app.app_context():
        ws = db.session.get(Workspace, workspace)
        ws.enabled_plugins = ["dirsearch"]      # alive NOT enabled
        db.session.add(Target(workspace_id=workspace, host="a.test", scheme="https"))
        db.session.commit()
    page = client.post(f"/workspaces/{workspace}/checkall", follow_redirects=True).data.decode()
    assert "isn&#39;t enabled" in page or "isn't enabled" in page


def test_admin_can_manage_plugins(client, app, workspace):
    client.post(f"/workspaces/{workspace}/settings",
                data={"manage_plugins": "1", "plugins": ["alive", "screenshot"]},
                follow_redirects=True)
    with app.app_context():
        assert set(db.session.get(Workspace, workspace).enabled_plugins) == \
            {"alive", "screenshot"}


def test_disabled_ui_hides_tabs_and_pickers(client, app, workspace):
    with app.app_context():
        ws = db.session.get(Workspace, workspace)
        ws.enabled_plugins = ["alive"]          # only alive
        db.session.commit()
    page = client.get(f"/workspaces/{workspace}").data.decode()
    assert 'data-tab="shots"' not in page       # screenshot tab hidden
    assert "Discover ▶" not in page              # dnsbrute discover card hidden
    assert 'id="fuzz-form"' not in page          # dirsearch fuzzing form hidden
    assert "No parser plugins are enabled" in page   # empty parser picker note


def test_plugins_tab_shows_capabilities_import_and_management(client, workspace):
    page = client.get(f"/workspaces/{workspace}").data.decode()
    assert 'data-pane="plugins"' in page and 'data-tab="plugins"' in page
    # Capability overview lists module + parser names.
    assert "iistilde" in page and "nessus" in page
    # Import form is present…
    assert "Import" in page and 'name="kind"' in page
    # …and the admin management controls.
    assert "Manage — enable / disable plugins" in page


def test_non_owner_operator_cannot_manage(app, workspace):
    with app.app_context():
        op = User(email="operator", is_admin=False)
        op.set_password("pw")
        db.session.add(op)
        db.session.flush()
        db.session.add(WorkspaceMember(workspace_id=workspace, user_id=op.id,
                                       role="operator"))
        db.session.commit()
    c = app.test_client()
    c.post("/login", data={"email": "operator", "password": "pw"})
    # An operator (not owner, not admin) may not change plugins.
    assert c.post(f"/workspaces/{workspace}/settings",
                  data={"manage_plugins": "1", "plugins": ["alive"]}).status_code == 403
