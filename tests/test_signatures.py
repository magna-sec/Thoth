"""Operator-added fingerprint signatures: matching, management routes, and access."""
import types

from app.extensions import db
from app.models import Signature, Target, User
from app.modules.alive import _fingerprint, load_signatures


def _resp(headers=None, text="", cookies=()):
    return types.SimpleNamespace(headers=headers or {}, text=text,
                                 cookies=types.SimpleNamespace(keys=lambda: list(cookies)))


def test_builtin_salesforce_signatures():
    assert "Salesforce" in _fingerprint(_resp(cookies=["BrowserId"]))
    assert "Salesforce" in _fingerprint(_resp(text="<script>/sfdcPage/x.js</script>"))
    assert "Salesforce" in _fingerprint(_resp(text="<a href='https://x.force.com/'>"))
    assert "Shopify" in _fingerprint(_resp(headers={"X-Shopify-Stage": "production"}))


def test_custom_signature_matches_each_field():
    cases = [
        (("body", "acmecorp-portal", "AcmePortal"), _resp(text="<div id=acmecorp-portal>")),
        (("header", "x-acme-node", "AcmePortal"), _resp(headers={"X-Acme-Node": "7"})),
        (("server", "acmehttpd", "AcmePortal"), _resp(headers={"Server": "AcmeHTTPd/2"})),
        (("powered_by", "acme-rt", "AcmePortal"), _resp(headers={"X-Powered-By": "Acme-RT"})),
        (("cookie", "acme_sess", "AcmePortal"), _resp(cookies=["ACME_SESS_1"])),
    ]
    for sig, resp in cases:
        assert "AcmePortal" in _fingerprint(resp, [sig]), sig


def test_custom_signatures_do_not_displace_builtins():
    found = _fingerprint(_resp(headers={"Server": "nginx"}, text="<div data-reactroot>"),
                         [("server", "nginx", "Our Edge")])
    assert "nginx" in found and "React" in found and "Our Edge" in found


def test_labels_are_not_duplicated():
    # Two rules for the same platform, both matching, still yield one chip.
    found = _fingerprint(_resp(headers={"Server": "acme"}, text="acme-portal"),
                         [("server", "acme", "Acme"), ("body", "acme-portal", "Acme")])
    assert found.count("Acme") == 1


def test_load_signatures_returns_tuples(app):
    with app.app_context():
        db.session.add(Signature(label="Salesforce", field="body", needle="force.com"))
        db.session.commit()
        assert ("body", "force.com", "Salesforce") in load_signatures()


def test_add_signature_route(client, app):
    client.post("/fingerprints/add",
                data={"label": "Salesforce", "field": "cookie", "needle": "sid_Client",
                      "notes": "seen on the partner portal"}, follow_redirects=True)
    with app.app_context():
        s = Signature.query.one()
        assert (s.label, s.field, s.needle) == ("Salesforce", "cookie", "sid_Client")


def test_add_signature_validation(client, app):
    bad = [
        {"label": "", "field": "body", "needle": "something"},        # no label
        {"label": "X", "field": "body", "needle": ""},                # no needle
        {"label": "X", "field": "nonsense", "needle": "something"},   # bad field
        {"label": "X", "field": "body", "needle": "ab"},              # too short to be useful
    ]
    for data in bad:
        client.post("/fingerprints/add", data=data, follow_redirects=True)
    with app.app_context():
        assert Signature.query.count() == 0


def test_duplicate_signature_is_rejected(client, app):
    data = {"label": "Salesforce", "field": "body", "needle": "force.com"}
    client.post("/fingerprints/add", data=data, follow_redirects=True)
    page = client.post("/fingerprints/add", data=data, follow_redirects=True).data.decode()
    assert "already exists" in page
    with app.app_context():
        assert Signature.query.count() == 1


def test_index_lists_custom_and_builtin(client, app):
    with app.app_context():
        db.session.add(Signature(label="AcmePortal", field="body", needle="acme-portal"))
        db.session.commit()
    page = client.get("/fingerprints/").data.decode()
    assert "AcmePortal" in page and "acme-portal" in page
    assert "WordPress" in page  # built-ins are shown too, so nobody re-adds them


def test_delete_is_admin_only(client, app):
    with app.app_context():
        db.session.add(Signature(label="Acme", field="body", needle="acme-portal"))
        u = User(email="operator", is_admin=False)
        u.set_password("pw")
        db.session.add(u)
        db.session.commit()
        sid = Signature.query.one().id

    op = app.test_client()
    op.post("/login", data={"email": "operator", "password": "pw"})
    assert op.post(f"/fingerprints/{sid}/delete").status_code == 403
    # ...but an operator can still add, which is the collaborative half.
    op.post("/fingerprints/add", data={"label": "Zed", "field": "body", "needle": "zedzed"},
            follow_redirects=True)
    with app.app_context():
        assert Signature.query.filter_by(label="Zed").count() == 1

    client.post(f"/fingerprints/{sid}/delete", follow_redirects=True)  # client is admin
    with app.app_context():
        assert db.session.get(Signature, sid) is None


def test_add_from_domain_page_returns_there(client, app, workspace):
    with app.app_context():
        t = Target(workspace_id=workspace, host="sf.test", scheme="https")
        db.session.add(t)
        db.session.commit()
        tid = t.id
    back = f"/workspaces/{workspace}/domains/{tid}"
    assert "Add a signature" in client.get("/fingerprints/").data.decode()
    page = client.get(back).data.decode()
    assert "Tag host" in page        # per-host manual tag
    assert "Add signature" in page   # ...and the global-rule form beside it

    resp = client.post("/fingerprints/add",
                       data={"label": "Salesforce", "field": "body", "needle": "force.com",
                             "next": back})
    assert resp.headers["Location"].endswith(back)


def test_manual_tag_added_and_removed(client, app, workspace):
    with app.app_context():
        t = Target(workspace_id=workspace, host="sf.test", scheme="https")
        db.session.add(t)
        db.session.commit()
        tid = t.id
    base = f"/workspaces/{workspace}/domains/{tid}"

    client.post(f"{base}/fingerprint", data={"labels": "Salesforce, Okta"},
                follow_redirects=True)
    with app.app_context():
        assert db.session.get(Target, tid).manual_tech_list == ["Salesforce", "Okta"]
    assert "Salesforce" in client.get(base).data.decode()

    client.post(f"{base}/fingerprint/remove", data={"label": "Okta"}, follow_redirects=True)
    with app.app_context():
        assert db.session.get(Target, tid).manual_tech_list == ["Salesforce"]


def test_manual_tag_survives_an_alive_run(app, workspace, mock_target, monkeypatch):
    """The whole point of a separate column: a re-scan must not wipe a hand-added tag."""
    monkeypatch.setattr("app.modules.alive.enrich", lambda host: {})
    from app.models import Run
    from app.tasks import run_module_task
    with app.app_context():
        t = Target(workspace_id=workspace, host="127.0.0.1", scheme="http",
                   port=mock_target.port)
        t.add_manual_tech(["Salesforce"])
        run = Run(workspace_id=workspace, module="alive",
                  config_json={"timeout": 3, "extra_ports": ""})
        db.session.add_all([t, run])
        db.session.commit()
        tid, rid = t.id, run.id
        run_module_task.run(rid)
        db.session.remove()
        assert db.session.get(Target, tid).manual_tech_list == ["Salesforce"]


def test_manual_tags_are_deduped_and_counted_in_analysis(client, app, workspace):
    with app.app_context():
        t = Target(workspace_id=workspace, host="sf.test", scheme="https")
        db.session.add(t)
        db.session.commit()
        tid = t.id
    base = f"/workspaces/{workspace}/domains/{tid}"
    client.post(f"{base}/fingerprint", data={"labels": "Salesforce"}, follow_redirects=True)
    page = client.post(f"{base}/fingerprint", data={"labels": "salesforce"},
                       follow_redirects=True).data.decode()
    assert "Already tagged" in page
    with app.app_context():
        assert db.session.get(Target, tid).manual_tech_list == ["Salesforce"]
    # Hand-tagged tech counts in the workspace Analysis alongside detected tech.
    assert "Salesforce" in client.get(f"/workspaces/{workspace}").data.decode()


def test_tagged_host_is_visible_and_filterable_on_the_workspace_page(client, app,
                                                                     workspace):
    """A hand-tagged fingerprint has to show on the card AND be reachable by the filters —
    it was stored correctly but invisible and unsearchable from the Subdomains tab."""
    with app.app_context():
        t = Target(workspace_id=workspace, host="sf.test", scheme="https",
                   last_alive=True, last_tech="nginx")
        t.add_manual_tech(["Salesforce"])
        db.session.add(t)
        db.session.commit()

    page = client.get(f"/workspaces/{workspace}").data.decode()
    assert "dc-tags" in page                       # the card renders a tag row...
    assert "Salesforce" in page                    # ...containing the hand-added label
    assert 'id="filter-tech"' in page              # ...and a tech filter exists
    assert '<option value="salesforce">' in page   # ...offering it, from the Analysis tally
    assert 'value="nginx"' in page                 # detected tech is offered too


def test_check_domain_returns_tech_and_tags(client, app, workspace, mock_target):
    """The live re-check rewrites the card in place, so it must return the labels back."""
    with app.app_context():
        t = Target(workspace_id=workspace, host="127.0.0.1", scheme="http",
                   port=mock_target.port)
        t.add_manual_tech(["Salesforce"])
        db.session.add(t)
        db.session.commit()
        tid = t.id
    data = client.post(f"/workspaces/{workspace}/domains/{tid}/check").get_json()
    assert data["tags"] == ["Salesforce"]
    assert isinstance(data["tech"], list)


def test_custom_signature_reaches_a_real_probe(app, workspace, mock_target):
    """End to end: a rule added in the UI shows up as tech on the next check."""
    from app.modules.alive import probe
    mock_target.routes["/"] = (200, b"<html><body>acme-portal here</body></html>", {})
    with app.app_context():
        db.session.add(Signature(label="AcmePortal", field="body", needle="acme-portal"))
        t = Target(workspace_id=workspace, host="127.0.0.1", scheme="http",
                   port=mock_target.port)
        db.session.add(t)
        db.session.commit()
        res = probe(t, timeout=3, extra_ports=())
        assert "AcmePortal" in res["extra"]["tech"]
        assert "AcmePortal" in t.last_tech
