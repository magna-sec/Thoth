"""DNS brute force: wildcard suppression, permutations, dedup, and scope enforcement."""
from app.extensions import db
from app.models import Finding, Run, Target, TestedName, Workspace
from app.modules.dnsbrute import _domains, permutations
from app.tasks import run_module_task

# A tiny fake DNS zone the module resolves against instead of the network.
ZONE = {
    "api.acme.test": {"10.0.0.1"},
    "dev.acme.test": {"10.0.0.2"},
    "api-dev.acme.test": {"10.0.0.3"},   # only reachable via permutations
}


def fake_resolve(zone, wildcard=None):
    def _resolve(name, resolver, timeout=3.0):
        if name in zone:
            return frozenset(zone[name])
        return frozenset(wildcard or ())
    return _resolve


def _run(app, workspace, config, monkeypatch, zone=ZONE, wildcard=None):
    monkeypatch.setattr("app.modules.dnsbrute.resolve", fake_resolve(zone, wildcard))
    monkeypatch.setattr("app.modules.dnsbrute.load_words",
                        lambda _p: ["api", "dev", "nope", "missing"])
    with app.app_context():
        run = Run(workspace_id=workspace, module="dnsbrute", config_json=config)
        db.session.add(run)
        db.session.commit()
        rid = run.id
        run_module_task.run(rid)
        db.session.remove()
        return rid


def test_permutations_from_known_labels():
    out = permutations(["api"])
    assert "api-dev" in out and "dev-api" in out and "api2" in out
    assert "api-api" not in out          # never permute a label with itself


def test_domains_inferred_from_existing_hosts():
    assert _domains(None, {"a.acme.test", "b.acme.test"}) == ["acme.test"]
    assert _domains("Example.COM, foo.test", set()) == ["example.com", "foo.test"]
    assert _domains(None, set()) == []


def test_discovers_and_adds_targets(app, workspace, monkeypatch):
    rid = _run(app, workspace, {"domain": "acme.test", "permutations": False}, monkeypatch)
    with app.app_context():
        hosts = {t.host for t in Target.query.filter_by(workspace_id=workspace).all()}
        assert hosts == {"api.acme.test", "dev.acme.test"}
        assert Finding.query.filter_by(run_id=rid).count() == 2
        assert db.session.get(Target, 1).ip in {"10.0.0.1", "10.0.0.2"}
        # Every label tried is recorded, hit or miss.
        assert TestedName.query.filter_by(workspace_id=workspace).count() == 4


def test_wildcard_answers_are_suppressed(app, workspace, monkeypatch):
    """A wildcard zone answers everything; without detection every label 'exists'."""
    rid = _run(app, workspace, {"domain": "acme.test", "permutations": False},
               monkeypatch, wildcard={"10.9.9.9"})
    with app.app_context():
        hosts = {t.host for t in Target.query.filter_by(workspace_id=workspace).all()}
        assert hosts == {"api.acme.test", "dev.acme.test"}   # not "nope"/"missing"
        assert "wildcard DNS detected" in (db.session.get(Run, rid).log or "")


def test_permutations_find_neighbours_of_known_hosts(app, workspace, monkeypatch):
    with app.app_context():
        db.session.add(Target(workspace_id=workspace, host="api.acme.test", scheme="https"))
        db.session.commit()
    _run(app, workspace, {"domain": "acme.test", "permutations": True}, monkeypatch)
    with app.app_context():
        hosts = {t.host for t in Target.query.filter_by(workspace_id=workspace).all()}
        assert "api-dev.acme.test" in hosts   # only reachable by permuting "api"


def test_dedup_skips_tried_labels_until_forced(app, workspace, monkeypatch):
    _run(app, workspace, {"domain": "acme.test", "permutations": False}, monkeypatch)
    with app.app_context():
        before = TestedName.query.filter_by(workspace_id=workspace).count()

    rid = _run(app, workspace, {"domain": "acme.test", "permutations": False}, monkeypatch)
    with app.app_context():
        assert "already-tried" in (db.session.get(Run, rid).log or "")
        assert TestedName.query.filter_by(workspace_id=workspace).count() == before
        assert Finding.query.filter_by(run_id=rid).count() == 0   # nothing new to do


def test_discovered_hosts_respect_scope(app, workspace, monkeypatch):
    with app.app_context():
        db.session.get(Workspace, workspace).scope = "api.acme.test"
        db.session.commit()
    rid = _run(app, workspace, {"domain": "acme.test", "permutations": False}, monkeypatch)
    with app.app_context():
        hosts = {t.host for t in Target.query.filter_by(workspace_id=workspace).all()}
        assert hosts == {"api.acme.test"}          # dev.acme.test resolved but was dropped
        assert "Scope: ignoring discovered dev.acme.test" in db.session.get(Run, rid).log


def test_no_domain_is_reported_not_crashed(app, workspace, monkeypatch):
    rid = _run(app, workspace, {"permutations": False}, monkeypatch)
    with app.app_context():
        run = db.session.get(Run, rid)
        assert run.status == "done"
        assert "No root domain" in (run.log or "")


def test_discovery_can_start_on_an_empty_workspace(client, app, workspace, monkeypatch):
    """needs_targets=False — discovery must not be blocked by 'add subdomains first'."""
    monkeypatch.setattr("app.modules.dnsbrute.resolve", fake_resolve({}))
    client.post("/runs/start", data={"workspace_id": workspace, "module": "dnsbrute",
                                     "cfg_domain": "acme.test"}, follow_redirects=True)
    with app.app_context():
        assert Run.query.filter_by(workspace_id=workspace, module="dnsbrute").count() == 1
