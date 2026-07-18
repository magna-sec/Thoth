"""Lock-ins for bugs already fixed, so they can't silently return."""
from sqlalchemy import inspect

from app.extensions import db
from app.models import Finding, Run, Target, User


def test_verbose_default_on_when_form_omits_it(client, app, workspace, target, small_wordlist):
    # Subdomain-button style form: no cfg_verbose, no cfg__bools -> module default (True).
    client.post("/runs/start",
                data={"workspace_id": workspace, "target_id": target, "module": "dirsearch",
                      "cfg_wordlist_dir": small_wordlist, "cfg_recursion_depth": "1"},
                follow_redirects=True)
    with app.app_context():
        run = Run.query.filter_by(workspace_id=workspace, module="dirsearch").first()
        assert "verbose" not in (run.config_json or {})   # unset -> default
        assert run.log and "Starting" in run.log          # verbose actually ran


def test_run_detail_shows_scope_and_operator(client, app, workspace):
    with app.app_context():
        magna = User.query.filter_by(email="magna").first().id
        t = Target(workspace_id=workspace, host="scope.test", scheme="https")
        db.session.add(t)
        db.session.flush()
        run = Run(workspace_id=workspace, module="dirsearch", status="done",
                  created_by=magna, config_json={"_targets": [t.id]})
        db.session.add(run)
        db.session.commit()
        rid = run.id
    page = client.get(f"/workspaces/{workspace}/runs/{rid}").data.decode()
    assert "Ran against" in page and "scope.test" in page and "magna" in page


def test_empty_dirsearch_shows_dedup_explainer(client, app, workspace, target, small_wordlist):
    def start():
        client.post("/runs/start",
                    data={"workspace_id": workspace, "target_id": target, "module": "dirsearch",
                          "cfg_wordlist_dir": small_wordlist, "cfg_recursion_depth": "1"},
                    follow_redirects=True)
    start()
    start()  # second run is fully deduped -> 0 findings
    with app.app_context():
        rid = Run.query.filter_by(workspace_id=workspace, module="dirsearch") \
            .order_by(Run.id.desc()).first().id
        assert Finding.query.filter_by(run_id=rid).count() == 0
    page = client.get(f"/workspaces/{workspace}/runs/{rid}").data.decode()
    assert "No results" in page and "already tested by an earlier task" in page


def test_model_columns_present(app):
    with app.app_context():
        insp = inspect(db.engine)
        tcols = {c["name"] for c in insp.get_columns("targets")}
        assert {"last_waf", "last_server", "last_title", "last_alive_at"} <= tcols
        rcols = {c["name"] for c in insp.get_columns("runs")}
        assert {"log", "progress_done", "progress_total"} <= rcols
        wcols = {c["name"] for c in insp.get_columns("workspaces")}
        assert "proxy" in wcols
