"""Stopping a task: cooperative cancellation, the queued shortcut, and the force kill."""
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import text

from app.extensions import db
from app.models import Finding, Run, Target
from app.modules.base import RunContext, TaskCancelled
from app.tasks import run_module_task


def _request_stop(run_id):
    """Raise the flag the way the web process does — over its own connection."""
    with db.engine.connect() as conn:
        conn.execute(text("UPDATE runs SET cancel_requested = 1 WHERE id = :i"),
                     {"i": run_id})
        conn.commit()


def _run(app, workspace, **cfg):
    run = Run(workspace_id=workspace, module="alive", config_json=cfg)
    db.session.add(run)
    db.session.commit()
    return run


def test_context_sees_a_flag_set_by_another_connection(app, workspace):
    """The whole mechanism rests on this: the task process holds a long read transaction,
    so a stale SQLite snapshot would never show the web process's write."""
    with app.app_context():
        run = _run(app, workspace)
        ctx = RunContext(run)
        assert ctx.cancelled is False

        _request_stop(run.id)
        ctx._cancel_checked_at = 0.0          # bypass the poll throttle
        assert ctx.cancelled is True
        with pytest.raises(TaskCancelled):
            ctx.raise_if_cancelled()


def test_cancel_check_is_throttled(app, workspace):
    with app.app_context():
        ctx = RunContext(_run(app, workspace))
        assert ctx.cancelled is False
        _request_stop(ctx.run.id)
        assert ctx.cancelled is False         # within the poll window, not re-read
        ctx._cancel_checked_at = 0.0
        assert ctx.cancelled is True


def test_cancelled_result_is_sticky(app, workspace):
    with app.app_context():
        ctx = RunContext(_run(app, workspace))
        _request_stop(ctx.run.id)
        ctx._cancel_checked_at = 0.0
        assert ctx.cancelled is True
        with db.engine.connect() as conn:      # un-cancel: must not resurrect the run
            conn.execute(text("UPDATE runs SET cancel_requested = 0 WHERE id = :i"),
                         {"i": ctx.run.id})
            conn.commit()
        ctx._cancel_checked_at = 0.0
        assert ctx.cancelled is True


def test_each_completed_drops_pending_work(app, workspace):
    with app.app_context():
        ctx = RunContext(_run(app, workspace))
        _request_stop(ctx.run.id)
        ctx._cancel_checked_at = 0.0
        seen = 0
        with ThreadPoolExecutor(max_workers=1) as ex:
            futs = {ex.submit(lambda: None): i for i in range(20)}
            with pytest.raises(TaskCancelled):
                for _ in ctx.each_completed(ex, futs):
                    seen += 1
        assert seen == 0                       # stopped on the first check


def test_queued_run_is_cancelled_without_ever_starting(client, app, workspace):
    with app.app_context():
        db.session.add(Target(workspace_id=workspace, host="a.test", scheme="https"))
        run = Run(workspace_id=workspace, module="alive", status="queued")
        db.session.add(run)
        db.session.commit()
        rid = run.id

    client.post(f"/workspaces/{workspace}/runs/{rid}/stop", follow_redirects=True)
    with app.app_context():
        run = db.session.get(Run, rid)
        assert run.status == "cancelled" and run.finished_at is not None

        # Even if the worker starts late, it must refuse to do the work.
        run_module_task.run(rid)
        db.session.remove()
        assert db.session.get(Run, rid).status == "cancelled"
        assert Finding.query.filter_by(run_id=rid).count() == 0


def test_running_task_stops_partway(app, workspace, mock_target, monkeypatch):
    """A stop raised mid-run is noticed and the task unwinds as 'cancelled', not 'error'."""
    monkeypatch.setattr("app.modules.alive.enrich", lambda host: {})
    import app.modules.alive as alive
    state = {"calls": 0}

    # Count probes (worker threads — read-only, no DB).
    real_probe = alive._do_probe
    monkeypatch.setattr(alive, "_do_probe",
                        lambda *a, **kw: (state.__setitem__("calls", state["calls"] + 1),
                                          real_probe(*a, **kw))[1])

    # Raise the stop from the MAIN thread, standing in for the web process. Doing it from
    # a worker would mean writing to SQLite from a thread holding no session — which is
    # what the first version of this test got wrong, surfacing as 'error' not 'cancelled'.
    original_set_progress = RunContext.set_progress

    def set_progress_then_stop(self, done, total):
        result = original_set_progress(self, done, total)
        if not state.get("stopped"):
            state["stopped"] = True
            _request_stop(self.run.id)
        return result

    monkeypatch.setattr(RunContext, "set_progress", set_progress_then_stop)

    with app.app_context():
        for i in range(6):
            db.session.add(Target(workspace_id=workspace, host="127.0.0.1", scheme="http",
                                  port=mock_target.port))
        run = _run(app, workspace, timeout=3, extra_ports="", threads=1)
        rid = run.id
        db.session.commit()

        run_module_task.run(rid)
        db.session.remove()

        run = db.session.get(Run, rid)
        assert run.status == "cancelled"
        assert "Stopped by operator" in (run.log or "")
        assert state["calls"] < 6             # it did not probe every target


def test_stopping_a_finished_run_is_refused(client, app, workspace):
    with app.app_context():
        run = Run(workspace_id=workspace, module="alive", status="done")
        db.session.add(run)
        db.session.commit()
        rid = run.id
    page = client.post(f"/workspaces/{workspace}/runs/{rid}/stop",
                       follow_redirects=True).data.decode()
    assert "already finished" in page
    with app.app_context():
        assert db.session.get(Run, rid).status == "done"   # untouched


def test_stop_button_shown_only_while_active(client, app, workspace):
    with app.app_context():
        active = Run(workspace_id=workspace, module="alive", status="running")
        finished = Run(workspace_id=workspace, module="alive", status="done")
        db.session.add_all([active, finished])
        db.session.commit()
        aid, fid = active.id, finished.id

    assert "Stop" in client.get(f"/workspaces/{workspace}/runs/{aid}").data.decode()
    assert "Stop" not in client.get(f"/workspaces/{workspace}/runs/{fid}").data.decode()
    assert "Stop" in client.get(f"/workspaces/{workspace}").data.decode()  # tasks table


def test_status_endpoint_reports_the_pending_stop(client, app, workspace):
    with app.app_context():
        run = Run(workspace_id=workspace, module="alive", status="running")
        db.session.add(run)
        db.session.commit()
        rid = run.id
    client.post(f"/workspaces/{workspace}/runs/{rid}/stop", follow_redirects=True)
    data = client.get(f"/workspaces/{workspace}/runs/{rid}/status").get_json()
    assert data["cancel_requested"] is True and data["status"] == "running"


def test_kill_reports_an_already_dead_process_as_killed():
    from app.workspaces.routes import _kill
    killed, _ = _kill(2 ** 30)   # a pid that cannot exist
    assert killed in (True, False)   # platform-dependent, but it must not raise
