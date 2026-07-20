"""Celery tasks. Runs a module across all targets in a workspace."""
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from .extensions import celery, db
from .modules import get_module
from .modules.base import RunContext, TaskCancelled
from .models import Run, Target
from .realtime import publish

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def dispatch(run_id):
    """Start a task without blocking the web request.

    With a real broker (Docker), hand off to a Celery worker. Locally (no broker), spawn
    a SEPARATE PROCESS (python -m app.runtask) so the scan's threads/CPU don't contend
    with the web server's GIL — that's what made the UI drag during a dirsearch. The child
    shares the DB (SQLite WAL) so findings/progress stream back live.
    """
    if celery.conf.task_always_eager:
        proc = subprocess.Popen([sys.executable, "-m", "app.runtask", str(run_id)],
                                cwd=str(_PROJECT_ROOT))
        # Recorded only so a wedged run can be force-killed; stopping is normally
        # cooperative and doesn't need it.
        run = db.session.get(Run, run_id)
        if run is not None:
            run.pid = proc.pid
            db.session.commit()
    else:
        run_module_task.delay(run_id)


@celery.task(name="thoth.run_module")
def run_module_task(run_id):
    run = db.session.get(Run, run_id)
    if run is None:
        return
    module = get_module(run.module)
    if module is None:
        run.status = "error"
        run.error = f"Unknown module: {run.module}"
        db.session.commit()
        return

    if run.cancel_requested:  # stopped while still queued — never start the work
        run.status = "cancelled"
        run.finished_at = datetime.utcnow()
        db.session.commit()
        publish(run.workspace_id, {"type": "run_status", "run_id": run.id,
                                   "status": "cancelled"})
        return

    run.status = "running"
    run.started_at = datetime.utcnow()
    db.session.commit()
    workspace_id = run.workspace_id
    publish(workspace_id, {"type": "run_status", "run_id": run.id, "status": "running"})

    ctx = RunContext(run)
    q = Target.query.filter_by(workspace_id=workspace_id)
    only = (run.config_json or {}).get("_targets")
    if only:
        q = q.filter(Target.id.in_(only))
    targets = q.all()

    # Scope is enforced here, once, rather than trusting each module to remember. Anything
    # outside the engagement is dropped before a single request is made, and the run says
    # so in its log rather than silently doing less than asked.
    if ctx.scope.restricted or ctx.scope.deny:
        allowed = [t for t in targets if ctx.scope.allows(t.host)]
        blocked = [t for t in targets if t not in allowed]
        if blocked:
            ctx.log(f"Scope: skipping {len(blocked)} out-of-scope host(s) — "
                    + ", ".join(sorted(t.host for t in blocked)[:10])
                    + (" …" if len(blocked) > 10 else ""))
        targets = allowed
        if not targets and blocked:
            ctx.log("Nothing in scope to run against.")
    try:
        cfg = run.config_json or {}
        if module.supports_batch:
            module.run_all(targets, cfg, ctx)
        else:
            # Coarse per-target progress for modules that don't report their own.
            if not module.reports_progress:
                ctx.set_progress(0, len(targets))
            for i, target in enumerate(targets):
                module.run(target, cfg, ctx)
                if not module.reports_progress:
                    ctx.set_progress(i + 1, len(targets))
        run.finished_at = datetime.utcnow()
        run.status = "done"
        db.session.commit()
        status = "done"
    except TaskCancelled:
        # Not a failure: the operator asked to stop. Whatever was already committed
        # stands, including the dedup ledger, so a re-run picks up where this left off.
        db.session.rollback()
        run = db.session.get(Run, run_id)
        run.status = status = "cancelled"
        run.finished_at = datetime.utcnow()
        run.log = (run.log or "") + f"{datetime.utcnow():%H:%M:%S} Stopped by operator.\n"
        db.session.commit()
    except Exception as e:  # noqa: BLE001 - surface any module failure to the UI
        # Roll back the poisoned transaction, then record the failure on a clean session.
        db.session.rollback()
        run = db.session.get(Run, run_id)
        run.status = status = "error"
        run.error = f"{type(e).__name__}: {e}"
        run.finished_at = datetime.utcnow()
        db.session.commit()
    publish(workspace_id, {"type": "run_status", "run_id": run_id, "status": status})
