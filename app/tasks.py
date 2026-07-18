"""Celery tasks. Runs a module across all targets in a workspace."""
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from .extensions import celery, db
from .modules import get_module
from .modules.base import RunContext
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
        subprocess.Popen([sys.executable, "-m", "app.runtask", str(run_id)],
                         cwd=str(_PROJECT_ROOT))
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
    except Exception as e:  # noqa: BLE001 - surface any module failure to the UI
        # Roll back the poisoned transaction, then record the failure on a clean session.
        db.session.rollback()
        run = db.session.get(Run, run_id)
        run.status = status = "error"
        run.error = f"{type(e).__name__}: {e}"
        run.finished_at = datetime.utcnow()
        db.session.commit()
    publish(workspace_id, {"type": "run_status", "run_id": run_id, "status": status})
