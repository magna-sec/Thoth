"""Start and view module runs."""
from flask import Blueprint, abort, flash, redirect, request, url_for
from flask_login import current_user, login_required

from ..extensions import db
from ..models import Run, Target, Workspace
from ..modules import get_module
from ..tasks import dispatch

runs_bp = Blueprint("runs", __name__, url_prefix="/runs")


def _require_member(workspace_id):
    # Any authenticated user may run tasks in a shared workspace.
    ws = db.session.get(Workspace, workspace_id)
    if ws is None:
        abort(404)
    return ws


def launch_run(ws, module_name, config, target_ids=None):
    """Create + enqueue a Run. target_ids limits it to specific subdomains."""
    if target_ids:
        config = dict(config, _targets=list(target_ids))
    run = Run(workspace_id=ws.id, module=module_name, config_json=config,
              status="queued", created_by=current_user.id)
    db.session.add(run)
    db.session.commit()
    dispatch(run.id)
    return run


@runs_bp.route("/start", methods=["POST"])
@login_required
def start():
    workspace_id = request.form.get("workspace_id", type=int)
    ws = _require_member(workspace_id)
    module_name = request.form.get("module", "")
    module = get_module(module_name)
    if module is None:
        abort(400, "Unknown module")
    if not ws.plugin_enabled(module_name):
        flash(f"The '{module_name}' module isn't enabled for this workspace.", "error")
        return redirect(url_for("workspaces.detail", workspace_id=ws.id))
    # Discovery modules create targets, so they must be allowed to run without any.
    if module.needs_targets and not Target.query.filter_by(workspace_id=ws.id).count():
        flash("Add subdomains before running a module — or run discovery to find some.",
              "error")
        return redirect(url_for("workspaces.detail", workspace_id=ws.id))

    # Build config from the module's declared schema. Only override a bool when the form
    # actually manages it (listed in cfg__bools) — otherwise a minimal form (e.g. the
    # subdomain "Fuzz directories" button) would wrongly force every checkbox to False.
    managed_bools = set(filter(None, request.form.get("cfg__bools", "").split(",")))
    config = {}
    for field in module.config_schema():
        key = field["name"]
        raw = request.form.get(f"cfg_{key}")
        if field["type"] == "bool":
            if key in managed_bools:
                config[key] = raw is not None
            # else: leave unset so the module's own default applies
        elif field["type"] == "number" and raw not in (None, ""):
            config[key] = float(raw)
        elif raw not in (None, ""):
            config[key] = raw

    # Single target (subdomain page) or a multiselect (Directory Fuzzing tab).
    target_id = request.form.get("target_id", type=int)
    target_ids = request.form.getlist("target_ids", type=int) or None
    if target_id and not target_ids:
        target_ids = [target_id]

    if target_ids is not None and len(target_ids) == 0:
        flash("Select at least one subdomain.", "error")
        return redirect(url_for("workspaces.detail", workspace_id=ws.id) + "#fuzz")

    run = launch_run(ws, module_name, config, target_ids)
    flash(f"Started {module_name} task #{run.id}"
          + (f" on {len(target_ids)} subdomain(s)" if target_ids else ""), "info")

    if target_id and len(target_ids or []) == 1:
        return redirect(url_for("workspaces.domain_detail", workspace_id=ws.id,
                                target_id=target_id))
    anchor = {"dirsearch": "#fuzz", "screenshot": "#shots",
              "dnsbrute": "#domains"}.get(module_name, "#findings")
    return redirect(url_for("workspaces.detail", workspace_id=ws.id) + anchor)
