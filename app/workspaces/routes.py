"""Workspace CRUD, target import, live findings stream, and wipe."""
import json
import re
import shutil
import socket
import threading
import time
from collections import Counter
from datetime import datetime
from urllib.parse import urlparse

import requests

from flask import (Blueprint, Response, abort, current_app, flash, jsonify,
                   redirect, render_template, request, send_from_directory,
                   stream_with_context, url_for)
from flask_login import current_user, login_required
from sqlalchemy import func

from ..auth import admin_required
from ..extensions import db
from ..importers import ImportError_, ledger_key, parse_dirsearch
from ..models import (Finding, Note, Run, Target, TestedPath, User, Workspace,
                      WorkspaceMember)
from ..modules import all_modules, get_module
from ..modules.alive import probe
from ..modules.base import to_proxies
from ..modules.screenshot import screenshot_dir
from ..realtime import publish, subscribe
from ..urlinsights import analyse as analyse_urls
from ..urlinsights import build_tree

DIRSEARCH_IMPORT = "dirsearch-import"  # Run.module for pasted results (not a live module)

ws_bp = Blueprint("workspaces", __name__, url_prefix="/workspaces")


def _get_member_workspace(workspace_id):
    # Workspaces are shared across the team; any authenticated user can work in one.
    # Structural actions (create / wipe / user management) are admin-only (see decorators).
    ws = db.session.get(Workspace, workspace_id)
    if ws is None:
        abort(404)
    return ws


@ws_bp.route("/")
@login_required
def list_workspaces():
    workspaces = Workspace.query.order_by(Workspace.created_at.desc()).all()
    return render_template("workspaces/list.html", workspaces=workspaces)


@ws_bp.route("/new", methods=["POST"])
@admin_required
def create_workspace():
    name = request.form.get("name", "").strip()
    if not name:
        flash("Workspace name required", "error")
        return redirect(url_for("workspaces.list_workspaces"))
    ws = Workspace(name=name, client=request.form.get("client", "").strip(),
                   created_by=current_user.id)
    db.session.add(ws)
    db.session.flush()
    db.session.add(WorkspaceMember(workspace_id=ws.id, user_id=current_user.id,
                                   role="owner"))
    db.session.commit()
    return redirect(url_for("workspaces.detail", workspace_id=ws.id))


@ws_bp.route("/<int:workspace_id>")
@login_required
def detail(workspace_id):
    ws = _get_member_workspace(workspace_id)
    findings = (Finding.query.filter_by(workspace_id=ws.id)
                .order_by(Finding.found_at.desc()).limit(500).all())
    runs = Run.query.filter_by(workspace_id=ws.id).order_by(Run.created_at.desc()).all()
    stats = _stats(ws)
    domains = sorted(ws.targets, key=lambda t: t.host)
    mod_runs = _module_runs(ws.id)
    status_dist = _status_distribution(ws.id)
    analysis = _analysis(ws.id)
    run_counts = dict(db.session.query(Finding.run_id, func.count(Finding.id))
                      .filter(Finding.workspace_id == ws.id)
                      .group_by(Finding.run_id).all())
    host_by_id = dict(db.session.query(Target.id, Target.host)
                      .filter_by(workspace_id=ws.id).all())
    user_by_id = dict(db.session.query(User.id, User.email).all())
    run_scope = {r.id: _run_scope_hosts(r, host_by_id) for r in runs}
    fuzz_cov = {host: {"paths": npaths, "words": nwords}
                for host, npaths, nwords in db.session.query(
                    TestedPath.host, func.count(func.distinct(TestedPath.parent_path)),
                    func.count(TestedPath.word))
                .filter_by(workspace_id=ws.id).group_by(TestedPath.host).all()}
    return render_template("workspaces/detail.html", ws=ws, findings=findings,
                           runs=runs, modules=all_modules(), stats=stats,
                           domains=domains, mod_runs=mod_runs, status_dist=status_dist,
                           dicc_count=_default_wordlist_count(), run_counts=run_counts,
                           run_scope=run_scope, user_by_id=user_by_id, fuzz_cov=fuzz_cov,
                           analysis=analysis, shots=_screenshots(ws.id))


def _run_scope_hosts(run, host_by_id):
    """Which subdomains a task targeted: an explicit list, or None meaning all."""
    tids = (run.config_json or {}).get("_targets")
    if not tids:
        return None
    return [host_by_id.get(i, f"#{i}") for i in tids]


@ws_bp.route("/<int:workspace_id>/runs/<int:run_id>")
@login_required
def run_detail(workspace_id, run_id):
    ws = _get_member_workspace(workspace_id)
    run = db.session.get(Run, run_id)
    if run is None or run.workspace_id != ws.id:
        abort(404)
    findings = (Finding.query.filter_by(run_id=run.id)
                .order_by(Finding.status_code, Finding.path).all())
    cfg = {k: v for k, v in (run.config_json or {}).items() if k != "_targets"}
    host_by_id = dict(db.session.query(Target.id, Target.host)
                      .filter_by(workspace_id=ws.id).all())
    scope = _run_scope_hosts(run, host_by_id)
    creator = db.session.get(User, run.created_by) if run.created_by else None
    duration = None
    if run.started_at and run.finished_at:
        duration = round((run.finished_at - run.started_at).total_seconds(), 1)
    return render_template("workspaces/run.html", ws=ws, run=run, findings=findings,
                           config=cfg, scope=scope, scope_all=len(host_by_id),
                           creator=creator, duration=duration,
                           rerunnable=get_module(run.module) is not None)


# ------------------------------------------------------------------ screenshots

_SHOT_NAME_RE = re.compile(r"^t\d+_r\d+\.png$")


@ws_bp.route("/<int:workspace_id>/screenshots/<name>")
@login_required
def screenshot_file(workspace_id, name):
    """Serve a captured PNG. The name pattern is fixed by the screenshot module, so
    anything else is rejected outright rather than path-normalized."""
    _get_member_workspace(workspace_id)
    if not _SHOT_NAME_RE.match(name):
        abort(404)
    directory = screenshot_dir(workspace_id)
    if not (directory / name).exists():
        abort(404)
    return send_from_directory(directory, name, mimetype="image/png")


def _screenshots(workspace_id):
    """Latest screenshot per target: target_id -> {name, taken_at, run_id, error, ...}."""
    rows = (db.session.query(Finding)
            .join(Run, Finding.run_id == Run.id)
            .filter(Finding.workspace_id == workspace_id, Run.module == "screenshot")
            .order_by(Finding.found_at.desc()).all())
    latest = {}
    for f in rows:
        extra = f.extra_json or {}
        if f.target_id in latest or not (extra.get("screenshot")
                                         or extra.get("screenshot_error")):
            continue
        latest[f.target_id] = {
            "name": extra.get("screenshot"),
            "error": extra.get("screenshot_error"),
            "taken_at": f.found_at,
            "run_id": f.run_id,
            "status_code": f.status_code,
            "title": extra.get("title"),
            "bytes": extra.get("bytes"),
        }
    return latest


@ws_bp.route("/<int:workspace_id>/runs/<int:run_id>/rerun", methods=["POST"])
@login_required
def rerun(workspace_id, run_id):
    """Re-launch a task with the same config. For dirsearch, force past the dedup ledger."""
    ws = _get_member_workspace(workspace_id)
    run = db.session.get(Run, run_id)
    if run is None or run.workspace_id != ws.id:
        abort(404)
    if get_module(run.module) is None:  # e.g. an import — there is nothing to re-execute
        flash(f"'{run.module}' tasks can't be re-run.", "error")
        return redirect(url_for("workspaces.run_detail", workspace_id=ws.id, run_id=run.id))
    from ..runs.routes import launch_run
    cfg = dict(run.config_json or {})
    targets = cfg.pop("_targets", None)
    if run.module == "dirsearch":
        cfg["force"] = True
    new = launch_run(ws, run.module, cfg, targets)
    flash(f"Re-running {run.module} as task #{new.id}"
          + (" (force re-scan)" if run.module == "dirsearch" else ""), "info")
    return redirect(url_for("workspaces.run_detail", workspace_id=ws.id, run_id=new.id))


@ws_bp.route("/<int:workspace_id>/clear-ledger", methods=["POST"])
@login_required
def clear_ledger(workspace_id):
    ws = _get_member_workspace(workspace_id)
    n = TestedPath.query.filter_by(workspace_id=ws.id).delete()
    db.session.commit()
    flash(f"Cleared {n} dedup-ledger entr(y/ies) for this workspace.", "info")
    return redirect(url_for("workspaces.detail", workspace_id=ws.id) + "#fuzz")


@ws_bp.route("/<int:workspace_id>/domains/<int:target_id>/clear-ledger", methods=["POST"])
@login_required
def clear_ledger_domain(workspace_id, target_id):
    ws = _get_member_workspace(workspace_id)
    t = db.session.get(Target, target_id)
    if t is None or t.workspace_id != ws.id:
        abort(404)
    n = TestedPath.query.filter_by(workspace_id=ws.id, host=t.host).delete()
    db.session.commit()
    flash(f"Cleared {n} dedup-ledger entr(y/ies) for {t.host}.", "info")
    return redirect(url_for("workspaces.domain_detail", workspace_id=ws.id, target_id=t.id))


@ws_bp.route("/<int:workspace_id>/runs/<int:run_id>/status")
@login_required
def run_status(workspace_id, run_id):
    ws = _get_member_workspace(workspace_id)
    run = db.session.get(Run, run_id)
    if run is None or run.workspace_id != ws.id:
        abort(404)
    return jsonify({
        "status": run.status,
        "log": run.log or "",
        "findings": Finding.query.filter_by(run_id=run.id).count(),
        "progress_done": run.progress_done or 0,
        "progress_total": run.progress_total or 0,
        "progress_pct": run.progress_pct,
    })


def _default_wordlist_count():
    root = current_app.config["WORDLIST_DIR"]
    for name in ("dicc.txt", "common.txt"):
        p = root / name
        if p.exists():
            try:
                with open(p, encoding="utf-8", errors="ignore") as fh:
                    return sum(1 for ln in fh if ln.strip() and not ln.startswith("#"))
            except OSError:
                return 0
    return 0


def _status_distribution(workspace_id):
    """Server-side Analysis data: [(label, count)] over ALL findings, sorted by count."""
    rows = (db.session.query(Finding.status_code, func.count(Finding.id))
            .filter(Finding.workspace_id == workspace_id)
            .group_by(Finding.status_code).all())
    dist = [(str(code) if code is not None else "dead", n) for code, n in rows]
    dist.sort(key=lambda x: -x[1])
    return dist


def _analysis(workspace_id):
    """Aggregate infra intel across subdomains for the Analysis tab."""
    targets = Target.query.filter_by(workspace_id=workspace_id).all()
    waf, country, tech, server = Counter(), Counter(), Counter(), Counter()
    asn = {}
    for t in targets:
        for w in (t.last_waf or "").split(","):
            if w.strip():
                waf[w.strip()] += 1
        # Detected and hand-tagged tech both count — a label an operator confirmed is
        # every bit as true as one a signature matched.
        for x in (t.last_tech or "").split(",") + t.manual_tech_list:
            if x.strip():
                tech[x.strip()] += 1
        if t.last_server:
            server[t.last_server] += 1
        if t.country:
            country[t.country] += 1
        if t.asn:
            d = asn.setdefault((t.asn, t.asn_name or "unknown"),
                               {"hosts": 0, "country": t.country})
            d["hosts"] += 1
    asn_list = sorted(
        ({"asn": a, "name": n, "hosts": d["hosts"], "country": d["country"]}
         for (a, n), d in asn.items()), key=lambda r: -r["hosts"])
    return {
        "total": len(targets),
        "alive": sum(1 for t in targets if t.last_alive),
        "dead": sum(1 for t in targets if t.last_alive is False),
        "unchecked": sum(1 for t in targets if t.last_alive is None),
        "enriched": sum(1 for t in targets if t.asn),
        "waf": waf.most_common(),
        "asn": asn_list,
        "country": country.most_common(),
        "tech": tech.most_common(),
        "server": server.most_common(15),
    }


def _module_runs(workspace_id):
    """target_id -> {module_name: latest_datetime} derived from findings."""
    rows = (db.session.query(Finding.target_id, Run.module, func.max(Finding.found_at))
            .join(Run, Finding.run_id == Run.id)
            .filter(Finding.workspace_id == workspace_id)
            .group_by(Finding.target_id, Run.module).all())
    out = {}
    for target_id, module, latest in rows:
        out.setdefault(target_id, {})[module] = latest
    return out


def _stats(ws):
    # Alive counts distinct subdomains currently marked live (updated by quick checks
    # AND module runs), so "Check all live" is reflected here.
    return {
        "targets": Target.query.filter_by(workspace_id=ws.id).count(),
        "findings": Finding.query.filter_by(workspace_id=ws.id).count(),
        "alive": Target.query.filter_by(workspace_id=ws.id, last_alive=True).count(),
        "waf": Target.query.filter_by(workspace_id=ws.id)
                     .filter(Target.last_waf.isnot(None)).count(),
        "runs": Run.query.filter_by(workspace_id=ws.id).count(),
    }


@ws_bp.route("/<int:workspace_id>/domains", methods=["POST"])
@login_required
def add_targets(workspace_id):
    ws = _get_member_workspace(workspace_id)
    raw = request.form.get("targets", "")
    upload = request.files.get("file")
    if upload and upload.filename:
        raw += "\n" + upload.read().decode("utf-8", errors="ignore")

    # Normalize: lowercase host -> unique against the current set -> sorted insert.
    existing = {(t.host, t.scheme, t.port) for t in ws.targets}
    parsed = set()
    for line in raw.splitlines():
        host, scheme, port = _parse_target(line)
        if host:
            parsed.add((host, scheme, port))
    new = sorted(parsed - existing)
    for host, scheme, port in new:
        db.session.add(Target(workspace_id=ws.id, host=host, scheme=scheme, port=port))
    db.session.commit()
    flash(f"Added {len(new)} subdomain(s)", "info")
    return redirect(url_for("workspaces.detail", workspace_id=ws.id) + "#domains")


def _parse_target(line):
    line = line.strip().lower()
    if not line:
        return None, None, None
    if "://" not in line:
        line = "https://" + line
    p = urlparse(line)
    return p.hostname, (p.scheme or "https"), p.port


MAX_PATHS_PER_GROUP = 300


@ws_bp.route("/<int:workspace_id>/domains/<int:target_id>")
@login_required
def domain_detail(workspace_id, target_id):
    ws = _get_member_workspace(workspace_id)
    t = db.session.get(Target, target_id)
    if t is None or t.workspace_id != ws.id:
        abort(404)

    findings = (Finding.query.filter_by(workspace_id=ws.id, target_id=t.id)
                .order_by(Finding.path).all())

    # Fingerprints: union tech / servers / powered-by / WAF seen across findings.
    tech, servers, powered, waf = set(), set(), set(), set()
    if t.last_waf:
        waf.update(w.strip() for w in t.last_waf.split(",") if w.strip())
    for f in findings:
        ex = f.extra_json or {}
        for label in (ex.get("tech") or []):
            tech.add(label)
        for w in (ex.get("waf") or []):
            waf.add(w)
        if ex.get("server"):
            servers.add(ex["server"])
        if ex.get("powered_by"):
            powered.add(ex["powered_by"])

    # Module runs (incl. dirsearches) that produced findings here.
    mruns = (db.session.query(Run.id, Run.module, Run.created_at, func.count(Finding.id))
             .join(Finding, Finding.run_id == Run.id)
             .filter(Finding.target_id == t.id)
             .group_by(Run.id, Run.module, Run.created_at)
             .order_by(Run.created_at.desc()).all())
    module_runs = [{"id": rid, "module": m, "at": at, "count": n}
                   for rid, m, at, n in mruns]

    # Pages breakdown: collapse near-identical responses by (status, length) so a
    # dirsearch that returns thousands of same-size hits doesn't render huge cards.
    groups = {}
    for f in findings:
        key = (f.status_code, f.content_length)
        groups.setdefault(key, []).append(f)
    page_groups = []
    for (status, length), items in groups.items():
        page_groups.append({
            "status": status,
            "length": length,
            "count": len(items),
            "paths": [{"path": i.path, "found_at": i.found_at}
                      for i in items[:MAX_PATHS_PER_GROUP]],
            "truncated": max(0, len(items) - MAX_PATHS_PER_GROUP),
        })
    page_groups.sort(key=lambda g: (-g["count"], g["status"] or 0))

    last_live = t.last_alive_at
    if last_live is None:
        alive_times = [f.found_at for f in findings if (f.extra_json or {}).get("alive")]
        last_live = max(alive_times) if alive_times else None

    ips = _resolve_ips(t.host)

    # Shortlist the URLs worth a human's attention: anything taking a parameter, or whose
    # name hints at what it does. Redirect targets count too — they often carry the params.
    url_rows, url_summary = analyse_urls(
        [f.path for f in findings] + [f.redirect for f in findings if f.redirect])
    tree, tree_stats = build_tree(
        (f.path, f.status_code, f.content_length) for f in findings)

    # Dedup coverage: which base paths have already been fuzzed on this host + how many
    # words each (so the operator knows a normal fuzz will be skipped).
    coverage = [{"parent": parent, "words": n, "last": last}
                for parent, n, last in db.session.query(
                    TestedPath.parent_path, func.count(TestedPath.word),
                    func.max(TestedPath.first_tested_at))
                .filter_by(workspace_id=ws.id, host=t.host)
                .group_by(TestedPath.parent_path)
                .order_by(func.count(TestedPath.word).desc()).all()]

    return render_template("workspaces/domain.html", ws=ws, t=t, ips=ips,
                           fingerprints={"tech": sorted(tech), "servers": sorted(servers),
                                         "powered": sorted(powered), "waf": sorted(waf),
                                         "manual": t.manual_tech_list},
                           module_runs=module_runs, page_groups=page_groups,
                           total_findings=len(findings), last_live=last_live,
                           notes=t.notes, coverage=coverage,
                           shot=_screenshots(ws.id).get(t.id),
                           open_ports=[p.strip() for p in (t.open_ports or "").split(",")
                                       if p.strip()],
                           url_rows=url_rows, url_summary=url_summary,
                           tree=tree, tree_stats=tree_stats)


def _resolve_ips(host, timeout=3.0):
    """Resolve current A/AAAA records for a host, bounded so a slow DNS server can't
    hang the page load."""
    out = []

    def work():
        try:
            out.extend(sorted({info[4][0] for info in socket.getaddrinfo(host, None)}))
        except OSError:
            pass

    th = threading.Thread(target=work, daemon=True)
    th.start()
    th.join(timeout)
    return out


@ws_bp.route("/<int:workspace_id>/domains/<int:target_id>/import-dirsearch",
             methods=["POST"])
@login_required
def import_dirsearch(workspace_id, target_id):
    """Fold pasted (or uploaded) real-dirsearch output into this subdomain.

    Recorded as a completed task so it shows up like any other, and every imported path
    is written to the dedup ledger — the point being that Thoth won't re-fuzz work the
    operator already did elsewhere.
    """
    ws = _get_member_workspace(workspace_id)
    t = db.session.get(Target, target_id)
    if t is None or t.workspace_id != ws.id:
        abort(404)

    raw = request.form.get("results", "")
    upload = request.files.get("file")
    if upload and upload.filename:
        raw += "\n" + upload.read().decode("utf-8", errors="ignore")
    try:
        rows, hosts = parse_dirsearch(raw)
    except ImportError_ as e:
        flash(str(e), "error")
        return redirect(url_for("workspaces.domain_detail", workspace_id=ws.id,
                                target_id=t.id) + "#import")

    now = datetime.utcnow()
    run = Run(workspace_id=ws.id, module=DIRSEARCH_IMPORT,
              config_json={"_targets": [t.id], "source": upload.filename
                           if (upload and upload.filename) else "pasted"},
              status="done", created_by=current_user.id, started_at=now, finished_at=now,
              progress_done=len(rows), progress_total=len(rows))
    db.session.add(run)
    db.session.flush()

    # Existing ledger keys for this host, so we never violate the unique constraint.
    known = {(p, w) for p, w in db.session.query(TestedPath.parent_path, TestedPath.word)
             .filter_by(workspace_id=ws.id, host=t.host).all()}
    log = [f"Importing {len(rows)} result(s) from dirsearch output into {t.host}"]
    ledger_added = 0
    for row in sorted(rows, key=lambda r: r["path"]):
        db.session.add(Finding(
            workspace_id=ws.id, run_id=run.id, target_id=t.id, path=row["path"],
            status_code=row["status_code"], content_length=row["content_length"],
            redirect=row["redirect"], found_at=now,
            extra_json={"module": DIRSEARCH_IMPORT, "imported": True}))
        parent, word = ledger_key(row["path"])
        if word and (parent, word) not in known:
            known.add((parent, word))
            db.session.add(TestedPath(workspace_id=ws.id, host=t.host, parent_path=parent,
                                      word=word, status_code=row["status_code"],
                                      first_tested_at=now))
            ledger_added += 1
        log.append(f"{row['status_code'] or '---'} - {row['path']}"
                   + (f"  ->  {row['redirect']}" if row["redirect"] else ""))

    foreign = {h for h in hosts if h != t.host}
    if foreign:
        log.append(f"Note: output referenced other host(s): {', '.join(sorted(foreign))}")
    log.append("")
    log.append(f"Import Completed — {len(rows)} result(s), "
               f"{ledger_added} new dedup-ledger entr(y/ies)")
    run.log = "\n".join(f"{now:%H:%M:%S} {line}" if line else "" for line in log) + "\n"
    db.session.commit()
    for f in Finding.query.filter_by(run_id=run.id).all():
        publish(ws.id, {"type": "finding", "run_id": run.id, "finding": f.to_dict()})

    msg = (f"Imported {len(rows)} dirsearch result(s) into {t.host} "
           f"({ledger_added} new ledger entries).")
    if foreign:
        msg += (f" Heads up: the output mentioned {', '.join(sorted(foreign))}, "
                f"not {t.host}.")
    flash(msg, "error" if foreign else "info")
    return redirect(url_for("workspaces.run_detail", workspace_id=ws.id, run_id=run.id))


@ws_bp.route("/<int:workspace_id>/domains/<int:target_id>/fingerprint", methods=["POST"])
@login_required
def add_manual_fingerprint(workspace_id, target_id):
    """Tag this one host directly — for things you confirmed by hand and no pattern
    would catch. Separate from a global signature, which teaches Thoth to detect it
    everywhere (see the signatures blueprint)."""
    ws = _get_member_workspace(workspace_id)
    t = db.session.get(Target, target_id)
    if t is None or t.workspace_id != ws.id:
        abort(404)
    labels = [x for x in request.form.get("labels", "").split(",") if x.strip()]
    if not labels:
        flash("Enter a fingerprint label, e.g. Salesforce.", "error")
    else:
        added = t.add_manual_tech(labels)
        if added:
            db.session.commit()
            flash(f"Tagged {t.host}: {', '.join(added)}", "info")
        elif len(", ".join(t.manual_tech_list + labels)) > 300:
            flash("No room for more labels on this host — remove one first.", "error")
        else:
            flash("Already tagged with that.", "error")
    return redirect(url_for("workspaces.domain_detail", workspace_id=ws.id,
                            target_id=t.id) + "#overview")


@ws_bp.route("/<int:workspace_id>/domains/<int:target_id>/fingerprint/remove",
             methods=["POST"])
@login_required
def remove_manual_fingerprint(workspace_id, target_id):
    ws = _get_member_workspace(workspace_id)
    t = db.session.get(Target, target_id)
    if t is None or t.workspace_id != ws.id:
        abort(404)
    label = request.form.get("label", "")
    t.remove_manual_tech(label)
    db.session.commit()
    flash(f"Removed '{label.strip()}' from {t.host}.", "info")
    return redirect(url_for("workspaces.domain_detail", workspace_id=ws.id,
                            target_id=t.id) + "#overview")


@ws_bp.route("/<int:workspace_id>/domains/<int:target_id>/notes", methods=["POST"])
@login_required
def add_note(workspace_id, target_id):
    ws = _get_member_workspace(workspace_id)
    t = db.session.get(Target, target_id)
    if t is None or t.workspace_id != ws.id:
        abort(404)
    body = request.form.get("body", "").strip()
    if body:
        db.session.add(Note(workspace_id=ws.id, target_id=t.id, body=body,
                            path=request.form.get("path", "").strip() or None,
                            created_by=current_user.id))
        db.session.commit()
    return redirect(url_for("workspaces.domain_detail", workspace_id=ws.id,
                            target_id=t.id) + "#notes")


@ws_bp.route("/<int:workspace_id>/activity")
@login_required
def activity(workspace_id):
    """Lightweight polling endpoint: how many runs are in flight + totals, so the UI can
    show a 'running' indicator and auto-refresh when everything finishes."""
    _get_member_workspace(workspace_id)
    active = Run.query.filter(Run.workspace_id == workspace_id,
                              Run.status.in_(["queued", "running"])).count()
    running = [{"id": r.id, "module": r.module, "status": r.status, "pct": r.progress_pct}
               for r in Run.query.filter(
                   Run.workspace_id == workspace_id,
                   Run.status.in_(["queued", "running"])).all()]
    return jsonify({
        "active": active,
        "running": running,
        "findings": Finding.query.filter_by(workspace_id=workspace_id).count(),
        "runs": Run.query.filter_by(workspace_id=workspace_id).count(),
    })


@ws_bp.route("/<int:workspace_id>/settings", methods=["POST"])
@login_required
def update_settings(workspace_id):
    ws = _get_member_workspace(workspace_id)
    ws.proxy = request.form.get("proxy", "").strip() or None
    db.session.commit()
    flash("Settings saved" + (f" · proxy {ws.proxy}" if ws.proxy else " · proxy cleared"), "info")
    return redirect(request.form.get("next")
                    or url_for("workspaces.detail", workspace_id=ws.id) + "#fuzz")


@ws_bp.route("/<int:workspace_id>/response")
@login_required
def view_response(workspace_id):
    """On-demand full response fetch (through the workspace proxy) for a finding/URL."""
    ws = _get_member_workspace(workspace_id)
    target_id = request.args.get("target_id", type=int)
    path = request.args.get("path", "/")
    t = db.session.get(Target, target_id)
    if t is None or t.workspace_id != ws.id:
        abort(404)
    url = t.base_url + (path if path.startswith("/") else "/" + path)
    try:
        r = requests.get(url, timeout=12, allow_redirects=False, verify=False,
                         proxies=to_proxies(ws.proxy), headers={"User-Agent": "Thoth/0.1"})
        body = r.text[:200_000]
        return jsonify({
            "url": url, "status": r.status_code, "reason": r.reason,
            "headers": dict(r.headers), "body": body,
            "truncated": len(r.text) > len(body), "length": len(r.content),
        })
    except requests.RequestException as e:
        return jsonify({"url": url, "error": f"{type(e).__name__}: {e}"}), 200


@ws_bp.route("/<int:workspace_id>/checkall", methods=["POST"])
@login_required
def check_all(workspace_id):
    ws = _get_member_workspace(workspace_id)
    if not Target.query.filter_by(workspace_id=ws.id).count():
        flash("Add subdomains first.", "error")
        return redirect(url_for("workspaces.detail", workspace_id=ws.id) + "#domains")
    from ..runs.routes import launch_run
    run = launch_run(ws, "alive", {})  # a real, recorded run over all subdomains
    flash(f"Started alive task #{run.id} across all subdomains", "info")
    return redirect(url_for("workspaces.detail", workspace_id=ws.id) + "#domains")


@ws_bp.route("/<int:workspace_id>/domains/<int:target_id>/check", methods=["POST"])
@login_required
def check_domain(workspace_id, target_id):
    ws = _get_member_workspace(workspace_id)
    t = db.session.get(Target, target_id)
    if t is None or t.workspace_id != ws.id:
        abort(404)
    probe(t, proxies=to_proxies(ws.proxy))  # updates t.last_* in place
    db.session.commit()
    return jsonify({
        "target_id": t.id,
        "status_code": t.last_status_code,
        "alive": t.last_alive,
        "waf": t.last_waf,
        "open_ports": t.open_port_list,  # full list, so the port filter stays accurate
        "server": t.last_server,
        "title": t.last_title,
        "checked_at": t.last_checked_at.strftime("%H:%M:%S") if t.last_checked_at else None,
    })


@ws_bp.route("/<int:workspace_id>/stream")
@login_required
def stream(workspace_id):
    _get_member_workspace(workspace_id)

    @stream_with_context
    def gen():
        last_id = request.args.get("last_id", 0, type=int)
        pubsub = subscribe(workspace_id)
        if pubsub is not None:
            # Redis pub/sub path
            try:
                for msg in pubsub.listen():
                    if msg.get("type") == "message":
                        yield f"data: {msg['data'].decode()}\n\n"
            finally:
                pubsub.close()
        else:
            # DB-poll fallback: stream new findings + run-status changes.
            run_status = {}
            while True:
                payloads = []
                rows = (Finding.query.filter(Finding.workspace_id == workspace_id,
                                             Finding.id > last_id)
                        .order_by(Finding.id).all())
                for f in rows:
                    last_id = f.id
                    payloads.append(json.dumps({"type": "finding", "run_id": f.run_id,
                                                "finding": f.to_dict()}))
                for r in (Run.query.filter_by(workspace_id=workspace_id)
                          .order_by(Run.id.desc()).limit(25).all()):
                    if run_status.get(r.id) != r.status:
                        run_status[r.id] = r.status
                        payloads.append(json.dumps({"type": "run_status",
                                                    "run_id": r.id, "status": r.status}))
                # Drop the session so the next poll starts a fresh read transaction and
                # actually sees rows the run thread has committed since (SQLite snapshots).
                db.session.remove()
                for p in payloads:
                    yield f"data: {p}\n\n"
                yield ": keepalive\n\n"
                time.sleep(1.5)

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@ws_bp.route("/<int:workspace_id>/wipe", methods=["POST"])
@admin_required
def wipe(workspace_id):
    ws = _get_member_workspace(workspace_id)
    if request.form.get("confirm") != ws.name:
        flash("Type the workspace name exactly to confirm the wipe.", "error")
        return redirect(url_for("workspaces.detail", workspace_id=ws.id))
    wid = ws.id
    db.session.delete(ws)  # cascades everything
    db.session.commit()
    wdir = current_app.config["DATA_DIR"] / "workspaces" / str(wid)
    if wdir.exists():
        shutil.rmtree(wdir, ignore_errors=True)
    flash(f"Workspace '{ws.name}' wiped.", "info")
    return redirect(url_for("workspaces.list_workspaces"))
