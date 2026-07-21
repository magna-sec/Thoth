"""IIS 8.3 short-name (tilde) enumeration: detection, name recovery, and the module.

The fake server implements the same wildcard-matching contract a vulnerable IIS exposes,
so the enumeration engine is exercised end to end without a real IIS.
"""
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

from app.extensions import db
from app.models import Finding, Run, Target
from app.modules.iistilde import _looks_like_iis, detect, enumerate_names
from app.tasks import run_module_task

# tilde expression grammar: STEM (SW) ~ IDX (NW) [ . EXT (EW) ]
_EXPR = re.compile(
    r"^(?P<stem>[^~*.]*)(?P<sw>\*?)~(?P<idx>\d+)(?P<nw>\*?)"
    r"(?:\.(?P<ext>[^*/]*)(?P<ew>\*?))?$")


def _matches(expr, known):
    """Does the tilde expression match any known short name? `known` = {(stem, idx, ext)}
    with ext None for no-extension names."""
    m = _EXPR.match(expr)
    if not m:
        return False
    stem, sw = m["stem"].upper(), m["sw"]
    idx, nw = int(m["idx"]), m["nw"]
    ext, ew = (m["ext"].upper() if m["ext"] is not None else None), m["ew"]
    for kstem, kidx, kext in known:
        if idx != kidx:
            continue
        if (kstem.startswith(stem) if sw == "*" else kstem == stem):
            if ext is None:
                if nw == "*" or kext is None:   # any/none extension, or exact no-ext name
                    return True
            elif kext is not None:
                if (kext.startswith(ext) if ew == "*" else kext == ext):
                    return True
    return False


def fake_iis(known, found=404, miss=400):
    """A server that answers `found` when the request's tilde expression matches a known
    short name, else `miss` — i.e. a vulnerable IIS."""
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            expr = self.path.strip("/").split("/")[0]   # the /{expr}/.aspx segment
            self.send_response(found if _matches(expr, known) else miss)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def test_looks_like_iis():
    assert _looks_like_iis(Target(host="x", last_server="Microsoft-IIS/10.0"))
    assert _looks_like_iis(Target(host="x", last_tech="IIS, ASP.NET"))
    assert not _looks_like_iis(Target(host="x", last_server="nginx"))


def test_matcher_helper_is_faithful():
    known = {("ADMIN", 1, "ASP")}
    assert _matches("*~1*", known)          # magic wildcard matches anything
    assert _matches("AD*~1*", known)        # prefix
    assert _matches("ADMIN~1*", known)      # exact stem, any ext
    assert _matches("ADMIN~1.AS*", known)   # ext prefix
    assert _matches("ADMIN~1.ASP", known)   # exact
    assert not _matches("ZZ*~1*", known)    # wrong prefix
    assert not _matches("ADMIN~1", known)   # this name HAS an extension
    assert not _matches("ADMIN~2*", known)  # wrong tilde index


def test_detect_vulnerable_and_patched():
    srv, port = fake_iis({("ADMIN", 1, "ASP")})
    try:
        d = detect(f"http://127.0.0.1:{port}", requests.Session(), timeout=3)
        assert d["vulnerable"] and d["found"] == 404 and d["miss"] == 400
    finally:
        srv.shutdown()

    # Patched: both requests answer the same -> no differential.
    srv, port = fake_iis(set(), found=404, miss=404)
    try:
        assert detect(f"http://127.0.0.1:{port}", requests.Session(), timeout=3)["vulnerable"] is False
    finally:
        srv.shutdown()


def test_enumeration_recovers_names_with_and_without_extensions():
    known = {("ADMIN", 1, "ASP"), ("BACKUP", 1, "ZIP"), ("TEST", 1, None)}
    srv, port = fake_iis(known)
    try:
        session = requests.Session()
        d = detect(f"http://127.0.0.1:{port}", session, timeout=3)
        names, reqs, truncated = enumerate_names(
            f"http://127.0.0.1:{port}", session, d["found"], d["suffix"], timeout=3)
        assert set(names) == {"ADMIN~1.ASP", "BACKUP~1.ZIP", "TEST~1"}
        assert not truncated and reqs > 0
    finally:
        srv.shutdown()


def test_enumeration_finds_tilde_collisions():
    known = {("REPORT", 1, "PDF"), ("REPORT", 2, "PDF")}
    srv, port = fake_iis(known)
    try:
        session = requests.Session()
        d = detect(f"http://127.0.0.1:{port}", session, timeout=3)
        names, _, _ = enumerate_names(
            f"http://127.0.0.1:{port}", session, d["found"], d["suffix"], timeout=3)
        assert "REPORT~1.PDF" in names and "REPORT~2.PDF" in names
    finally:
        srv.shutdown()


def test_enumeration_respects_the_budget():
    srv, port = fake_iis({("ADMIN", 1, "ASP")})
    try:
        session = requests.Session()
        d = detect(f"http://127.0.0.1:{port}", session, timeout=3)
        names, reqs, truncated = enumerate_names(
            f"http://127.0.0.1:{port}", session, d["found"], d["suffix"], timeout=3,
            budget=10)
        assert truncated and reqs <= 10
    finally:
        srv.shutdown()


def test_module_enumerates_a_vulnerable_iis_host(app, workspace):
    known = {("ADMIN", 1, "ASP"), ("WEBCON", 1, "CON")}
    srv, port = fake_iis(known)
    try:
        with app.app_context():
            t = Target(workspace_id=workspace, host="127.0.0.1", scheme="http", port=port,
                       last_server="Microsoft-IIS/10.0")
            db.session.add(t)
            run = Run(workspace_id=workspace, module="iistilde", config_json={"timeout": 3})
            db.session.add(run)
            db.session.commit()
            tid, rid = t.id, run.id
            run_module_task.run(rid)
            db.session.remove()

            f = Finding.query.filter_by(run_id=rid, target_id=tid).one()
            assert f.extra_json["vulnerable"] is True
            assert f.extra_json["severity"] == "high"     # names found
            assert set(f.extra_json["shortnames"]) == {"ADMIN~1.ASP", "WEBCON~1.CON"}
            log = db.session.get(Run, rid).log or ""
            assert "ADMIN~1.ASP" in log
    finally:
        srv.shutdown()


def test_module_detect_only_when_enumerate_off(app, workspace):
    srv, port = fake_iis({("ADMIN", 1, "ASP")})
    try:
        with app.app_context():
            t = Target(workspace_id=workspace, host="127.0.0.1", scheme="http", port=port,
                       last_server="Microsoft-IIS/10.0")
            db.session.add(t)
            run = Run(workspace_id=workspace, module="iistilde",
                      config_json={"timeout": 3, "enumerate": False})
            db.session.add(run)
            db.session.commit()
            tid, rid = t.id, run.id
            run_module_task.run(rid)
            db.session.remove()
            f = Finding.query.filter_by(run_id=rid, target_id=tid).one()
            assert f.extra_json["vulnerable"] is True
            assert f.extra_json["severity"] == "medium"   # vulnerable but not enumerated
            assert f.extra_json["shortnames"] == []
    finally:
        srv.shutdown()


def test_module_skips_non_iis_hosts_by_default(app, workspace, mock_target):
    with app.app_context():
        t = Target(workspace_id=workspace, host="127.0.0.1", scheme="http",
                   port=mock_target.port, last_server="nginx")
        db.session.add(t)
        run = Run(workspace_id=workspace, module="iistilde", config_json={"timeout": 3})
        db.session.add(run)
        db.session.commit()
        tid, rid = t.id, run.id
        run_module_task.run(rid)
        db.session.remove()
        assert Finding.query.filter_by(run_id=rid, target_id=tid).count() == 0
        assert "not fingerprinted as IIS" in (db.session.get(Run, rid).log or "")


def test_scan_all_iis_button_shown_when_iis_hosts_exist(client, app, workspace):
    with app.app_context():
        db.session.add(Target(workspace_id=workspace, host="iis.test", scheme="https",
                              last_server="Microsoft-IIS/10.0"))
        db.session.add(Target(workspace_id=workspace, host="ngx.test", scheme="https",
                              last_server="nginx"))
        db.session.commit()
    page = client.get(f"/workspaces/{workspace}").data.decode()
    assert "for tilde" in page          # the "Scan N IIS host(s) for tilde" button
    assert "1 IIS host(s)" in page       # only the one IIS host counted


def test_scan_all_iis_button_hidden_without_iis(client, app, workspace):
    with app.app_context():
        db.session.add(Target(workspace_id=workspace, host="ngx.test", scheme="https",
                              last_server="nginx"))
        db.session.commit()
    assert "for tilde" not in client.get(f"/workspaces/{workspace}").data.decode()


def test_iis_tilde_button_on_iis_domain_page(client, app, workspace):
    with app.app_context():
        t = Target(workspace_id=workspace, host="iis.test", scheme="https",
                   last_server="Microsoft-IIS/10.0")
        db.session.add(t)
        db.session.commit()
        tid = t.id
    assert "IIS tilde ▶" in client.get(f"/workspaces/{workspace}/domains/{tid}").data.decode()
