"""IIS 8.3 short-name (tilde) enumeration check: detection logic and the module."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

from app.extensions import db
from app.models import Finding, Run, Target
from app.modules.iistilde import _looks_like_iis, check_host
from app.tasks import run_module_task


def _server(handler_status):
    """A server whose status depends on the request path, to fake the tilde differential.
    `handler_status(path) -> int`."""
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(handler_status(self.path))
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


def test_detects_the_vulnerable_differential():
    # Vulnerable IIS: the wildcard that matches (has "*~1") → 404, the improbable
    # control prefix → 400. `*` at the start matches; the random prefix does not.
    def status(path):
        # control paths contain the random 12-char prefix -> 400; the magic /*~1* -> 404
        return 400 if "/*~1*" not in path else 404

    srv, port = _server(status)
    try:
        session = requests.Session()
        res = check_host(f"http://127.0.0.1:{port}", session, timeout=3)
        assert res["vulnerable"] is True
        assert res["magic_status"] == 404 and res["control_status"] == 400
    finally:
        srv.shutdown()


def test_patched_server_is_not_flagged():
    # Patched IIS answers both the same (e.g. 404) — no differential, not vulnerable.
    srv, port = _server(lambda path: 404)
    try:
        res = check_host(f"http://127.0.0.1:{port}", requests.Session(), timeout=3)
        assert res["vulnerable"] is False
    finally:
        srv.shutdown()


def test_server_that_rejects_everything_is_not_flagged():
    # 400 for both (server dislikes ~ or *) is not a differential.
    srv, port = _server(lambda path: 400)
    try:
        res = check_host(f"http://127.0.0.1:{port}", requests.Session(), timeout=3)
        assert res["vulnerable"] is False
    finally:
        srv.shutdown()


def test_module_flags_vulnerable_iis_host(app, workspace):
    def status(path):
        return 400 if "/*~1*" not in path else 404

    srv, port = _server(status)
    try:
        with app.app_context():
            t = Target(workspace_id=workspace, host="127.0.0.1", scheme="http", port=port,
                       last_server="Microsoft-IIS/10.0")
            db.session.add(t)
            run = Run(workspace_id=workspace, module="iistilde",
                      config_json={"timeout": 3})
            db.session.add(run)
            db.session.commit()
            tid, rid = t.id, run.id
            run_module_task.run(rid)
            db.session.remove()

            f = Finding.query.filter_by(run_id=rid, target_id=tid).one()
            assert f.extra_json["vulnerable"] is True
            assert f.extra_json["severity"] == "medium"
            assert "VULN" in (db.session.get(Run, rid).log or "")
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

        # Skipped: no finding emitted, and the log says why.
        assert Finding.query.filter_by(run_id=rid, target_id=tid).count() == 0
        assert "not fingerprinted as IIS" in (db.session.get(Run, rid).log or "")


def test_only_iis_can_be_forced_off(app, workspace):
    # An nginx-looking host, but only_iis unticked -> it gets tested anyway.
    srv, port = _server(lambda path: 404)   # patched: will resolve as not-vulnerable
    try:
        with app.app_context():
            t = Target(workspace_id=workspace, host="127.0.0.1", scheme="http", port=port,
                       last_server="nginx")
            db.session.add(t)
            run = Run(workspace_id=workspace, module="iistilde",
                      config_json={"timeout": 3, "only_iis": False})
            db.session.add(run)
            db.session.commit()
            tid, rid = t.id, run.id
            run_module_task.run(rid)
            db.session.remove()
            # It ran (produced a finding) rather than skipping.
            assert Finding.query.filter_by(run_id=rid, target_id=tid).count() == 1
    finally:
        srv.shutdown()


def test_iis_tilde_button_shown_on_iis_domain_page(client, app, workspace):
    with app.app_context():
        iis = Target(workspace_id=workspace, host="iis.test", scheme="https",
                     last_server="Microsoft-IIS/10.0")
        other = Target(workspace_id=workspace, host="ngx.test", scheme="https",
                       last_server="nginx")
        db.session.add_all([iis, other])
        db.session.commit()
        iis_id, other_id = iis.id, other.id

    iis_page = client.get(f"/workspaces/{workspace}/domains/{iis_id}").data.decode()
    assert "IIS tilde ▶" in iis_page                 # prominent on an IIS host
    other_page = client.get(f"/workspaces/{workspace}/domains/{other_id}").data.decode()
    assert "IIS tilde (force)" in other_page          # available but tucked away otherwise
