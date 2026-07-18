"""alive module: fingerprinting, WAF detection, and multi-threaded batch run."""
import time
import types

from app.extensions import db
from app.models import Finding, Run, Target
from app.modules.alive import _detect_waf, _fingerprint
from app.tasks import run_module_task


def _resp(headers=None, text="", cookies=()):
    return types.SimpleNamespace(headers=headers or {}, text=text,
                                 cookies=types.SimpleNamespace(keys=lambda: list(cookies)))


def test_fingerprint_server_and_body():
    assert "IIS" in _fingerprint(_resp(headers={"Server": "Microsoft-IIS/10.0"}))
    assert "nginx" in _fingerprint(_resp(headers={"Server": "nginx/1.25"}))
    assert "WordPress" in _fingerprint(_resp(text="<link href='/wp-content/x.css'>"))
    assert "React" in _fingerprint(_resp(text="<div data-reactroot></div>"))


def test_waf_detection_variants():
    assert "Cloudflare" in _detect_waf(_resp(headers={"cf-ray": "abc"}))
    assert "Sucuri" in _detect_waf(_resp(headers={"X-Sucuri-ID": "1"}))
    assert "Imperva Incapsula" in _detect_waf(_resp(cookies=["visid_incap_1"]))
    assert _detect_waf(_resp(headers={"Server": "nginx"})) == []


def test_alive_is_multithreaded(app, workspace, mock_target, monkeypatch):
    # Avoid real DNS/ASN network during the timing test.
    monkeypatch.setattr("app.modules.alive.enrich", lambda host: {})
    # 6 hosts, each 0.25s latency: sequential ~1.5s, concurrent should be well under.
    import http.server as _h

    class Slow(_h.BaseHTTPRequestHandler):
        def do_GET(self):
            time.sleep(0.25)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = _h.ThreadingHTTPServer(("127.0.0.1", 0), Slow)
    port = srv.server_address[1]
    import threading
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with app.app_context():
            for _ in range(6):
                db.session.add(Target(workspace_id=workspace, host="127.0.0.1",
                                      scheme="http", port=port))
            run = Run(workspace_id=workspace, module="alive", config_json={})
            db.session.add(run)
            db.session.commit()
            rid = run.id
            t0 = time.time()
            run_module_task.run(rid)
            elapsed = time.time() - t0
            db.session.remove()
            r = db.session.get(Run, rid)
            n = Finding.query.filter_by(run_id=rid).count()
        assert n == 6
        assert r.progress_done == r.progress_total == 6
        assert elapsed < 1.0, f"alive not concurrent (took {elapsed:.2f}s)"
    finally:
        srv.shutdown()
