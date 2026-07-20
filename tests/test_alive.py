"""alive module: fingerprinting, WAF detection, alt-port sweep, multi-threaded batch run."""
import socket
import time
import types

from app.extensions import db
from app.models import Finding, Run, Target
from app.modules.alive import (DEFAULT_EXTRA_PORTS, _detect_waf, _fingerprint,
                               _probe_ports, parse_ports)
from app.tasks import run_module_task


def _closed_port():
    """Grab a port number, then release it, so connections to it are refused."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


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


def test_parse_ports():
    assert parse_ports(None) == list(DEFAULT_EXTRA_PORTS)
    assert parse_ports("8080,8443") == [8080, 8443]
    assert parse_ports(" 8080 ; 8443 , 8080 ") == [8080, 8443]  # trimmed and deduped
    assert parse_ports("") == []                                 # opt out entirely
    assert parse_ports("nope,0,99999,8081") == [8081]            # junk dropped


def test_probe_ports_reports_only_listening_ports(app, mock_target):
    found = _probe_ports("127.0.0.1", [mock_target.port, _closed_port()],
                         timeout=3, verify=False, proxies=None)
    assert [p["port"] for p in found] == [mock_target.port]
    assert found[0]["status_code"] == 404 and found[0]["scheme"] == "http"


def test_probe_ports_picks_scheme_by_convention(app):
    # 8443 is assumed TLS, 8080 plain — checked without any listener via the URL we build.
    assert _probe_ports("127.0.0.1", [], 1, False, None) == []
    from app.modules.alive import _scheme_for_port
    assert _scheme_for_port(8443) == "https"
    assert _scheme_for_port(8080) == "http"


def test_alive_marks_open_alt_ports(app, workspace, mock_target, monkeypatch):
    """A host dead on its primary port but answering on 8080-style ports gets marked."""
    monkeypatch.setattr("app.modules.alive.enrich", lambda host: {})
    with app.app_context():
        t = Target(workspace_id=workspace, host="127.0.0.1", scheme="http",
                   port=_closed_port())
        db.session.add(t)
        run = Run(workspace_id=workspace, module="alive",
                  config_json={"timeout": 3, "extra_ports": str(mock_target.port)})
        db.session.add(run)
        db.session.commit()
        tid, rid = t.id, run.id
        run_module_task.run(rid)
        db.session.remove()

        t = db.session.get(Target, tid)
        assert t.last_alive is False                  # primary port really is down...
        assert t.open_ports == str(mock_target.port)  # ...but the alt port answered
        f = Finding.query.filter_by(run_id=rid, target_id=tid).one()
        assert f.extra_json["open_ports"][0]["port"] == mock_target.port
        assert f"open port {mock_target.port}" in db.session.get(Run, rid).log


def test_alive_can_skip_the_port_sweep(app, workspace, mock_target, monkeypatch):
    monkeypatch.setattr("app.modules.alive.enrich", lambda host: {})
    with app.app_context():
        t = Target(workspace_id=workspace, host="127.0.0.1", scheme="http",
                   port=mock_target.port)
        db.session.add(t)
        run = Run(workspace_id=workspace, module="alive",
                  config_json={"timeout": 3, "extra_ports": ""})
        db.session.add(run)
        db.session.commit()
        tid, rid = t.id, run.id
        run_module_task.run(rid)
        db.session.remove()
        assert db.session.get(Target, tid).open_ports is None


def test_scheme_order_prefers_the_port_convention():
    from app.modules.alive import scheme_order
    assert scheme_order("https", None) == ["https", "http"]
    assert scheme_order("https", 80) == ["http", "https"]     # port beats stored scheme
    assert scheme_order("https", 8080) == ["http", "https"]
    assert scheme_order("http", 8443) == ["https", "http"]
    assert scheme_order("http", None) == ["http", "https"]


def test_http_only_host_is_found_and_scheme_corrected(app, workspace, mock_target,
                                                      monkeypatch):
    """A bare hostname is stored as https. An http-only site must still be discovered,
    and the target's scheme corrected so later modules use the right URL."""
    monkeypatch.setattr("app.modules.alive.enrich", lambda host: {})
    with app.app_context():
        # scheme=https, but the only listener is plain HTTP on the mock server's port.
        t = Target(workspace_id=workspace, host="127.0.0.1", scheme="https",
                   port=mock_target.port)
        db.session.add(t)
        run = Run(workspace_id=workspace, module="alive",
                  config_json={"timeout": 3, "extra_ports": ""})
        db.session.add(run)
        db.session.commit()
        tid, rid = t.id, run.id
        run_module_task.run(rid)
        db.session.remove()

        t = db.session.get(Target, tid)
        assert t.last_alive is True          # found, where before it was "dead"
        assert t.scheme == "http"            # ...and the scheme was corrected
        assert t.base_url == f"http://127.0.0.1:{mock_target.port}"
        assert "switched to http" in (db.session.get(Run, rid).log or "")


def test_scheme_fallback_can_be_disabled(app, workspace, mock_target, monkeypatch):
    monkeypatch.setattr("app.modules.alive.enrich", lambda host: {})
    with app.app_context():
        t = Target(workspace_id=workspace, host="127.0.0.1", scheme="https",
                   port=mock_target.port)
        db.session.add(t)
        run = Run(workspace_id=workspace, module="alive",
                  config_json={"timeout": 3, "extra_ports": "",
                               "scheme_fallback": False})
        db.session.add(run)
        db.session.commit()
        tid, rid = t.id, run.id
        run_module_task.run(rid)
        db.session.remove()
        assert db.session.get(Target, tid).scheme == "https"   # left alone


def test_quick_check_also_falls_back(app, workspace, mock_target):
    from app.modules.alive import probe
    with app.app_context():
        t = Target(workspace_id=workspace, host="127.0.0.1", scheme="https",
                   port=mock_target.port)
        db.session.add(t)
        db.session.commit()
        probe(t, timeout=3, extra_ports=())
        assert t.last_alive is True and t.scheme == "http"


def test_open_port_list_includes_the_primary_port():
    from app.models import Target
    t = Target(host="a.test", scheme="https", last_alive=True, open_ports="8080, 8443")
    assert t.open_port_list == [443, 8080, 8443]      # implied 443 for a live https host
    t.scheme, t.open_ports = "http", None
    assert t.open_port_list == [80]
    t.last_alive = False
    assert t.open_port_list == []                     # dead: primary port isn't "open"
    t.open_ports = "8080"
    assert t.open_port_list == [8080]                 # ...but a found alt port still is
    t.port, t.last_alive = 8000, True
    assert t.open_port_list == [8000, 8080]           # explicit port wins over the scheme


def test_port_filter_rendered_with_card_data(client, app, workspace):
    from app.models import Target
    with app.app_context():
        db.session.add(Target(workspace_id=workspace, host="p.test", scheme="https",
                              last_alive=True, open_ports="8080"))
        db.session.commit()
    page = client.get(f"/workspaces/{workspace}").data.decode()
    assert 'id="filter-port"' in page
    assert 'data-ports="443,8080"' in page


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
            # No alt-port sweep here: this test is timing the concurrency of the probes.
            run = Run(workspace_id=workspace, module="alive",
                      config_json={"extra_ports": ""})
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
