"""Shared pytest fixtures: temp-DB app, logged-in client, a mock target server, and a
small wordlist. Tasks run inline (dispatch is patched) so no subprocess/broker is needed."""
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app import create_app
from app.config import Config
from app.extensions import db
from app.models import Target, User, Workspace, WorkspaceMember


@pytest.fixture
def app(tmp_path):
    class TestConfig(Config):
        TESTING = True
        WTF_CSRF_ENABLED = False
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'test.db'}"
        CELERY_BROKER_URL = None
        CELERY_RESULT_BACKEND = None
        CELERY_TASK_ALWAYS_EAGER = True
        REDIS_URL = None
        DATA_DIR = tmp_path / "data"

    application = create_app(TestConfig)
    yield application


@pytest.fixture(autouse=True)
def inline_tasks(monkeypatch, app):
    """Run tasks synchronously in-process instead of spawning a subprocess."""
    from app.tasks import run_module_task
    import app.runs.routes as runs_routes
    monkeypatch.setattr(runs_routes, "dispatch", lambda run_id: run_module_task.run(run_id))


@pytest.fixture
def ctx(app):
    with app.app_context():
        yield


@pytest.fixture
def user(app):
    with app.app_context():
        u = User(email="magna", is_admin=True)
        u.set_password("magna")
        db.session.add(u)
        db.session.commit()
        return u.id


@pytest.fixture
def client(app, user):
    c = app.test_client()
    c.post("/login", data={"email": "magna", "password": "magna"})
    return c


@pytest.fixture
def workspace(app, user):
    with app.app_context():
        ws = Workspace(name="WS", client="ACME", created_by=user)
        db.session.add(ws)
        db.session.flush()
        db.session.add(WorkspaceMember(workspace_id=ws.id, user_id=user, role="owner"))
        db.session.commit()
        return ws.id


@pytest.fixture
def mock_target():
    """A tiny HTTP server. Tests set routes[path] = (status, body, headers); unknown paths
    fall back to `catch_all` (default 404) — set catch_all to emulate a wildcard responder."""
    ctl = types.SimpleNamespace(port=None, routes={}, catch_all=None)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            spec = ctl.routes.get(self.path) or ctl.catch_all or (404, b"not found", {})
            status, body, hdrs = spec
            self.send_response(status)
            for k, v in hdrs.items():
                self.send_header(k, v)
            if not any(k.lower() == "content-length" for k in hdrs):
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctl.port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield ctl
    srv.shutdown()


@pytest.fixture
def target(app, workspace, mock_target):
    """A Target pointing at the mock server."""
    with app.app_context():
        t = Target(workspace_id=workspace, host="127.0.0.1", scheme="http",
                   port=mock_target.port)
        db.session.add(t)
        db.session.commit()
        return t.id


@pytest.fixture
def small_wordlist(tmp_path):
    d = tmp_path / "wl"
    d.mkdir()
    (d / "list.txt").write_text("\n".join(
        ["admin", "login", "secret", "backup"] + [f"w{i}" for i in range(40)]))
    return str(d)
