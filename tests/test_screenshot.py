"""Screenshot module: capture, dedup/skip rules, failure handling, and image serving.

The real renderer is swapped for a stub — CI has no browser, and what matters here is the
module's bookkeeping, not Chromium's output.
"""
from contextlib import contextmanager
from pathlib import Path

import pytest

from app.extensions import db
from app.models import Finding, Run, Target
from app.modules.screenshot import (Backend, CaptureError, chrome_binary, screenshot_dir,
                                    shot_name)
from app.tasks import run_module_task

# Smallest valid PNG (1x1, transparent).
PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06"
       b"\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05"
       b"\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82")


@pytest.fixture
def stub_renderer(monkeypatch):
    """Replace open_backend with one that writes a PNG (or fails for flagged hosts)."""
    calls = []

    @contextmanager
    def fake(width, height, timeout, proxy=None, verify_tls=False, full_page=False):
        def capture(url, out_path):
            calls.append(url)
            if "boom" in url:
                raise CaptureError("net::ERR_NAME_NOT_RESOLVED")
            out_path.write_bytes(PNG)

        yield Backend("stub", capture, parallel=True, full_page_supported=False)

    monkeypatch.setattr("app.modules.screenshot.open_backend", fake)
    # The probe alongside each capture must not hit the network in tests.
    monkeypatch.setattr("app.modules.screenshot._do_probe", lambda *a, **k: {
        "status_code": 200, "content_length": 12, "redirect": None,
        "extra": {"alive": True, "title": "Home", "server": "nginx"}})
    return calls


def _run(app, workspace, config=None):
    with app.app_context():
        run = Run(workspace_id=workspace, module="screenshot", config_json=config or {})
        db.session.add(run)
        db.session.commit()
        rid = run.id
        run_module_task.run(rid)
        db.session.remove()
        return rid


def test_captures_every_subdomain(app, workspace, stub_renderer):
    with app.app_context():
        for host in ("a.test", "b.test"):
            db.session.add(Target(workspace_id=workspace, host=host, scheme="https"))
        db.session.commit()

    rid = _run(app, workspace)

    with app.app_context():
        run = db.session.get(Run, rid)
        assert run.status == "done"
        assert run.progress_done == run.progress_total == 2
        findings = Finding.query.filter_by(run_id=rid).all()
        assert len(findings) == 2
        for f in findings:
            assert f.extra_json["screenshot"] == shot_name(f.target_id, rid)
            assert f.extra_json["bytes"] == len(PNG)
            assert f.status_code == 200  # carried over from the HTTP probe
            assert (screenshot_dir(workspace) / f.extra_json["screenshot"]).exists()
    assert sorted(stub_renderer) == ["https://a.test", "https://b.test"]


def test_single_target_run(app, workspace, stub_renderer):
    with app.app_context():
        t = Target(workspace_id=workspace, host="one.test", scheme="https")
        db.session.add(t)
        db.session.add(Target(workspace_id=workspace, host="other.test", scheme="https"))
        db.session.commit()
        tid = t.id
    _run(app, workspace, {"_targets": [tid]})
    assert stub_renderer == ["https://one.test"]


def test_skips_dead_hosts_unless_told_otherwise(app, workspace, stub_renderer):
    with app.app_context():
        db.session.add(Target(workspace_id=workspace, host="up.test", scheme="https",
                              last_alive=True))
        db.session.add(Target(workspace_id=workspace, host="down.test", scheme="https",
                              last_alive=False))
        db.session.commit()

    _run(app, workspace)
    assert stub_renderer == ["https://up.test"]

    stub_renderer.clear()
    _run(app, workspace, {"skip_dead": False, "force": True})
    assert sorted(stub_renderer) == ["https://down.test", "https://up.test"]


def test_already_captured_hosts_are_skipped_until_forced(app, workspace, stub_renderer):
    with app.app_context():
        db.session.add(Target(workspace_id=workspace, host="a.test", scheme="https"))
        db.session.commit()

    _run(app, workspace)
    assert len(stub_renderer) == 1

    stub_renderer.clear()
    rid = _run(app, workspace)  # second run: nothing to do
    assert stub_renderer == []
    with app.app_context():
        assert Finding.query.filter_by(run_id=rid).count() == 0
        assert "already captured" in db.session.get(Run, rid).log

    stub_renderer.clear()
    _run(app, workspace, {"force": True})
    assert len(stub_renderer) == 1


def test_capture_failure_is_recorded_not_fatal(app, workspace, stub_renderer):
    with app.app_context():
        db.session.add(Target(workspace_id=workspace, host="boom.test", scheme="https"))
        db.session.add(Target(workspace_id=workspace, host="fine.test", scheme="https"))
        db.session.commit()

    rid = _run(app, workspace)

    with app.app_context():
        assert db.session.get(Run, rid).status == "done"  # one bad host doesn't kill the run
        by_host = {f.target.host: f.extra_json for f in
                   Finding.query.filter_by(run_id=rid).all()}
        assert "ERR_NAME_NOT_RESOLVED" in by_host["boom.test"]["screenshot_error"]
        assert "screenshot" not in by_host["boom.test"]
        assert by_host["fine.test"]["screenshot"]


def test_missing_renderer_fails_the_run_with_a_useful_message(app, workspace, monkeypatch):
    monkeypatch.setattr("app.modules.screenshot.chrome_binary", lambda: None)
    monkeypatch.setattr("app.modules.screenshot._do_probe", lambda *a, **k: {
        "status_code": None, "content_length": None, "redirect": None,
        "extra": {"alive": False}})
    # Pretend Playwright isn't installed either.
    import builtins
    real_import = builtins.__import__

    def no_playwright(name, *a, **k):
        if name.startswith("playwright"):
            raise ImportError("no playwright")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_playwright)
    with app.app_context():
        db.session.add(Target(workspace_id=workspace, host="a.test", scheme="https"))
        db.session.commit()

    rid = _run(app, workspace)
    with app.app_context():
        run = db.session.get(Run, rid)
        assert run.status == "error" and "No renderer found" in run.error


def test_image_route_serves_and_rejects_traversal(client, app, workspace, stub_renderer):
    with app.app_context():
        t = Target(workspace_id=workspace, host="a.test", scheme="https")
        db.session.add(t)
        db.session.commit()
        tid = t.id

    rid = _run(app, workspace)
    name = shot_name(tid, rid)

    ok = client.get(f"/workspaces/{workspace}/screenshots/{name}")
    assert ok.status_code == 200 and ok.data == PNG
    assert client.get(f"/workspaces/{workspace}/screenshots/nope.png").status_code == 404
    assert client.get(f"/workspaces/{workspace}/screenshots/..%2fthoth.db").status_code == 404


def test_gallery_and_domain_page_show_the_capture(client, app, workspace, stub_renderer):
    with app.app_context():
        t = Target(workspace_id=workspace, host="shot.test", scheme="https")
        db.session.add(t)
        db.session.commit()
        tid = t.id
    rid = _run(app, workspace)

    page = client.get(f"/workspaces/{workspace}").data.decode()
    assert 'data-pane="shots"' in page and shot_name(tid, rid) in page
    domain = client.get(f"/workspaces/{workspace}/domains/{tid}").data.decode()
    assert shot_name(tid, rid) in domain


def test_relative_data_dir_still_serves_images(client, app, workspace, stub_renderer,
                                               monkeypatch, tmp_path):
    """Regression: `.env` ships DATA_DIR=./data (relative). Flask resolves a relative
    send_from_directory against the app package dir, not the cwd, so captures were
    written in one place and looked for in another — a 404 for a file that exists.
    """
    monkeypatch.chdir(tmp_path)
    app.config["DATA_DIR"] = Path("./data")  # exactly what a relative env var produces
    with app.app_context():
        t = Target(workspace_id=workspace, host="rel.test", scheme="https")
        db.session.add(t)
        db.session.commit()
        tid = t.id

    rid = _run(app, workspace)
    name = shot_name(tid, rid)

    with app.app_context():  # the capture really did land on disk
        assert (screenshot_dir(workspace) / name).exists()
    resp = client.get(f"/workspaces/{workspace}/screenshots/{name}")
    assert resp.status_code == 200 and resp.data == PNG


def test_config_forces_data_dir_absolute(monkeypatch):
    from app.config import BASE_DIR, _abs_dir
    assert _abs_dir("./data", None) == (BASE_DIR / "data").resolve()
    assert _abs_dir("", BASE_DIR / "data") == BASE_DIR / "data"
    assert _abs_dir(str(BASE_DIR / "x"), None).is_absolute()


def test_chrome_binary_env_override(monkeypatch, tmp_path):
    fake = tmp_path / "chrome.exe"
    fake.write_bytes(b"")
    monkeypatch.setenv("THOTH_CHROME", str(fake))
    assert chrome_binary() == str(fake)
    monkeypatch.setenv("THOTH_CHROME", str(tmp_path / "missing.exe"))
    assert chrome_binary() is None
