"""dirsearch engine: hits, wildcard suppression, dedup, force re-scan, sizing, %EXT%."""
from app.extensions import db
from app.models import Finding, Run, TestedPath
from app.modules.dirsearch import _humansize, _is_hit
from app.tasks import run_module_task


def _run(app, workspace, target, **cfg):
    with app.app_context():
        run = Run(workspace_id=workspace, module="dirsearch",
                  config_json={"_targets": [target], "recursion_depth": 1, **cfg})
        db.session.add(run)
        db.session.commit()
        rid = run.id
        run_module_task.run(rid)
        db.session.remove()
        return rid, Finding.query.filter_by(run_id=rid).count()


def test_finds_hits_ignores_404(app, workspace, target, mock_target, small_wordlist):
    mock_target.routes["/admin"] = (200, b"ok", {})
    mock_target.routes["/login"] = (200, b"hello there", {})
    rid, n = _run(app, workspace, target, wordlist_dir=small_wordlist)
    assert n == 2
    with app.app_context():
        paths = {f.path for f in Finding.query.filter_by(run_id=rid)}
        assert paths == {"/admin", "/login"}


def test_wildcard_suppressed(app, workspace, target, mock_target, small_wordlist):
    # Every unknown path returns an identical 200 -> wildcard baseline suppresses them all.
    mock_target.catch_all = (200, b"same-everywhere", {})
    _, n = _run(app, workspace, target, wordlist_dir=small_wordlist)
    assert n == 0


def test_dedup_skips_on_rerun(app, workspace, target, mock_target, small_wordlist):
    mock_target.routes["/admin"] = (200, b"ok", {})
    _, n1 = _run(app, workspace, target, wordlist_dir=small_wordlist)
    assert n1 == 1
    _, n2 = _run(app, workspace, target, wordlist_dir=small_wordlist)
    assert n2 == 0  # ledger already covers everything


def test_force_rescan_retests(app, workspace, target, mock_target, small_wordlist):
    mock_target.routes["/admin"] = (200, b"ok", {})
    _run(app, workspace, target, wordlist_dir=small_wordlist)
    with app.app_context():
        ledger_before = TestedPath.query.count()
    _, n2 = _run(app, workspace, target, wordlist_dir=small_wordlist, force=True)
    assert n2 == 1  # re-tested despite the ledger
    with app.app_context():
        assert TestedPath.query.count() == ledger_before  # no duplicate ledger rows


def test_content_length_sizing_no_full_download(app, workspace, target, mock_target,
                                                small_wordlist):
    mock_target.routes["/admin"] = (200, b"A" * 250000, {})
    rid, _ = _run(app, workspace, target, wordlist_dir=small_wordlist)
    with app.app_context():
        f = Finding.query.filter_by(run_id=rid, path="/admin").first()
        assert f.content_length == 250000


def test_ext_placeholder_expansion(app, workspace, target, mock_target, tmp_path):
    wl = tmp_path / "ext"
    wl.mkdir()
    (wl / "l.txt").write_text("config.%EXT%\nplain")
    mock_target.routes["/config.bak"] = (200, b"secret", {})
    rid, n = _run(app, workspace, target, wordlist_dir=str(wl), extensions="bak,old")
    with app.app_context():
        paths = {f.path for f in Finding.query.filter_by(run_id=rid)}
    assert "/config.bak" in paths


def test_humansize():
    assert _humansize(0) == "0B"
    assert _humansize(512) == "512B"
    assert _humansize(2048) == "2KB"
    assert _humansize(None) == "?"


def test_is_hit_rules():
    assert _is_hit(200, 100, None) is True
    assert _is_hit(404, 100, None) is False
    assert _is_hit(200, 14, (200, 14)) is False   # matches wildcard
    assert _is_hit(None, None, None) is False
