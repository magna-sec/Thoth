"""Shortlisting the interesting URLs on a host: parameters, keywords, and flags."""
from app.extensions import db
from app.models import Finding, Target
from app.urlinsights import analyse, classify, keywords, param_names, split_url


def test_split_url_handles_absolute_and_relative():
    assert split_url("https://a.test/search?q=1") == ("/search", "q=1")
    assert split_url("/search?q=1") == ("/search", "q=1")
    assert split_url("/admin") == ("/admin", "")
    assert split_url("") == ("", "")


def test_param_names_in_order_deduped():
    assert param_names("/s?q=1&page=2&q=3") == ["q", "page"]
    assert param_names("/x?debug") == ["debug"]        # valueless params still count
    assert param_names("/plain") == []


def test_keywords_match_by_theme():
    assert "search" in dict(keywords("/search.php"))
    assert "admin" in dict(keywords("/wp-admin/"))
    assert "exposure" in dict(keywords("/.git/HEAD"))
    assert "api" in dict(keywords("/api/v1/users"))
    assert keywords("/xyzzy") == []


def test_keywords_carry_a_reason():
    for label, why in keywords("/search?q=1"):
        assert why and len(why) > 10, label


def test_classify_flags_redirect_and_id_params():
    r = classify("/go?url=https://evil.test")
    assert "redirect-param" in r["flags"]
    r = classify("/account?id=42")
    assert "id-param" in r["flags"]
    assert "dynamic" in classify("/index.php")["flags"]
    assert classify("/static/logo.svg")["flags"] == []


def test_parameters_outrank_names():
    """A path taking input beats one that merely looks interesting."""
    rows, _ = analyse(["/admin", "/thing?id=1&next=/x"])
    assert rows[0]["path"] == "/thing"


def test_analyse_summarises_and_dedupes():
    rows, summary = analyse([
        "/search?q=a", "/search?q=a",           # duplicate collapses
        "/products?id=1", "/admin/", "/static/app.css",
    ])
    paths = [r["path"] for r in rows]
    assert "/static/app.css" not in paths       # nothing notable about it
    assert summary["scanned"] == 4
    assert summary["with_params"] == 2
    assert dict(summary["params"]) == {"q": 1, "id": 1}
    assert "admin" in dict(summary["labels"])


def test_analyse_respects_the_limit():
    rows, summary = analyse([f"/p{i}?id={i}" for i in range(30)], limit=10)
    assert len(rows) == 10 and summary["truncated"] == 20


def test_domain_page_shows_interesting_urls(client, app, workspace):
    with app.app_context():
        t = Target(workspace_id=workspace, host="u.test", scheme="https")
        db.session.add(t)
        db.session.flush()
        for path in ("/search?q=test", "/static/app.css", "/admin/"):
            db.session.add(Finding(workspace_id=workspace, target_id=t.id, path=path,
                                   status_code=200))
        # A redirect target contributes its parameters too.
        db.session.add(Finding(workspace_id=workspace, target_id=t.id, path="/go",
                               status_code=302, redirect="https://u.test/out?url=x"))
        db.session.commit()
        tid = t.id

    page = client.get(f"/workspaces/{workspace}/domains/{tid}").data.decode()
    assert 'data-pane="urls"' in page
    assert "/search" in page and "redirect-param" in page
    assert "Interesting URLs" in page
