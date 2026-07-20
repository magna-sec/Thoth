"""Parsing pasted dirsearch output, and folding it into findings + the dedup ledger."""
import json

import pytest

from app.extensions import db
from app.importers import ImportError_, ledger_key, parse_dirsearch, parse_size
from app.models import Finding, Run, Target, TestedPath

TERMINAL = """
  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, html | HTTP method: GET | Threads: 25
Target: http://sub.example.com/

[12:34:56] Starting:
[12:34:57] 200 -    1KB - /admin/
[12:34:57] 301 -  169B  - /js  ->  http://sub.example.com/js/
[12:34:58] 403 -  278B  - /.git/HEAD
[12:34:59] 200 -   12KB - /admin/login.php

Task Completed
"""


def test_parses_terminal_output():
    rows, hosts = parse_dirsearch(TERMINAL)
    by_path = {r["path"]: r for r in rows}
    assert set(by_path) == {"/admin/", "/js", "/.git/HEAD", "/admin/login.php"}
    assert by_path["/admin/"]["status_code"] == 200
    assert by_path["/admin/"]["content_length"] == 1024
    assert by_path["/.git/HEAD"]["content_length"] == 278
    assert by_path["/js"]["redirect"] == "/js/"
    assert hosts == {"sub.example.com"}
    # Banner/summary lines are not mistaken for results.
    assert "/Completed" not in by_path


def test_parses_json_report():
    text = json.dumps({"results": [
        {"url": "https://a.test/admin", "status": 200, "content-length": 4096,
         "redirect": ""},
        {"url": "https://a.test/old", "status": 301, "content-length": 0,
         "redirect": "https://a.test/new"},
    ]})
    rows, hosts = parse_dirsearch(text)
    assert {r["path"] for r in rows} == {"/admin", "/old"}
    assert [r for r in rows if r["path"] == "/admin"][0]["content_length"] == 4096
    assert [r for r in rows if r["path"] == "/old"][0]["redirect"] == "https://a.test/new"
    assert hosts == {"a.test"}


def test_parses_csv_and_markdown_reports():
    csv_text = ("URL,Status,Size,Content Type,Redirection\n"
                "http://b.test/admin,200,1KB,text/html,\n"
                "http://b.test/backup.zip,200,5MB,application/zip,\n")
    rows, _ = parse_dirsearch(csv_text)
    assert {r["path"]: r["content_length"] for r in rows} == {
        "/admin": 1024, "/backup.zip": 5 * 1024 ** 2}

    md_text = ("| URL | Status | Size | Content Type | Redirection |\n"
               "|-----|--------|------|--------------|-------------|\n"
               "| http://b.test/admin | 403 | 278B | text/html | |\n")
    rows, _ = parse_dirsearch(md_text)
    assert rows == [{"path": "/admin", "status_code": 403, "content_length": 278,
                     "redirect": None}]


def test_parses_simple_url_list():
    rows, hosts = parse_dirsearch("https://c.test/admin\nhttps://c.test/api/v1\n")
    assert {r["path"] for r in rows} == {"/admin", "/api/v1"}
    assert all(r["status_code"] is None for r in rows)
    assert hosts == {"c.test"}


def test_query_strings_and_duplicates_kept_sane():
    rows, _ = parse_dirsearch("200 - 1KB - /search?q=1\n200 - 2KB - /search?q=1\n")
    assert len(rows) == 1 and rows[0]["path"] == "/search?q=1"


def test_rejects_junk():
    with pytest.raises(ImportError_):
        parse_dirsearch("just some prose, 404 responses were boring\n")
    with pytest.raises(ImportError_):
        parse_dirsearch("   ")


def test_parse_size_units():
    assert parse_size("169B") == 169
    assert parse_size("1KB") == 1024
    assert parse_size("1.5MB") == int(1.5 * 1024 ** 2)
    assert parse_size("4096") == 4096
    assert parse_size("weird") is None


def test_ledger_key_matches_fuzzer_layout():
    assert ledger_key("/admin") == ("/", "admin")
    assert ledger_key("/admin/") == ("/", "admin")
    assert ledger_key("/admin/login.php") == ("/admin/", "login.php")
    assert ledger_key("/a/b/c") == ("/a/b/", "c")
    assert ledger_key("/search?q=1") == ("/", "search")
    assert ledger_key("/")[1] == ""  # nothing to record for the root


def test_import_route_creates_run_findings_and_ledger(client, app, workspace):
    with app.app_context():
        t = Target(workspace_id=workspace, host="sub.example.com", scheme="http")
        db.session.add(t)
        db.session.commit()
        tid = t.id

    client.post(f"/workspaces/{workspace}/domains/{tid}/import-dirsearch",
                data={"results": TERMINAL}, follow_redirects=True)

    with app.app_context():
        run = Run.query.filter_by(workspace_id=workspace).one()
        assert run.module == "dirsearch-import" and run.status == "done"
        findings = Finding.query.filter_by(run_id=run.id).all()
        assert {f.path for f in findings} == {"/admin/", "/js", "/.git/HEAD",
                                              "/admin/login.php"}
        # Imported paths land in the dedup ledger so a later fuzz skips that work.
        ledger = {(p.parent_path, p.word) for p in
                  TestedPath.query.filter_by(workspace_id=workspace).all()}
        assert ("/", "admin") in ledger
        assert ("/admin/", "login.php") in ledger
        assert ("/.git/", "HEAD") in ledger


def test_import_is_idempotent_against_the_ledger(client, app, workspace):
    """Importing the same output twice must not blow up on the ledger's unique key."""
    with app.app_context():
        t = Target(workspace_id=workspace, host="sub.example.com", scheme="http")
        db.session.add(t)
        db.session.commit()
        tid = t.id
    url = f"/workspaces/{workspace}/domains/{tid}/import-dirsearch"
    client.post(url, data={"results": TERMINAL}, follow_redirects=True)
    resp = client.post(url, data={"results": TERMINAL}, follow_redirects=True)
    assert resp.status_code == 200
    with app.app_context():
        assert Run.query.filter_by(workspace_id=workspace).count() == 2
        # Second import adds findings again but no duplicate ledger rows.
        assert TestedPath.query.filter_by(workspace_id=workspace).count() == 4


def test_import_accepts_multiple_files_at_once(client, app, workspace):
    """A host is usually fuzzed in several passes, each with its own report file."""
    import io
    with app.app_context():
        t = Target(workspace_id=workspace, host="multi.test", scheme="https")
        db.session.add(t)
        db.session.commit()
        tid = t.id

    client.post(f"/workspaces/{workspace}/domains/{tid}/import-dirsearch",
                data={"results": "", "file": [
                    (io.BytesIO(b"200 - 1KB - /from-first\n"), "pass1.txt"),
                    (io.BytesIO(b"403 - 278B - /from-second\n"), "pass2"),  # no extension
                ]},
                content_type="multipart/form-data", follow_redirects=True)

    with app.app_context():
        run = Run.query.filter_by(workspace_id=workspace).one()
        assert {f.path for f in Finding.query.filter_by(run_id=run.id).all()} == {
            "/from-first", "/from-second"}
        assert run.config_json["source"] == "pass1.txt, pass2"


def test_import_warns_about_a_different_host(client, app, workspace):
    with app.app_context():
        t = Target(workspace_id=workspace, host="mine.test", scheme="https")
        db.session.add(t)
        db.session.commit()
        tid = t.id
    page = client.post(f"/workspaces/{workspace}/domains/{tid}/import-dirsearch",
                       data={"results": "200 - 1KB - http://someoneelse.test/admin"},
                       follow_redirects=True).data.decode()
    assert "someoneelse.test" in page


def test_import_rejects_junk_with_a_flash(client, app, workspace):
    with app.app_context():
        t = Target(workspace_id=workspace, host="j.test", scheme="https")
        db.session.add(t)
        db.session.commit()
        tid = t.id
    page = client.post(f"/workspaces/{workspace}/domains/{tid}/import-dirsearch",
                       data={"results": "nothing useful here"},
                       follow_redirects=True).data.decode()
    assert "Couldn&#39;t find any results" in page or "Couldn't find any results" in page
    with app.app_context():
        assert Run.query.filter_by(workspace_id=workspace).count() == 0
