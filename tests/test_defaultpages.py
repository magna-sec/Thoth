"""Recognising server defaults and holding pages, and surfacing them in the gallery."""
from app.defaultpages import classify
from app.extensions import db
from app.models import Finding, Run, Target


def test_recognises_common_server_defaults():
    assert classify("IIS Windows Server") == "IIS default"
    assert classify("Welcome to nginx!") == "nginx default"
    assert classify("Apache2 Ubuntu Default Page: It works") == "Apache default"
    assert classify("Apache Tomcat/9.0.50") == "Tomcat default"


def test_recognises_parked_and_placeholder_pages():
    assert classify("This domain is parked") == "Parked"
    assert classify("Coming Soon") == "Placeholder"
    assert classify("Index of /") == "Placeholder"
    assert classify("404 Not Found") == "Error page"


def test_real_application_titles_are_not_flagged():
    assert classify("ACME CRM — Sign in") is None
    assert classify("Dashboard") is None
    # A titled page with a big body is content, even from nginx.
    assert classify("Our Products", server="nginx", content_length=48000) is None


def test_blank_pages_fall_back_to_the_server_header():
    assert classify("", server="Microsoft-IIS/10.0", content_length=200) == "IIS default"
    assert classify(None, server="unknown/1", content_length=0) == "Blank"
    # A blank title with a substantial body is a real (JS-rendered) app, not a default.
    assert classify("", server="nginx", content_length=90000) is None


def test_case_and_whitespace_insensitive():
    assert classify("  WELCOME TO NGINX!  ") == "nginx default"


def test_gallery_labels_defaults_and_counts_identical(client, app, workspace):
    with app.app_context():
        run = Run(workspace_id=workspace, module="screenshot", status="done")
        db.session.add(run)
        db.session.flush()
        # Two hosts serving the byte-identical IIS splash page, one real app.
        for host, title, sha in (("a.test", "IIS Windows Server", "deadbeef"),
                                 ("b.test", "IIS Windows Server", "deadbeef"),
                                 ("c.test", "ACME Portal", "cafe1234")):
            t = Target(workspace_id=workspace, host=host, scheme="https")
            db.session.add(t)
            db.session.flush()
            db.session.add(Finding(
                workspace_id=workspace, run_id=run.id, target_id=t.id, path="/",
                status_code=200,
                extra_json={"screenshot": f"t{t.id}_r{run.id}.png", "title": title,
                            "sha256": sha,
                            **({"default_page": "IIS default"} if sha == "deadbeef"
                               else {})}))
        db.session.commit()

    page = client.get(f"/workspaces/{workspace}").data.decode()
    assert "IIS default" in page          # labelled
    assert "×2" in page                   # the two identical captures are counted
    assert 'id="shot-default"' in page    # and can be filtered out
