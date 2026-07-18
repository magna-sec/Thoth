"""ASN enrichment: Team Cymru response parsing + workspace analysis aggregation."""
from app.enrich import _parse_asname, _parse_origin, _rev4, asn_for_ip, asn_name, enrich
from app.extensions import db
from app.models import Target
from app.workspaces.routes import _analysis


def test_parse_origin():
    got = _parse_origin("15169 | 8.8.8.0/24 | US | arin | 1992-12-01")
    assert got == {"asn": "15169", "prefix": "8.8.8.0/24", "country": "US"}
    # multiple origin ASNs -> take the first
    assert _parse_origin("23028 1234 | 216.90.108.0/24 | US | arin")["asn"] == "23028"
    assert _parse_origin("") == {}


def test_parse_asname():
    assert _parse_asname("15169 | US | arin | 1992 | GOOGLE, US") == "GOOGLE, US"
    assert _parse_asname("") is None


def test_rev4():
    assert _rev4("1.2.3.4") == "4.3.2.1"


def test_enrich_offline_gracefully(monkeypatch):
    # No network: DNS helper returns None -> enrich yields ip (if resolvable) but no ASN.
    monkeypatch.setattr("app.enrich._txt", lambda name, timeout=3.0: None)
    asn_for_ip.cache_clear()
    asn_name.cache_clear()
    info = enrich("localhost")
    assert info["asn"] is None and info["asn_name"] is None


def test_enrich_with_mocked_cymru(monkeypatch):
    def fake_txt(name, timeout=3.0):
        if name.endswith("origin.asn.cymru.com"):
            return "15169 | 8.8.8.0/24 | US | arin | 1992"
        if name.startswith("AS15169"):
            return "15169 | US | arin | 1992 | GOOGLE, US"
        return None
    monkeypatch.setattr("app.enrich._txt", fake_txt)
    monkeypatch.setattr("app.enrich.resolve_ip", lambda host, timeout=3.0: "8.8.8.8")
    asn_for_ip.cache_clear()
    asn_name.cache_clear()
    info = enrich("dns.google")
    assert info["asn"] == "15169" and info["asn_name"] == "GOOGLE, US" and info["country"] == "US"


def test_analysis_aggregates_infra(app, workspace):
    with app.app_context():
        db.session.add_all([
            Target(workspace_id=workspace, host="a.test", scheme="https", last_alive=True,
                   last_waf="Cloudflare", last_tech="React,nginx", last_server="nginx",
                   asn="13335", asn_name="CLOUDFLARENET, US", country="US"),
            Target(workspace_id=workspace, host="b.test", scheme="https", last_alive=True,
                   last_waf="Cloudflare", last_tech="React", asn="13335",
                   asn_name="CLOUDFLARENET, US", country="US"),
            Target(workspace_id=workspace, host="c.test", scheme="https", last_alive=False,
                   asn="15169", asn_name="GOOGLE, US", country="US"),
        ])
        db.session.commit()
        a = _analysis(workspace)
    assert a["total"] == 3 and a["alive"] == 2 and a["dead"] == 1
    assert dict(a["waf"]) == {"Cloudflare": 2}
    assert dict(a["tech"])["React"] == 2
    asn_by = {r["asn"]: r for r in a["asn"]}
    assert asn_by["13335"]["hosts"] == 2 and asn_by["13335"]["name"] == "CLOUDFLARENET, US"
    assert asn_by["15169"]["hosts"] == 1
