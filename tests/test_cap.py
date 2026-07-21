"""ROADrecon / Conditional Access parser and gap analysis."""
import json

import pytest

from app.capparse import analyse_gaps, looks_like_cap, parse_cap
from app.extensions import db
from app.models import Artifact


def _pol(name, state="enabled", include=("All",), exclude=(), apps=("All",),
         clients=("all",), controls=("mfa",), roles=(), loc_excl=(), risk=()):
    return {"displayName": name, "state": state,
            "conditions": {"users": {"includeUsers": list(include),
                                     "excludeUsers": list(exclude),
                                     "includeRoles": list(roles)},
                           "applications": {"includeApplications": list(apps)},
                           "clientAppTypes": list(clients),
                           "locations": {"excludeLocations": list(loc_excl)},
                           "signInRiskLevels": list(risk)},
            "grantControls": {"operator": "OR", "builtInControls": list(controls)}}


def _titles(policies):
    return {f["title"] for f in analyse_gaps(policies_normalised(policies))}


def policies_normalised(raw):
    return parse_cap(json.dumps({"value": raw}))["policies"]


def test_accepts_various_shapes():
    p = _pol("x")
    assert parse_cap(json.dumps([p]))["summary"]["total"] == 1        # bare array
    assert parse_cap(json.dumps({"value": [p]}))["summary"]["total"] == 1
    assert parse_cap(json.dumps(p))["summary"]["total"] == 1          # single object


def test_detection_and_rejection():
    assert looks_like_cap(json.dumps(_pol("x")))
    with pytest.raises(ValueError):
        parse_cap("not json")
    with pytest.raises(ValueError):
        parse_cap(json.dumps({"value": []}))     # no policies


def test_no_policies_is_critical():
    with pytest.raises(ValueError):
        parse_cap(json.dumps([]))                # empty -> rejected
    # A single disabled policy: enabled=0 -> high.
    assert "No enabled policies" in _titles([_pol("d", state="disabled")])


def test_good_baseline_has_no_high_gaps():
    good = [
        _pol("MFA all", controls=("mfa",)),
        _pol("Block legacy", clients=("exchangeActiveSync", "other"), controls=("block",)),
        _pol("Compliant device", controls=("compliantDevice",)),
        _pol("Risk", risk=("high",), controls=("mfa",)),
    ]
    titles = _titles(good)
    assert "Legacy authentication not blocked" not in titles
    assert "MFA not required for all users" not in titles
    assert "Privileged roles may be unprotected" not in titles
    assert "Device compliance never required" not in titles


def test_flags_the_classic_gaps():
    # Only a report-only legacy block + a browser-only MFA with a trusted-location exclusion.
    policies = [
        _pol("MFA browser only", clients=("browser",), loc_excl=("AllTrusted",)),
        _pol("Block legacy (report only)", state="enabledForReportingButNotEnforced",
             clients=("exchangeActiveSync", "other"), controls=("block",)),
    ]
    titles = _titles(policies)
    assert "Legacy authentication not blocked" in titles     # the block isn't enabled
    assert "MFA enforced for browsers only" in titles
    assert "MFA bypassed from excluded locations" in titles
    assert "Report-only / disabled policies" in titles


def test_exclusions_flagged():
    assert "Policies with exclusions" in _titles([_pol("mfa", exclude=("bg-guid",))])
    assert "Policies with exclusions" not in _titles([_pol("mfa")])


def test_missing_broad_mfa_flagged():
    # MFA only for a single app, not All -> broad MFA gap.
    titles = _titles([_pol("scoped", apps=("some-app-guid",))])
    assert "MFA not required for all users" in titles


def test_plugin_registered_and_route_renders(client, app, workspace):
    from app.plugins import get_parser
    p = get_parser("roadrecon-cap")
    assert p is not None and p.kind == "artifact"

    payload = json.dumps({"value": [
        _pol("MFA browser only", clients=("browser",)),
        _pol("Block legacy (report only)", state="enabledForReportingButNotEnforced",
             clients=("exchangeActiveSync", "other"), controls=("block",))]})
    page = client.post(f"/workspaces/{workspace}/artifacts",
                       data={"content": payload, "kind": "auto"},
                       follow_redirects=True).data.decode()
    with app.app_context():
        art = Artifact.query.filter_by(workspace_id=workspace, kind="roadrecon-cap").one()
        assert art.data_json["summary"]["total"] == 2
    assert "Legacy authentication not blocked" in page
    assert "Coverage gaps" in page and "MFA browser only" in page
