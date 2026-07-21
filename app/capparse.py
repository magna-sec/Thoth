"""Parse Entra ID (Azure AD) **Conditional Access** policies — e.g. a ROADrecon dump or a
Microsoft Graph export — and flag the classic **coverage gaps**.

Conditional Access is Entra ID's policy engine; the gaps below are the ones every CA review
looks for (and that tooling like ROADtools, Maester, and CAOptics test): legacy-auth not
blocked, MFA not required for everyone, admins unprotected, exclusion "backdoors",
MFA scoped to browsers only, and trusted-location IP bypasses. Pure JSON parsing.

Accepts the documented Graph shape (``displayName`` / ``state`` / ``conditions`` /
``grantControls``) as a bare array, ``{"value":[…]}``, ``{"policies":[…]}``, or a single
policy object.
"""
import json

STATE_LABEL = {
    "enabled": "enabled",
    "enabledforreportingbutnotenforced": "report-only",
    "disabled": "disabled",
}
# Legacy authentication client types (no modern-auth / MFA support).
LEGACY_CLIENTS = {"exchangeactivesync", "other"}


def looks_like_cap(text):
    t = (text or "").lower()
    return ("grantcontrols" in t or "conditionalaccess" in t
            or ("displayname" in t and ("clientapptypes" in t or "builtincontrols" in t)))


def _as_list(value):
    return value if isinstance(value, list) else []


def _lower_list(values):
    # Sorted, de-duped, lowercased — kept as a list so the result is JSON-serialisable
    # (it's stored in an Artifact). Analysis wraps it in set() where it needs membership.
    return sorted({str(v).strip().lower() for v in _as_list(values)})


def _has_all(values):
    return any(str(v).strip().lower() == "all" for v in _as_list(values))


def _policy(obj):
    """Normalise one policy dict to the fields we care about."""
    if not isinstance(obj, dict):
        return None
    name = obj.get("displayName") or obj.get("name") or obj.get("id") or "(unnamed policy)"
    state = (obj.get("state") or "").strip().lower()
    cond = obj.get("conditions") or {}
    users = cond.get("users") or {}
    apps = cond.get("applications") or {}
    locs = cond.get("locations") or {}
    plats = cond.get("platforms") or {}
    grant = obj.get("grantControls") or {}

    return {
        "name": name,
        "state": state,
        "state_label": STATE_LABEL.get(state, state or "unknown"),
        "enabled": state == "enabled",
        "report_only": state == "enabledforreportingbutnotenforced",
        "users_include": _as_list(users.get("includeUsers")),
        "users_exclude": _as_list(users.get("excludeUsers")),
        "groups_include": _as_list(users.get("includeGroups")),
        "groups_exclude": _as_list(users.get("excludeGroups")),
        "roles_include": _as_list(users.get("includeRoles")),
        "roles_exclude": _as_list(users.get("excludeRoles")),
        "apps_include": _as_list(apps.get("includeApplications")),
        "apps_exclude": _as_list(apps.get("excludeApplications")),
        "client_app_types": _lower_list(cond.get("clientAppTypes")),
        "platforms_include": _as_list(plats.get("includePlatforms")),
        "platforms_exclude": _as_list(plats.get("excludePlatforms")),
        "locations_include": _as_list(locs.get("includeLocations")),
        "locations_exclude": _as_list(locs.get("excludeLocations")),
        "user_risk": _as_list(cond.get("userRiskLevels")),
        "signin_risk": _as_list(cond.get("signInRiskLevels")),
        "grant_operator": (grant.get("operator") or "OR"),
        "grant_controls": _lower_list(grant.get("builtInControls")),
        "session_controls": sorted((obj.get("sessionControls") or {}).keys())
        if isinstance(obj.get("sessionControls"), dict) else [],
    }


def _policies_from(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("value", "policies", "conditionalAccessPolicies", "ConditionalAccessPolicies"):
            if isinstance(data.get(key), list):
                return data[key]
        if data.get("displayName") or data.get("conditions") or data.get("grantControls"):
            return [data]
    return []


def _has_exclusions(p):
    return any(p[k] for k in ("users_exclude", "groups_exclude", "roles_exclude"))


def _strong_auth(p):
    """Does the policy require a strong control (MFA or a compliant/joined device)?"""
    return bool(set(p["grant_controls"]) & {"mfa", "compliantdevice", "domainjoineddevice"})


def analyse_gaps(policies):
    """Tenant-level Conditional Access coverage gaps, most severe first.
    `policies` is the normalised list; only *enabled* policies actually protect anything."""
    out = []

    def add(sev, title, detail):
        out.append({"severity": sev, "title": title, "detail": detail})

    enabled = [p for p in policies if p["enabled"]]

    if not policies:
        add("critical", "No Conditional Access policies",
            "No CA policies at all — access is unrestricted unless Security Defaults are on.")
        return out
    if not enabled:
        add("high", "No enabled policies",
            f"All {len(policies)} policy(ies) are disabled or report-only — none is enforced.")

    # Legacy authentication (no MFA support) should be blocked outright.
    legacy_blocked = any("block" in p["grant_controls"]
                         and set(p["client_app_types"]) & LEGACY_CLIENTS
                         for p in enabled)
    if not legacy_blocked:
        add("high", "Legacy authentication not blocked",
            "No enabled policy blocks legacy auth clients (Exchange ActiveSync / 'other') — "
            "these bypass MFA and are the #1 account-takeover vector.")

    # MFA / strong auth for everyone.
    broad_mfa = any(_strong_auth(p) and _has_all(p["users_include"]) and _has_all(p["apps_include"])
                    for p in enabled)
    if not broad_mfa:
        add("high", "MFA not required for all users",
            "No enabled policy requires MFA (or a compliant device) for All users and All "
            "cloud apps — coverage has gaps.")

    # Admin / privileged-role protection.
    admin_protected = any(_strong_auth(p) and (p["roles_include"] or _has_all(p["users_include"]))
                          for p in enabled)
    if not admin_protected:
        add("high", "Privileged roles may be unprotected",
            "No enabled policy requires strong auth for directory roles or All users — admin "
            "sign-ins may not be MFA-protected.")

    # Exclusions are the usual backdoor (break-glass is legitimate, broad exclusions aren't).
    excluded = [p for p in enabled if _has_exclusions(p)]
    if excluded:
        add("medium", "Policies with exclusions",
            f"{len(excluded)} enabled policy(ies) exclude users/groups/roles — verify each is "
            f"a monitored break-glass account and not an unmonitored bypass: "
            + ", ".join(p["name"] for p in excluded[:8]) + ".")

    # MFA scoped to browsers only — rich/mobile clients then slip past.
    for p in enabled:
        if "mfa" in p["grant_controls"] and set(p["client_app_types"]) == {"browser"}:
            add("medium", "MFA enforced for browsers only",
                f"'{p['name']}' requires MFA only for browser sessions — desktop/mobile "
                f"clients are not covered.")
            break

    # Trusted / named location excluded from an MFA policy — an IP-based MFA bypass.
    for p in enabled:
        if _strong_auth(p) and p["locations_exclude"]:
            add("medium", "MFA bypassed from excluded locations",
                f"'{p['name']}' excludes location(s) {', '.join(map(str, p['locations_exclude'][:4]))} "
                f"from strong auth — anyone on those IPs skips MFA.")
            break

    # Device compliance never required.
    if enabled and not any(set(p["grant_controls"]) & {"compliantdevice", "domainjoineddevice"}
                           for p in enabled):
        add("low", "Device compliance never required",
            "No enabled policy requires a compliant or hybrid-joined device — sign-ins are "
            "allowed from unmanaged devices.")

    # Risk-based policies absent (needs Entra ID P2).
    if enabled and not any(p["user_risk"] or p["signin_risk"] for p in enabled):
        add("info", "No risk-based policies",
            "No enabled policy acts on user or sign-in risk (Entra ID P2 Identity Protection).")

    # Report-only / disabled policies — coverage you might think you have but don't.
    inactive = [p for p in policies if not p["enabled"]]
    if inactive:
        add("info", "Report-only / disabled policies",
            f"{len(inactive)} policy(ies) are not enforced: "
            + ", ".join(f"{p['name']} ({p['state_label']})" for p in inactive[:8]) + ".")

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out.sort(key=lambda f: order.get(f["severity"], 9))
    return out


def parse_cap(text):
    """Parse Conditional Access policy JSON. Returns ``{"policies","summary","findings"}``.
    Raises ValueError if it isn't CA policy data."""
    text = (text or "").strip()
    if not text:
        raise ValueError("Nothing to parse — paste Conditional Access policy JSON first.")
    try:
        data = json.loads(text)
    except ValueError as e:
        raise ValueError(f"Not valid JSON: {e}") from e

    raw = _policies_from(data)
    policies = [p for p in (_policy(o) for o in raw) if p]
    if not policies:
        raise ValueError("No Conditional Access policies found. Expecting Graph CA policy "
                         "JSON (displayName / conditions / grantControls).")

    policies.sort(key=lambda p: (0 if p["enabled"] else 1, p["name"].lower()))
    summary = {
        "total": len(policies),
        "enabled": sum(1 for p in policies if p["enabled"]),
        "report_only": sum(1 for p in policies if p["report_only"]),
        "disabled": sum(1 for p in policies if p["state"] == "disabled"),
    }
    return {"policies": policies, "summary": summary, "findings": analyse_gaps(policies)}
