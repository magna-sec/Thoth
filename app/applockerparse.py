"""Parse an AppLocker policy (``Get-AppLockerPolicy -Effective -Xml``) and flag the classic
bypass / coverage gaps.

AppLocker is Windows application allow-listing. Its well-known weaknesses — and what this
checks for — are: rule collections left **NotConfigured / AuditOnly** (so that file type
isn't blocked), the default **%WINDIR%\\* / %PROGRAMFILES%\\* allow** rules (those folders
contain user-writable subdirectories like ``\\Windows\\Temp`` and ``\\Tasks`` you can drop a
binary into), explicit **writable-path allow** rules, and **wildcard publisher** rules that
allow any signed binary (every Microsoft-signed LOLBin included). Pure XML parsing.
"""
from xml.etree import ElementTree as ET

RULE_TYPES = ("Exe", "Dll", "Msi", "Script", "Appx")
SENSITIVE = {"Exe", "Dll", "Script"}     # unrestricting these is the worst
SID_LABELS = {
    "s-1-1-0": "Everyone",
    "s-1-5-32-544": "Administrators",
    "s-1-5-32-545": "Users",
    "s-1-5-11": "Authenticated Users",
}
# Broad default allows — bypassable because these trees contain user-writable subfolders.
BROAD_ALLOW = {r"%windir%\*", r"%programfiles%\*", r"%programfiles(x86)%\*",
               r"%system32%\*", r"%osdrive%\*", r"%systemroot%\*"}
# Documented user-writable locations under %WINDIR% (AppLocker bypass folders).
WRITABLE = (r"\temp", r"\tasks", r"\tracing", r"\registration\crmlog",
            r"\system32\spool\drivers\color", r"\system32\spool\printers",
            r"\system32\spool\servers", r"\system32\fxstmp", r"\system32\com\dmp",
            r"\system32\microsoft\crypto\rsa\machinekeys", r"\debug\wia",
            r"\downloaded program files", r"\syswow64\tasks")


def looks_like_applocker(text):
    t = text or ""
    return "AppLockerPolicy" in t or ("RuleCollection" in t and (
        "FilePathRule" in t or "FilePublisherRule" in t or "FileHashRule" in t))


def _sid_label(sid):
    return SID_LABELS.get((sid or "").lower(), sid or "")


def _rule(el):
    kind = {"FilePathRule": "path", "FilePublisherRule": "publisher",
            "FileHashRule": "hash"}.get(el.tag)
    if not kind:
        return None
    sid = el.get("UserOrGroupSid", "")
    name = el.get("Name", "")
    out = {"kind": kind, "name": name, "action": el.get("Action", "Allow"),
           "sid": sid, "sid_label": _sid_label(sid),
           "description": el.get("Description", ""),
           "is_default": name.strip().lower().startswith("(default rule)"),
           "detail": ""}
    if kind == "path":
        c = el.find("./Conditions/FilePathCondition")
        out["path"] = c.get("Path", "") if c is not None else ""
        out["detail"] = out["path"]
    elif kind == "publisher":
        c = el.find("./Conditions/FilePublisherCondition")
        if c is not None:
            vr = c.find("BinaryVersionRange")
            out["publisher"] = c.get("PublisherName", "")
            out["product"] = c.get("ProductName", "*")
            out["binary"] = c.get("BinaryName", "*")
            out["ver_low"] = vr.get("LowSection", "*") if vr is not None else "*"
            out["ver_high"] = vr.get("HighSection", "*") if vr is not None else "*"
            out["detail"] = f"{out['publisher']} · {out['product']} · {out['binary']}"
    elif kind == "hash":
        c = el.find("./Conditions/FileHashCondition/FileHash")
        if c is not None:
            out["filename"] = c.get("SourceFileName", "")
            out["hash_type"] = c.get("Type", "")
            out["detail"] = out["filename"]
    return out


def _collection(rc):
    mode = rc.get("EnforcementMode", "NotConfigured")
    rules = [r for r in (_rule(el) for el in list(rc)) if r]
    return {
        "type": rc.get("Type", "?"),
        "mode": mode,
        "enabled": mode == "Enabled",
        "audit": mode == "AuditOnly",
        "rules": rules,
        "allow": sum(1 for r in rules if r["action"] == "Allow"),
        "deny": sum(1 for r in rules if r["action"] == "Deny"),
    }


def _findings(collections):
    out = []

    def add(sev, title, detail):
        out.append({"severity": sev, "title": title, "detail": detail})

    by_type = {c["type"]: c for c in collections}

    # 1. Enforcement gaps, per collection type.
    for t in RULE_TYPES:
        c = by_type.get(t)
        sensitive = t in SENSITIVE
        if c is None or c["mode"] == "NotConfigured":
            add("high" if sensitive else "medium", f"{t} rules not enforced",
                f"The {t} collection is {'absent' if c is None else 'NotConfigured'} — "
                f"{t} files are not restricted at all.")
        elif c["audit"]:
            add("medium", f"{t} in audit-only mode",
                f"The {t} collection logs but does not block — it enforces nothing.")

    # Only look at enabled collections for the allow-rule analysis.
    enabled = [c for c in collections if c["enabled"]]
    all_rules = [r for c in enabled for r in c["rules"]]

    # 2. Allow any file (path '*') to non-admins.
    for r in all_rules:
        if r["kind"] == "path" and r["action"] == "Allow" and r.get("path") == "*" \
                and r["sid"].lower() != "s-1-5-32-544":
            add("high", "Allows any executable (path '*')",
                f"Rule '{r['name']}' allows path '*' for {r['sid_label'] or r['sid']} — "
                f"no restriction on where binaries run from.")

    # 3. Explicit writable-path allow rule.
    for r in all_rules:
        if r["kind"] == "path" and r["action"] == "Allow":
            p = (r.get("path") or "").lower()
            if any(w in p for w in WRITABLE):
                add("high", "Allow rule covers a user-writable path",
                    f"Rule '{r['name']}' allows '{r['path']}', a user-writable location — "
                    f"drop a binary there to bypass AppLocker.")

    # 4. Broad default allows (%WINDIR%\* / %PROGRAMFILES%\*) contain writable subdirs.
    broad = [r for r in all_rules if r["kind"] == "path" and r["action"] == "Allow"
             and (r.get("path") or "").lower() in BROAD_ALLOW]
    if broad:
        add("medium", "Default broad-folder allow rules",
            "Allow rules cover %WINDIR%\\* / %PROGRAMFILES%\\* — those trees contain "
            "user-writable subfolders (e.g. C:\\Windows\\Temp, \\Tasks, "
            "\\System32\\spool\\drivers\\color) that bypass AppLocker.")

    # 5. Wildcard publisher rules — any signed binary / any version.
    for r in all_rules:
        if r["kind"] == "publisher" and r["action"] == "Allow" \
                and r.get("binary") == "*" and r.get("ver_low") == "*" \
                and r["sid"].lower() != "s-1-5-32-544":
            add("medium", "Wildcard publisher rule",
                f"Rule '{r['name']}' allows ANY binary / version from "
                f"{r.get('publisher', 'a publisher')} — a Microsoft wildcard admits signed "
                f"LOLBins (e.g. msbuild, installutil).")
            break

    # 6. Only default rules present.
    custom = [r for c in enabled for r in c["rules"] if not r["is_default"]]
    if enabled and not custom:
        add("medium", "Only the default rules are present",
            "No custom allow/deny rules — execution relies entirely on the default "
            "%WINDIR%/%PROGRAMFILES%/admin rules, which are bypassable via writable subdirs.")

    # 7. No deny rules anywhere (informational — pure allow-listing).
    if enabled and not any(c["deny"] for c in enabled):
        add("info", "No explicit deny rules",
            "The policy is allow-list only; no Deny rules block known-bad or LOLBin paths.")

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    out.sort(key=lambda f: order.get(f["severity"], 9))
    return out


def parse_applocker(text):
    """Parse an AppLocker policy XML. Returns ``{"collections","summary","findings"}``.
    Raises ValueError if it isn't an AppLocker policy."""
    text = (text or "").strip()
    if not text:
        raise ValueError("Nothing to parse — paste the AppLocker policy XML first.")
    if "AppLockerPolicy" not in text and "RuleCollection" not in text:
        raise ValueError("This doesn't look like an AppLocker policy "
                         "(no AppLockerPolicy / RuleCollection).")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise ValueError(f"Malformed AppLocker XML: {e}") from e

    collections = [_collection(rc) for rc in root.iter("RuleCollection")]
    if not collections:
        raise ValueError("No rule collections found in that AppLocker policy.")

    order = {t: i for i, t in enumerate(RULE_TYPES)}
    collections.sort(key=lambda c: order.get(c["type"], 99))
    summary = {
        "collections": len(collections),
        "rules": sum(len(c["rules"]) for c in collections),
        "enforced": sum(1 for c in collections if c["enabled"]),
        "modes": {c["type"]: c["mode"] for c in collections},
    }
    return {"collections": collections, "summary": summary,
            "findings": _findings(collections)}
