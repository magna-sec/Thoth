"""Parse ASP.NET / IIS ``web.config`` files and surface the secrets and misconfigurations
they leak.

A ``web.config`` is where an ASP.NET app keeps its **connection strings** (often with a
plaintext SQL password), its **appSettings** (API keys, tokens, endpoint URLs), the
**machineKey** (static ViewState / forms-auth keys enable ViewState RCE and auth-ticket
forgery), Forms-auth ``<credentials>`` (sometimes plaintext user/password), an
``<identity impersonate>`` service account, SMTP creds, and hardening flags
(``debug="true"``, ``customErrors mode="Off"``, remote ``trace``). This parser reads all of
that statically — it makes no network requests.

Several files can be handed in at once (the upload accepts multiple, and the PowerShell
collector concatenates every ``web.config`` under a site with ``===== path =====`` headers);
each ``<configuration>`` document is parsed and reported separately.
"""
import re
from xml.etree import ElementTree as ET

# One <configuration>…</configuration> document (there is one per web.config file).
_CONFIG_RE = re.compile(r"<configuration\b[^>]*>.*?</configuration\s*>",
                        re.DOTALL | re.IGNORECASE)
# ===== C:\inetpub\wwwroot\app\web.config ===== markers emitted by the collector.
_HEADER_RE = re.compile(r"=====\s*(.+?)\s*=====")
_URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
# appSettings keys whose name alone marks the value as sensitive.
_SECRET_KEY = re.compile(
    r"pass(word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret"
    r"|account[_-]?key|private[_-]?key|connection[_-]?string|conn[_-]?str|credential"
    r"|\bsas\b|encrypt|signing[_-]?key", re.IGNORECASE)
# Hosts that only ever appear as XML-schema noise — never worth listing as a target URL.
_NOISE_HOST = ("schemas.microsoft.com", "schemas.xmlsoap.org", "www.w3.org",
               "schemas.openxmlformats.org", "docs.oasis-open.org", "tempuri.org")

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def looks_like_webconfig(text):
    """Auto-detect heuristic: an ASP.NET/IIS configuration document."""
    t = (text or "").lower()
    if "<configuration" not in t:
        return False
    return any(k in t for k in ("system.web", "system.webserver", "connectionstrings",
                                "appsettings", "machinekey", "runtime"))


def _local(tag):
    """Element tag without its XML namespace — web.config mixes namespaced sections."""
    return tag.rsplit("}", 1)[-1].lower()


def _find_local(el, name):
    for d in el.iter():
        if _local(d.tag) == name:
            return d
    return None


def _parse_conn(cs):
    """Break a SQL/ADO connection string into its notable parts."""
    parts = {}
    for seg in (cs or "").split(";"):
        if "=" in seg:
            k, v = seg.split("=", 1)
            parts[k.strip().lower()] = v.strip()

    def g(*keys):
        for k in keys:
            if parts.get(k):
                return parts[k]
        return ""

    integrated = g("integrated security", "trusted_connection").lower()
    return {
        "server": g("server", "data source", "address", "addr", "network address", "host"),
        "database": g("database", "initial catalog", "aliasname"),
        "user": g("user id", "uid", "user", "username", "user name"),
        "password": g("password", "pwd"),
        "integrated": integrated in ("true", "sspi", "yes"),
    }


def _split_documents(text):
    """Yield ``(name, xml)`` for each web.config in the (possibly concatenated) blob."""
    headers = [(m.start(), m.group(1).strip()) for m in _HEADER_RE.finditer(text)]

    def name_before(pos, idx):
        name = ""
        for hpos, h in headers:
            if hpos < pos:
                name = h
            else:
                break
        return name or f"web.config #{idx}"

    blocks = list(_CONFIG_RE.finditer(text))
    if not blocks:                     # a fragment with no <configuration> wrapper
        yield "web.config", text
        return
    for i, m in enumerate(blocks, 1):
        yield name_before(m.start(), i), m.group()


def _parse_one(name, xml):
    """Parse a single web.config document into its extracted secrets/settings."""
    out = {"name": name, "connection_strings": [], "app_settings": [], "machine_key": None,
           "credentials": [], "identity": None, "smtp": None, "flags": [], "urls": [],
           "error": ""}
    try:
        root = ET.fromstring(xml.lstrip("\ufeff").strip())
    except ET.ParseError as e:
        out["error"] = f"Malformed XML: {e}"
        return out

    for el in root.iter():
        tag, at = _local(el.tag), el.attrib
        cs = at.get("connectionString") or at.get("connectionstring")
        if cs is not None:
            parsed = _parse_conn(cs)
            out["connection_strings"].append({
                "name": at.get("name") or at.get("Name") or "",
                "provider": at.get("providerName", ""), "value": cs[:1024],
                "parsed": parsed, "has_password": bool(parsed["password"])})
        elif tag == "add" and "key" in at and "value" in at:
            key, val = at["key"], at["value"]
            low = val.lower()
            out["app_settings"].append({
                "key": key, "value": val[:1024],
                "secret": bool(_SECRET_KEY.search(key)) or "password=" in low
                or "pwd=" in low,
                "is_url": low.strip().startswith(("http://", "https://"))})
        elif tag == "machinekey":
            vk, dk = at.get("validationKey", ""), at.get("decryptionKey", "")
            static = (("autogenerate" not in vk.lower() and vk)
                      or ("autogenerate" not in dk.lower() and dk))
            out["machine_key"] = {
                "validationKey": vk, "decryptionKey": dk,
                "validation": at.get("validation", ""),
                "decryption": at.get("decryption", ""), "static": bool(static)}
        elif tag == "credentials":
            fmt = at.get("passwordFormat", "Clear")
            for u in el.iter():
                if _local(u.tag) == "user":
                    out["credentials"].append({
                        "user": u.get("name", ""), "password": u.get("password", ""),
                        "format": fmt})
        elif tag == "identity" and str(at.get("impersonate", "")).lower() == "true" \
                and at.get("userName"):
            out["identity"] = {"user": at.get("userName", ""),
                               "password": at.get("password", "")}
        elif tag == "smtp":
            net = _find_local(el, "network")
            if net is not None:
                out["smtp"] = {"host": net.get("host", ""), "port": net.get("port", ""),
                               "user": net.get("userName", ""),
                               "password": net.get("password", ""),
                               "from": el.get("from", "")}
        elif tag == "customerrors" and at.get("mode", "").lower() == "off":
            out["flags"].append(("medium", "customErrors mode=\"Off\"",
                                 "Detailed ASP.NET error pages (stack traces, paths) are "
                                 "shown to every visitor."))
        elif tag == "compilation" and str(at.get("debug", "")).lower() == "true":
            out["flags"].append(("medium", "compilation debug=\"true\"",
                                 "Debug build — leaks source paths, disables optimisations, "
                                 "and lengthens request timeouts."))
        elif tag == "trace" and str(at.get("enabled", "")).lower() == "true":
            remote = str(at.get("localOnly", "true")).lower() == "false"
            out["flags"].append(("medium" if remote else "low",
                                 "ASP.NET trace enabled",
                                 "trace.axd exposes requests, cookies and server variables"
                                 + (" to remote clients (localOnly=false)." if remote
                                    else " (localOnly).")))
        elif tag == "httpcookies" and (str(at.get("requireSSL", "true")).lower() == "false"
                                       or str(at.get("httpOnlyCookies", "true")).lower()
                                       == "false"):
            out["flags"].append(("low", "Weak cookie settings",
                                 "httpCookies has requireSSL or httpOnlyCookies disabled."))

    seen = set()
    for u in _URL_RE.findall(xml):
        u = u.rstrip(".,;\"'")
        host = u.split("//", 1)[-1].split("/", 1)[0].lower()
        if any(n in host for n in _NOISE_HOST) or u in seen:
            continue
        seen.add(u)
        out["urls"].append(u)
    return out


def _findings(files):
    """Roll every file's extracted material into severity-ranked findings."""
    out = []

    def add(sev, title, detail, where):
        out.append({"severity": sev, "title": title, "detail": detail, "file": where})

    for f in files:
        where = f["name"]
        if f["error"]:
            add("info", "Could not parse document", f["error"], where)
        for cs in f["connection_strings"]:
            p, label = cs["parsed"], cs["name"] or "(unnamed)"
            target = "/".join(x for x in (p["server"], p["database"]) if x)
            if cs["has_password"]:
                who = f"{p['user']}@" if p["user"] else ""
                add("high", "Connection-string password",
                    f"'{label}' → {who}{target or 'db'} — password: {p['password']}", where)
            elif p["integrated"]:
                add("info", "Connection string (Integrated Security)",
                    f"'{label}' → {target or 'db'} uses Windows auth (no stored password).",
                    where)
            elif target:
                add("low", "Connection string",
                    f"'{label}' → {target}" + (f" as {p['user']}" if p["user"] else ""),
                    where)
        mk = f["machine_key"]
        if mk and mk["static"]:
            add("high", "Static machineKey",
                "Hard-coded validation/decryption keys — forge ViewState "
                "(__VIEWSTATE RCE) and forms-auth / anti-CSRF tokens: "
                f"validationKey={mk['validationKey'][:24]}…", where)
        for c in f["credentials"]:
            if c["format"].lower() == "clear":
                add("high", "Forms-auth plaintext credentials",
                    f"<credentials> user '{c['user']}' password: {c['password']}", where)
            else:
                add("medium", "Forms-auth stored credentials",
                    f"user '{c['user']}' — {c['format']} hash of the password "
                    f"({c['password'][:32]}…), crackable offline.", where)
        if f["identity"]:
            i = f["identity"]
            add("high" if i["password"] else "medium", "Impersonation identity",
                f"<identity impersonate> as {i['user']}"
                + (f" — password: {i['password']}" if i["password"]
                   else " (password not stored here)."), where)
        s = f["smtp"]
        if s and s["password"]:
            add("medium", "SMTP credentials",
                f"{s['user']}:{s['password']}@{s['host']}"
                + (f":{s['port']}" if s["port"] else ""), where)
        for a in f["app_settings"]:
            if a["secret"]:
                add("medium", "Secret in appSettings",
                    f"{a['key']} = {a['value']}", where)
        for sev, title, detail in f["flags"]:
            add(sev, title, detail, where)

    out.sort(key=lambda x: _SEV_ORDER.get(x["severity"], 9))
    return out


def parse_webconfig(text):
    """Parse one or more web.config documents.

    Returns ``{"files", "summary", "findings"}``. Raises ``ValueError`` when the text holds
    no configuration document at all.
    """
    text = (text or "").strip()
    if not text:
        raise ValueError("Nothing to parse — paste or upload a web.config first.")
    if "<configuration" not in text.lower() and "connectionstring" not in text.lower() \
            and "appsettings" not in text.lower():
        raise ValueError("This doesn't look like a web.config "
                         "(no <configuration> / connectionStrings / appSettings).")

    files = [_parse_one(name, xml) for name, xml in _split_documents(text)]
    if not any(f["connection_strings"] or f["app_settings"] or f["machine_key"]
               or f["credentials"] or f["identity"] or f["smtp"] or f["flags"]
               or f["urls"] for f in files) and all(f["error"] for f in files):
        raise ValueError("Couldn't parse any web.config document from that text.")

    findings = _findings(files)
    summary = {
        "files": len(files),
        "connection_strings": sum(len(f["connection_strings"]) for f in files),
        "secrets": sum(1 for x in findings if x["severity"] in ("critical", "high", "medium")),
        "urls": len({u for f in files for u in f["urls"]}),
    }
    return {"files": files, "summary": summary, "findings": findings}
