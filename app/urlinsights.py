"""Pick the interesting URLs out of a host's findings.

After a fuzz a subdomain can carry thousands of paths, and the ones worth a human's
attention are a small subset: those that take **parameters** (an input surface) and those
whose name hints at what they do (``/search``, ``/admin``, ``/upload``). This turns a flat
path list into that shortlist, and collects every distinct parameter name seen on the host
— which doubles as a ready-made param wordlist for the next tool.

Pure functions over strings: no ORM, no requests, so it is cheap to call per page render
and trivial to test.
"""
import re
from urllib.parse import parse_qsl, urlsplit

# (label, needles, why) — matched against the path, case-insensitively. `why` is shown as
# the chip's tooltip so a label never appears without saying what it's hinting at.
KEYWORD_RULES = [
    ("search", ("search", "query", "find", "lookup", "filter"),
     "Search endpoints commonly reflect input — XSS/SQLi surface"),
    ("admin", ("admin", "manage", "console", "dashboard", "cpanel", "wp-admin"),
     "Administrative area — check access control"),
    ("auth", ("login", "signin", "sign-in", "auth", "sso", "oauth", "saml", "logout",
              "register", "password", "reset"),
     "Authentication flow"),
    ("api", ("/api", "graphql", "/rest", "/v1", "/v2", "swagger", "openapi", ".json",
             "wsdl", "soap"),
     "Machine interface — often less hardened than the UI"),
    ("upload", ("upload", "import", "attachment", "file", "media"),
     "File handling — upload restrictions and path traversal"),
    ("redirect", ("redirect", "return", "callback", "continue", "goto", "next"),
     "Possible open redirect"),
    ("debug", ("debug", "test", "dev", "staging", "trace", "phpinfo", "status",
               "actuator", "metrics"),
     "Non-production or diagnostic endpoint"),
    ("exposure", (".git", ".env", ".svn", "backup", "dump", ".sql", ".bak", ".old",
                  ".zip", ".tar", "config", "credentials", ".log"),
     "Potential information disclosure"),
    ("account", ("user", "account", "profile", "member", "customer"),
     "User-scoped object — check for IDOR"),
]

# Parameters whose value is frequently a URL or a path.
REDIRECT_PARAMS = {"url", "uri", "next", "redirect", "redirect_uri", "redirect_url",
                   "return", "returnurl", "return_url", "continue", "goto", "dest",
                   "destination", "callback", "target", "r", "u"}
# ...and ones that usually address a record, i.e. IDOR candidates.
ID_PARAMS = {"id", "uid", "user", "userid", "user_id", "account", "account_id", "no",
             "num", "order", "order_id", "doc", "docid", "file", "page_id", "pid"}

_DYNAMIC_EXT = re.compile(r"\.(php|aspx?|jspx?|cfm|do|action|py|rb|pl|cgi)$", re.I)


def build_tree(entries, max_nodes=5000):
    """Fold flat paths into a directory tree.

    A fuzz returns paths, but a site has *shape* — ``/admin/users/edit`` only means
    something next to ``/admin/users/delete``. The Pages view groups by status+size, which
    is right for spotting wildcard noise and wrong for seeing structure; this is the other
    half of that.

    `entries` is an iterable of ``(path, status_code, content_length)``. Returns
    ``(children, stats)``: `children` are the top-level nodes, each
    ``{name, path, depth, endpoint, status, length, children, total}`` where `total` counts
    the real findings at or under that node, and `endpoint` marks a node that is itself a
    finding (rather than an implied parent directory like ``/admin`` inferred from
    ``/admin/x``). `max_nodes` bounds pathological input.
    """
    root = {"name": "", "path": "", "depth": -1, "endpoint": False, "status": None,
            "length": None, "children": {}, "total": 0}
    nodes = 0
    truncated = 0

    for path, status, length in entries:
        clean = split_url(path)[0]
        parts = [p for p in clean.split("/") if p]
        node = root
        acc = ""
        for depth, part in enumerate(parts):
            acc += "/" + part
            child = node["children"].get(part)
            if child is None:
                if nodes >= max_nodes:
                    truncated += 1
                    node = None
                    break
                nodes += 1
                child = {"name": part, "path": acc, "depth": depth, "endpoint": False,
                         "status": None, "length": None, "children": {}, "total": 0}
                node["children"][part] = child
            node = child
        if node is None:
            continue
        # The deepest node for this path is a real finding, not an inferred directory.
        node["endpoint"] = True
        if node["status"] is None:
            node["status"] = status
            node["length"] = length

    def finish(node):
        """dict children -> sorted list, and roll descendant counts upward."""
        kids = [finish(c) for c in node["children"].values()]
        # Directories first, then alphabetical — the shape reads top-down.
        kids.sort(key=lambda c: (not c["children"], c["name"].lower()))
        node["children"] = kids
        node["total"] = (1 if node["endpoint"] else 0) + sum(c["total"] for c in kids)
        return node

    finish(root)
    stats = {"nodes": nodes, "truncated": truncated,
             "top_level": len(root["children"])}
    return root["children"], stats


def split_url(value):
    """Return (path, query) for an absolute URL or a bare path."""
    value = (value or "").strip()
    if not value:
        return "", ""
    if "://" in value:
        parts = urlsplit(value)
        return parts.path or "/", parts.query
    path, _, query = value.partition("?")
    return path, query


def param_names(value):
    """Parameter names in a URL/path, in order, de-duplicated.

    Handles valueless params (``?debug``), which parse_qsl drops by default.
    """
    _, query = split_url(value)
    if not query:
        return []
    names, seen = [], set()
    for name, _ in parse_qsl(query, keep_blank_values=True):
        key = name.strip()
        if key and key.lower() not in seen:
            seen.add(key.lower())
            names.append(key)
    return names


def keywords(value):
    """Interest labels for a URL/path, as (label, why) pairs."""
    lowered = (value or "").lower()
    return [(label, why) for label, needles, why in KEYWORD_RULES
            if any(n in lowered for n in needles)]


def classify(value):
    """Describe one URL: its parameters, keyword hits, and how notable it is."""
    path, _ = split_url(value)
    params = param_names(value)
    hits = keywords(value)
    lowered = [p.lower() for p in params]
    flags = []
    if any(p in REDIRECT_PARAMS for p in lowered):
        flags.append("redirect-param")
    if any(p in ID_PARAMS for p in lowered):
        flags.append("id-param")
    if _DYNAMIC_EXT.search(path):
        flags.append("dynamic")

    # Parameters are the strongest signal (a real input surface), then flags, then names.
    score = (3 * len(params)) + (2 * len(flags)) + len(hits)
    return {
        "url": value,
        "path": path,
        "params": params,
        "keywords": hits,
        "flags": flags,
        "score": score,
    }


def analyse(values, limit=200):
    """Shortlist the interesting URLs from an iterable of paths/URLs.

    Returns ``(rows, summary)``. Rows are the notable ones (anything with a parameter,
    flag, or keyword hit), most notable first, capped at `limit`. Summary counts the
    whole input, not just the shown rows.
    """
    seen, rows = set(), []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        info = classify(value)
        if info["score"]:
            rows.append(info)

    rows.sort(key=lambda r: (-r["score"], r["path"]))
    all_params, label_counts = {}, {}
    for r in rows:
        for p in r["params"]:
            all_params[p.lower()] = all_params.get(p.lower(), 0) + 1
        for label, _ in r["keywords"]:
            label_counts[label] = label_counts.get(label, 0) + 1

    summary = {
        "scanned": len(seen),
        "notable": len(rows),
        "with_params": sum(1 for r in rows if r["params"]),
        "params": sorted(all_params.items(), key=lambda kv: (-kv[1], kv[0])),
        "labels": sorted(label_counts.items(), key=lambda kv: (-kv[1], kv[0])),
        "truncated": max(0, len(rows) - limit),
    }
    return rows[:limit], summary
