"""Parsers for pasted output from the real dirsearch, so results found outside Thoth can
be folded into a workspace (findings + the dedup ledger) instead of being re-fuzzed.

Every report format dirsearch can emit is accepted, plus what you get from just
selecting the terminal and hitting copy:

  * ``--format=json``   {"results": [{"url", "status", "content-length", "redirect"}]}
  * ``--format=csv``    URL,Status,Size,Content Type,Redirection
  * ``--format=md``     | URL | Status | Size | ... |
  * ``--format=plain``  200    1KB   http://host/admin/
  * ``--format=simple`` bare URLs, one per line
  * terminal            [12:00:00] 200 -    1KB - /admin/  ->  http://host/admin/
"""
import csv
import io
import json
import re
from urllib.parse import urlsplit

_UNITS = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}

_SIZE_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)?$", re.I)

# [hh:mm:ss] 200 - 1KB - /path -> /redirect   (dashes, sizes and timestamp all optional)
_LINE_RE = re.compile(r"""
    ^\s*(?:\[\d{1,2}:\d{2}:\d{2}\]\s*)?          # optional [hh:mm:ss] stamp
    (?P<status>\d{3})\s*-?\s+                    # status code
    (?:(?P<size>\d+(?:\.\d+)?\s*(?:B|KB|MB|GB|TB))\s*-?\s+)?   # optional human size
    (?P<target>\S+)                              # path or absolute URL
    (?:\s*(?:->|=>)\s*(?P<redirect>\S+))?        # optional redirect arrow
    \s*$
""", re.X | re.I)

# dirsearch's banner names what it scanned — the authoritative host for a paste.
_TARGET_RE = re.compile(r"^\s*Target:\s*(\S+)", re.I | re.M)


class ImportError_(ValueError):
    """Nothing in the pasted text looked like dirsearch output."""


def parse_size(token):
    """'1KB' / '169B' / '1.2MB' / '4096' -> bytes, or None if unparseable."""
    if token is None:
        return None
    m = _SIZE_RE.match(str(token).strip())
    if not m:
        return None
    return int(float(m.group(1)) * _UNITS.get((m.group(2) or "B").upper(), 1))


def _clean_path(value, host_seen):
    """Normalize a URL or path to a leading-slash path. Records the host if absolute."""
    value = (value or "").strip().strip('"').strip("'")
    if not value:
        return None
    if "://" in value:
        parts = urlsplit(value)
        if parts.hostname:
            host_seen.add(parts.hostname.lower())
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
    else:
        path = value
    if not path.startswith("/"):
        path = "/" + path
    return path[:1024]


def _row(path, status, size, redirect):
    return {"path": path, "status_code": status, "content_length": size,
            "redirect": (redirect or None) or None}


def _from_json(text, host_seen):
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if isinstance(data, dict):
        # dirsearch nests under "results"; some versions key by target URL.
        results = data.get("results")
        if results is None:
            results = [r for v in data.values() if isinstance(v, list) for r in v]
    else:
        results = data
    if not isinstance(results, list):
        return None
    out = []
    for item in results:
        if not isinstance(item, dict):
            continue
        url = item.get("url") or item.get("URL") or item.get("path")
        path = _clean_path(url, host_seen)
        if not path:
            continue
        status = item.get("status") or item.get("status-code") or item.get("Status")
        size = item.get("content-length", item.get("content_length", item.get("Size")))
        out.append(_row(path, _int(status), parse_size(size),
                        item.get("redirect") or item.get("redirection")))
    return out or None


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _from_table(text, host_seen):
    """CSV (--format=csv) and markdown (--format=md) share a header + columns shape."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return None
    markdown = lines[0].lstrip().startswith("|")
    if markdown:
        rows = [[c.strip() for c in ln.strip().strip("|").split("|")] for ln in lines
                if ln.lstrip().startswith("|") and not set(ln) <= set("|-: \t")]
    elif "," in lines[0] and lines[0].lower().replace(" ", "").startswith("url,"):
        rows = list(csv.reader(io.StringIO(text)))
    else:
        return None
    if not rows:
        return None

    header = [c.lower().replace(" ", "").replace("-", "") for c in rows[0]]
    if "url" not in header:
        return None
    idx = {name: header.index(name) for name in
           ("url", "status", "size", "contentlength", "redirection", "redirect")
           if name in header}

    def cell(row, *names):
        for name in names:
            i = idx.get(name)
            if i is not None and i < len(row):
                return row[i]
        return None

    out = []
    for row in rows[1:]:
        path = _clean_path(cell(row, "url"), host_seen)
        if not path:
            continue
        out.append(_row(path, _int(cell(row, "status")),
                        parse_size(cell(row, "size", "contentlength")),
                        cell(row, "redirection", "redirect")))
    return out or None


def _from_lines(text, host_seen):
    """Terminal / --format=plain / --format=simple output, one result per line."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if m:
            target = m.group("target")
            # Guard against prose that happens to start with a number ("404 responses").
            if not (target.startswith("/") or "://" in target):
                continue
            path = _clean_path(target, host_seen)
            if path:
                out.append(_row(path, int(m.group("status")), parse_size(m.group("size")),
                                _clean_path(m.group("redirect"), set())
                                if m.group("redirect") else None))
            continue
        if "://" in line and " " not in line:  # --format=simple: bare URLs
            path = _clean_path(line, host_seen)
            if path:
                out.append(_row(path, None, None, None))
    return out or None


def parse_dirsearch(text):
    """Parse pasted dirsearch output in any of its formats.

    Returns ``(rows, hosts)`` — rows are ``{path, status_code, content_length, redirect}``
    de-duplicated by path (last mention wins), hosts is the set of hostnames that were
    *scanned* (the banner's ``Target:`` plus the host of each result URL), so the caller
    can warn about a paste from a different subdomain. Redirect destinations are
    deliberately excluded: pointing off-host is normal and not a sign of a bad paste.
    """
    text = (text or "").strip()
    if not text:
        raise ImportError_("Nothing to import — paste dirsearch output first.")

    hosts = set()
    for banner in _TARGET_RE.findall(text):
        _clean_path(banner, hosts)
    rows = None
    for parser in (_from_json, _from_table, _from_lines):
        rows = parser(text, hosts)
        if rows:
            break
    if not rows:
        raise ImportError_(
            "Couldn't find any results in that text. Paste dirsearch's output "
            "(terminal, or a --format=json/csv/md/plain/simple report).")

    by_path = {}
    for row in rows:
        by_path[row["path"]] = row
    return list(by_path.values()), hosts


def ledger_key(path):
    """Split a path into the ``(parent_path, word)`` pair the dedup ledger is keyed by,
    mirroring how the fuzzer records what it requested: ``/admin/login`` was word
    ``login`` under parent ``/admin/``. Trailing slashes are dropped because wordlist
    entries are bare. Returns an empty word for ``/``, which has nothing to record.
    """
    trimmed = path.split("?", 1)[0].rstrip("/")
    if not trimmed:
        return "/", ""
    parent, _, word = trimmed.rpartition("/")
    return (parent or "") + "/", word
