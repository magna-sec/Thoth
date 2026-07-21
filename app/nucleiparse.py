"""Parse output from the real nuclei so its findings can be folded into a workspace.

nuclei is the natural companion to Thoth's recon: run it out of band, paste (or upload)
the results, and each finding is matched to the subdomain it belongs to by host. Both of
nuclei's machine formats are accepted:

  * ``-jsonl`` / ``-j`` — one JSON object per line (the common case)
  * ``-json``           — a single JSON array

Field names have drifted across nuclei versions (``template-id`` vs ``templateID``,
``matched-at`` vs ``matched_at``), so every key is looked up leniently.
"""
import json
from urllib.parse import urlsplit

SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")


class NucleiParseError(ValueError):
    """The pasted text held no recognisable nuclei findings."""


def _get(d, *keys, default=None):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def _host_and_path(value):
    """Split a nuclei host/url/matched-at into (hostname, path)."""
    value = (value or "").strip()
    if not value:
        return None, "/"
    if "://" not in value:
        value = "http://" + value
    parts = urlsplit(value)
    host = (parts.hostname or "").lower()
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return host or None, path


def _severity(value):
    value = (value or "unknown").strip().lower()
    return value if value in SEVERITIES else "unknown"


def _one(obj):
    """Normalise a single nuclei result dict, or None if it isn't one."""
    if not isinstance(obj, dict):
        return None
    info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
    where = _get(obj, "matched-at", "matched_at", "matched", "url", "host")
    host, path = _host_and_path(where)
    # host is authoritative when matched-at was a bare path
    if not host:
        host, _ = _host_and_path(_get(obj, "host", "url"))
    template = _get(obj, "template-id", "templateID", "template_id", "template")
    if not (host and (template or info.get("name"))):
        return None

    tags = info.get("tags")
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    elif not isinstance(tags, list):
        tags = []

    return {
        "host": host,
        "path": path[:1024],
        "template_id": template or "",
        "name": info.get("name") or template or "nuclei finding",
        "severity": _severity(info.get("severity")),
        "type": _get(obj, "type", default=""),
        "tags": tags,
        "matched_at": where or "",
        "matcher_name": _get(obj, "matcher-name", "matcher_name", default=""),
        "description": (info.get("description") or "").strip()[:2000],
    }


def parse_nuclei(text):
    """Parse nuclei JSONL or JSON.

    Returns ``(rows, hosts)`` — rows are normalised finding dicts (de-duplicated by
    host+template+path), hosts is every hostname referenced.
    """
    text = (text or "").strip()
    if not text:
        raise NucleiParseError("Nothing to import — paste nuclei output first.")

    objs = []
    # A whole-document JSON array (from -json), else JSONL line by line.
    try:
        loaded = json.loads(text)
        objs = loaded if isinstance(loaded, list) else [loaded]
    except ValueError:
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line or line[0] not in "{[":
                continue
            try:
                objs.append(json.loads(line))
            except ValueError:
                continue

    rows, hosts, seen = [], set(), set()
    for obj in objs:
        row = _one(obj)
        if not row:
            continue
        hosts.add(row["host"])
        key = (row["host"], row["template_id"], row["path"])
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)

    if not rows:
        raise NucleiParseError(
            "Couldn't find any nuclei results in that text. Paste JSONL (nuclei -jsonl) "
            "or JSON (nuclei -json).")
    # Most severe first — that's the reading order operators want.
    rows.sort(key=lambda r: (SEVERITIES.index(r["severity"]), r["host"]))
    return rows, hosts
