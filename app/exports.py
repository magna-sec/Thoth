"""Getting data back out.

Thoth could already import a dirsearch run but had no way to emit anything, which made it
a dead end at the point an engagement actually needs output. Four datasets, four formats:

  findings  every result (host, path, status, size, fingerprints)
  hosts     the subdomain inventory with its enrichment
  urls      bare URLs, one per line — the format other tools eat
  params    distinct parameter names seen — a ready-made param wordlist

CSV/JSON/Markdown are for humans and spreadsheets; TXT is for pipes. The builders return
plain rows so they stay trivially testable and never touch Flask.
"""
import csv
import io
import json
from datetime import datetime

FORMATS = ("csv", "json", "md", "txt")
DATASETS = ("findings", "hosts", "urls", "params")

MIME = {"csv": "text/csv", "json": "application/json",
        "md": "text/markdown", "txt": "text/plain"}


# ----------------------------------------------------------------- datasets

FINDING_COLUMNS = ("host", "url", "path", "status", "length", "redirect", "server",
                   "title", "tech", "waf", "module", "found_at")


def findings_dataset(findings):
    rows = []
    for f in findings:
        extra = f.extra_json or {}
        target = f.target
        rows.append({
            "host": target.host if target else "",
            "url": (target.base_url if target else "") + (f.path or ""),
            "path": f.path,
            "status": f.status_code,
            "length": f.content_length,
            "redirect": f.redirect or "",
            "server": extra.get("server") or "",
            "title": extra.get("title") or "",
            "tech": ", ".join(extra.get("tech") or []),
            "waf": ", ".join(extra.get("waf") or []) or (target.last_waf if target else ""),
            "module": extra.get("module") or "",
            "found_at": _iso(f.found_at),
        })
    return FINDING_COLUMNS, rows


HOST_COLUMNS = ("host", "url", "alive", "status", "ip", "asn", "asn_name", "country",
                "waf", "server", "title", "tech", "tags", "open_ports", "in_scope",
                "findings", "last_checked")


def hosts_dataset(targets, finding_counts=None, scope=None):
    counts = finding_counts or {}
    rows = []
    for t in targets:
        rows.append({
            "host": t.host,
            "url": t.base_url,
            "alive": "" if t.last_alive is None else ("yes" if t.last_alive else "no"),
            "status": t.last_status_code,
            "ip": t.ip or "",
            "asn": t.asn or "",
            "asn_name": t.asn_name or "",
            "country": t.country or "",
            "waf": t.last_waf or "",
            "server": t.last_server or "",
            "title": t.last_title or "",
            "tech": t.last_tech or "",
            "tags": ", ".join(t.manual_tech_list),
            "open_ports": ", ".join(str(p) for p in t.open_port_list),
            "in_scope": "" if scope is None else ("yes" if scope.allows(t.host) else "no"),
            "findings": counts.get(t.id, 0),
            "last_checked": _iso(t.last_checked_at),
        })
    return HOST_COLUMNS, rows


def urls_lines(findings):
    """Absolute URLs, de-duplicated, sorted — ready to pipe into another tool."""
    seen = {(f.target.base_url if f.target else "") + (f.path or "") for f in findings}
    return sorted(u for u in seen if u)


def params_lines(findings):
    """Distinct parameter names across a host/workspace, most frequent first."""
    from .urlinsights import analyse
    values = [f.path for f in findings] + [f.redirect for f in findings if f.redirect]
    _, summary = analyse(values, limit=0)
    return [name for name, _ in summary["params"]]


def _iso(value):
    return value.isoformat(timespec="seconds") if isinstance(value, datetime) else ""


# ----------------------------------------------------------------- formats


def to_csv(columns, rows):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(columns), extrasaction="ignore",
                            lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({c: _cell(row.get(c)) for c in columns})
    return buf.getvalue()


def to_json(columns, rows):
    return json.dumps(rows, indent=2, default=str) + "\n"


def to_markdown(columns, rows):
    head = "| " + " | ".join(columns) + " |"
    rule = "| " + " | ".join("---" for _ in columns) + " |"
    body = ["| " + " | ".join(_md_cell(row.get(c)) for c in columns) + " |"
            for row in rows]
    return "\n".join([head, rule, *body]) + "\n"


def to_txt(columns, rows):
    """Tab-separated — greppable and awk-able, unlike quoted CSV."""
    out = ["\t".join(columns)]
    out += ["\t".join(_cell(row.get(c)).replace("\t", " ") for c in columns)
            for row in rows]
    return "\n".join(out) + "\n"


def lines_payload(lines, fmt):
    """urls/params are a flat list; render it sensibly in whichever format was asked for."""
    if fmt == "json":
        return json.dumps(lines, indent=2) + "\n"
    if fmt == "csv":
        return to_csv(("value",), [{"value": v} for v in lines])
    if fmt == "md":
        return to_markdown(("value",), [{"value": v} for v in lines])
    return "\n".join(lines) + ("\n" if lines else "")


RENDERERS = {"csv": to_csv, "json": to_json, "md": to_markdown, "txt": to_txt}


def render(columns, rows, fmt):
    return RENDERERS[fmt](columns, rows)


def _cell(value):
    if value is None:
        return ""
    return str(value)


def _md_cell(value):
    # Pipes would break the table; newlines would break the row.
    return _cell(value).replace("|", "\\|").replace("\n", " ")


def filename(workspace_name, what, fmt, host=None):
    """A filename that says what it is and when — engagements accumulate these."""
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M")
    parts = [_slug(workspace_name), _slug(host) if host else "", what, stamp]
    return "-".join(p for p in parts if p) + "." + fmt


def _slug(value):
    keep = [c if (c.isalnum() or c in "-_.") else "-" for c in (value or "").strip()]
    return "".join(keep).strip("-").lower()[:60] or "thoth"
