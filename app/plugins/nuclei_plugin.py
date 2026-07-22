"""nuclei parser plugin — a "findings" plugin: it doesn't store an artifact, it folds the
findings onto the matching subdomains (shown in each host's Vulnerabilities panel)."""
from collections import Counter
from datetime import datetime

from flask import url_for

from ..extensions import db
from ..models import Finding, Run
from ..nucleiparse import looks_like_nuclei, parse_nuclei
from ..realtime import publish
from .base import ParserPlugin, register_parser

NUCLEI_IMPORT = "nuclei-import"      # Run.module for imported nuclei findings
_SEV_ORDER = ("critical", "high", "medium", "low", "info", "unknown")


def ingest_nuclei(ws, rows, hosts, user, selected_ids=None, source="pasted"):
    """Match nuclei rows to the workspace's subdomains by host and record Findings.

    Shared by this plugin and the legacy ``/import-nuclei`` route. Hosts not present in the
    workspace (or not in `selected_ids`) are reported, never invented. Returns a summary
    dict for the caller to flash.
    """
    by_host = {t.host.lower(): t for t in ws.targets}
    if selected_ids:
        by_host = {h: t for h, t in by_host.items() if t.id in selected_ids}

    now = datetime.utcnow()
    run = Run(workspace_id=ws.id, module=NUCLEI_IMPORT, status="done",
              config_json={"_targets": sorted({t.id for t in by_host.values()}) or None,
                           "source": source},
              created_by=(user.id if user else None), started_at=now, finished_at=now)
    db.session.add(run)
    db.session.flush()

    sev_counts, unmatched, hit = Counter(), Counter(), set()
    imported = 0
    for row in rows:
        target = by_host.get(row["host"])
        if target is None:
            unmatched[row["host"]] += 1
            continue
        sev_counts[row["severity"]] += 1
        hit.add(target.id)
        imported += 1
        db.session.add(Finding(
            workspace_id=ws.id, run_id=run.id, target_id=target.id, path=row["path"],
            status_code=None, found_at=now,
            extra_json={"module": NUCLEI_IMPORT, "imported": True,
                        "severity": row["severity"], "title": row["name"],
                        "template_id": row["template_id"], "tags": row["tags"],
                        "type": row["type"], "matched_at": row["matched_at"],
                        "matcher_name": row["matcher_name"],
                        "description": row["description"]}))

    log = [f"Importing nuclei results into {ws.name} ({source})"]
    for sev in _SEV_ORDER:
        if sev_counts.get(sev):
            log.append(f"  {sev:>8}: {sev_counts[sev]}")
    if unmatched:
        log.append("")
        log.append(f"{sum(unmatched.values())} finding(s) skipped — host not "
                   + ("in the selection" if selected_ids else "a subdomain in this workspace")
                   + ": " + ", ".join(sorted(unmatched)[:15]))
    log.append("")
    log.append(f"Import Completed — {imported} finding(s) across {len(hit)} host(s)")
    run.progress_done = run.progress_total = imported
    run.log = "\n".join(f"{now:%H:%M:%S} {ln}" if ln else "" for ln in log) + "\n"
    db.session.commit()
    for f in Finding.query.filter_by(run_id=run.id).all():
        publish(ws.id, {"type": "finding", "run_id": run.id, "finding": f.to_dict()})

    return {"run": run, "imported": imported, "unmatched": unmatched,
            "sev_counts": sev_counts, "hit": hit, "hosts": sorted(hosts)}


@register_parser
class NucleiPlugin(ParserPlugin):
    name = "nuclei"
    title = "nuclei findings"
    kind = "findings"
    description = ("nuclei output (JSONL / JSON): each finding is matched to its subdomain "
                   "by host and shown in that host's Vulnerabilities panel — no artifact "
                   "is stored, the results go straight onto the subdomains.")
    glyph = "🧪"
    placeholder = "Paste nuclei -jsonl or -json output"
    collect = "nuclei -l hosts.txt -jsonl -o nuclei.jsonl"

    def detect(self, text):
        return looks_like_nuclei(text)

    def parse(self, text):
        rows, hosts = parse_nuclei(text)          # raises NucleiParseError (a ValueError)
        return {"rows": rows, "hosts": sorted(hosts)}

    def summary(self, data):
        return f"{len(data.get('rows', []))} finding(s)"

    def ingest(self, ws, data, user):
        res = ingest_nuclei(ws, data["rows"], data["hosts"], user)
        if not res["imported"]:
            hosts = res["hosts"]
            return {"category": "error", "redirect":
                    url_for("workspaces.detail", workspace_id=ws.id) + "#domains",
                    "message": "No nuclei findings matched a subdomain in this workspace."
                    + (f" Hosts in the file: {', '.join(hosts[:10])}" if hosts else "")}
        sev = " · ".join(f"{res['sev_counts'][s]} {s}" for s in _SEV_ORDER
                         if res["sev_counts"].get(s))
        msg = f"Imported {res['imported']} nuclei finding(s) ({sev})."
        if res["unmatched"]:
            msg += f" {sum(res['unmatched'].values())} skipped (host not matched)."
        return {"category": "info", "message": msg, "redirect":
                url_for("workspaces.run_detail", workspace_id=ws.id, run_id=res["run"].id)}
