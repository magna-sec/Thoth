"""IIS 8.3 short-name (tilde) enumeration check.

Old/misconfigured IIS leaks the existence of files and directories whose 8.3 "short name"
(``SECRET~1.TXT``) can be guessed a character at a time, because it answers *differently*
for a wildcard that matches an existing short name than for one that can't. That differential
is the whole vulnerability, and it's what this checks for — it does **not** enumerate names,
only answers "is this host exposed?".

Method (the standard differential, no enumeration):

  * request a wildcard that *should* match if any 8.3 name exists — ``/*~1*/<junk>.aspx``
  * request one with an improbable prefix that *can't* match — ``/<random>*~1*/<junk>.aspx``
  * on a vulnerable server the two produce different HTTP statuses (classically 404 for the
    match vs 400 for the miss); a patched server answers both identically.

For authorized testing only — this is a read-only probe of hosts already in the workspace,
governed by the engagement scope like every other module.
"""
import random
import string

import requests

from .base import Module, register

# Junk file under the magic path — a .NET extension makes IIS invoke the handler that
# produces the tell-tale 400/404 split. Several are tried; servers differ.
_EXTS = ("/.aspx", "/a.aspx", "/a.asp", "\\a.aspx")


def _looks_like_iis(target):
    hay = " ".join(filter(None, [
        target.last_server, target.last_tech, target.manual_tech or ""])).lower()
    return "iis" in hay or "microsoft" in hay or "asp.net" in hay


def _status(session, url, timeout, verify):
    try:
        r = session.get(url, timeout=timeout, allow_redirects=False, verify=verify)
        return r.status_code
    except requests.RequestException:
        return None


def check_host(base_url, session, timeout=8, verify=False):
    """Run the differential. Returns a result dict; ``vulnerable`` is the headline.

    Pure network work (no ORM), so a module can call it per target from the main thread.
    """
    rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    attempts = []
    for ext in _EXTS:
        magic = f"{base_url}/*~1*{ext}"
        control = f"{base_url}/{rnd}*~1*{ext}"
        magic_status = _status(session, magic, timeout, verify)
        control_status = _status(session, control, timeout, verify)
        attempts.append({"ext": ext, "magic": magic_status, "control": control_status})
        # The signature: statuses differ AND a 400 is involved — IIS accepting the matched
        # short name while rejecting the invalid one (or vice versa). Both-equal means a
        # patched server or one that simply dislikes the characters: not vulnerable.
        if (magic_status is not None and control_status is not None
                and magic_status != control_status
                and 400 in (magic_status, control_status)):
            return {"vulnerable": True, "ext": ext, "magic_status": magic_status,
                    "control_status": control_status, "attempts": attempts}
    last = attempts[-1] if attempts else {"magic": None, "control": None}
    return {"vulnerable": False, "ext": None, "magic_status": last.get("magic"),
            "control_status": last.get("control"), "attempts": attempts}


@register
class IisTildeModule(Module):
    name = "iistilde"
    version = "0.1"
    description = "Check IIS hosts for 8.3 short-name (tilde) enumeration exposure."
    supports_batch = True
    reports_progress = True

    def config_schema(self):
        return [
            {"name": "timeout", "type": "number", "default": 8, "label": "Timeout (s)"},
            {"name": "verify_tls", "type": "bool", "default": False, "label": "Verify TLS"},
            {"name": "only_iis", "type": "bool", "default": True,
             "label": "Only test hosts fingerprinted as IIS",
             "help": "Untick to test every selected host regardless of server"},
        ]

    def run(self, target, config, ctx):
        self.run_all([target], config, ctx)

    def run_all(self, targets, config, ctx):
        timeout = float(config.get("timeout", 8) or 8)
        verify = bool(config.get("verify_tls", False))
        only_iis = bool(config.get("only_iis", True))

        session = requests.Session()
        session.headers["User-Agent"] = "Thoth-iistilde/0.1"
        if ctx.proxies:
            session.proxies.update(ctx.proxies)

        ctx.set_progress(0, len(targets))
        vuln = tested = skipped = 0
        for i, target in enumerate(targets):
            ctx.raise_if_cancelled()
            if only_iis and not _looks_like_iis(target):
                skipped += 1
                ctx.log(f"skip   {target.host} — not fingerprinted as IIS "
                        f"(run alive first, or untick 'Only test IIS hosts')")
                ctx.set_progress(i + 1, len(targets))
                continue

            tested += 1
            res = check_host(target.base_url, session, timeout, verify)
            if res["vulnerable"]:
                vuln += 1
                line = (f"VULN   {target.host} — 8.3 short-name enumeration "
                        f"(matched {res['magic_status']} vs invalid "
                        f"{res['control_status']})")
            else:
                line = (f"ok     {target.host} — not vulnerable "
                        f"(statuses {res['magic_status']}/{res['control_status']})")
            ctx.finding(
                target, path="/", status_code=res.get("magic_status"),
                module=self.name, vulnerable=res["vulnerable"],
                severity="medium" if res["vulnerable"] else "info",
                title=("IIS 8.3 short-name enumeration"
                       if res["vulnerable"] else "IIS tilde check — not vulnerable"),
                magic_status=res["magic_status"], control_status=res["control_status"],
                log=line)
            ctx.set_progress(i + 1, len(targets))

        ctx.log("")
        ctx.log(f"Task Completed — {vuln} vulnerable, {tested - vuln} not, "
                f"{skipped} skipped (non-IIS)")
