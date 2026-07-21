"""Parse ``dsregcmd /status`` output into tidy sections.

``dsregcmd /status`` is the go-to for a Windows host's device-join and Entra ID (Azure AD)
state — join type, tenant, MDM enrolment URL, SSO/PRT status. It's dumped as ASCII-boxed
sections of ``Key : Value`` lines; this turns that into structured data plus a curated
summary of the fields worth reading first.

Pure string work — no execution, no ORM.
"""
import re

# A section header is a "| Title |" line between +----+ rules.
_TITLE = re.compile(r"^\s*\|\s*(?P<title>.+?)\s*\|\s*$")
_RULE = re.compile(r"^\s*\+-+\+\s*$")

# Fields surfaced up top, in reading order. Matched case-insensitively against any section.
SUMMARY_KEYS = [
    "AzureAdJoined", "EnterpriseJoined", "DomainJoined", "WorkplaceJoined",
    "DeviceName", "DeviceId", "TenantName", "TenantId", "Idp", "DomainName",
    "MdmUrl", "MdmEnrollmentUrl", "AzureAdPrt", "AzureAdPrtauthority",
    "OsVersion", "KeyProvider", "TpmProtected",
]
_YESNO = {"yes": True, "no": False}


def _kv(line):
    """Split a 'Key : Value' line, or return None."""
    # dsregcmd separates with ' : '; keys are right-aligned with leading spaces.
    if " : " not in line:
        return None
    key, _, value = line.partition(" : ")
    key = key.strip()
    if not key:
        return None
    return key, value.strip()


def parse_dsregcmd(text):
    """Parse dsregcmd output. Returns ``{"sections": [...], "summary": [...]}``.

    Each section is ``{"title", "items": [{"key", "value"}], "notes": [str]}``; summary is
    an ordered list of ``{"key", "value", "bool"}`` for the curated fields that were present
    (``bool`` is True/False for YES/NO values, else None).
    """
    lines = (text or "").replace("\r\n", "\n").split("\n")
    sections = []
    current = {"title": "General", "items": [], "notes": []}
    index = {}  # lowercased key -> value, for the summary (first occurrence wins)

    for i, line in enumerate(lines):
        if _RULE.match(line):
            continue
        m = _TITLE.match(line)
        # A title line is "| ... |"; but value lines never start with '|', and a title is
        # only real when bracketed by rule lines. Check the neighbours to avoid eating a
        # stray pipe in a value.
        if m and (_RULE.match(lines[i - 1]) if i else False):
            if current["items"] or current["notes"]:
                sections.append(current)
            current = {"title": m.group("title"), "items": [], "notes": []}
            continue

        kv = _kv(line)
        if kv:
            key, value = kv
            current["items"].append({"key": key, "value": value})
            index.setdefault(key.lower(), value)
        elif line.strip():
            current["notes"].append(line.strip())

    if current["items"] or current["notes"]:
        sections.append(current)

    summary = []
    for key in SUMMARY_KEYS:
        if key.lower() in index:
            value = index[key.lower()]
            summary.append({"key": key, "value": value,
                            "bool": _YESNO.get(value.strip().lower())})
    return {"sections": sections, "summary": summary}


def looks_like_dsregcmd(text):
    """Cheap heuristic so the UI can route a paste automatically."""
    t = (text or "").lower()
    return ("dsregcmd" in t or "azureadjoined" in t
            or ("device state" in t and "tenant" in t))
