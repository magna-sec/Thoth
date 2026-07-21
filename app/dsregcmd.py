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

# Fields surfaced up top, in reading order, with human labels. Matched case-insensitively.
SUMMARY_FIELDS = [
    ("AzureAdJoined", "Azure AD Joined"),
    ("EnterpriseJoined", "Enterprise Joined"),
    ("DomainJoined", "Domain Joined"),
    ("WorkplaceJoined", "Workplace Joined"),
    ("DeviceName", "Device Name"),
    ("DeviceId", "Device ID"),
    ("TenantName", "Tenant"),
    ("TenantId", "Tenant ID"),
    ("Idp", "Identity Provider"),
    ("DomainName", "AD Domain"),
    ("MdmUrl", "MDM URL"),
    ("AzureAdPrt", "Azure AD PRT"),
    ("KeyProvider", "Key Provider"),
    ("TpmProtected", "TPM Protected"),
    ("OsVersion", "OS Version"),
]
SUMMARY_KEYS = [k for k, _ in SUMMARY_FIELDS]  # back-compat
# Only these render as a Yes/No pill. Everything else shows its literal value — otherwise a
# non-boolean field whose value happens to read "YES"/"NO" would flash a misleading pill.
BOOL_KEYS = {"AzureAdJoined", "EnterpriseJoined", "DomainJoined", "WorkplaceJoined",
             "AzureAdPrt", "TpmProtected"}
_YESNO = {"yes": True, "no": False}


def interpret(index):
    """Derive the human headline + security-notable observations from the parsed fields.

    `index` is the lowercased key->value map. Returns ``{"headline", "notable"}`` where
    notable is a list of ``{severity, title, detail}``.
    """
    def b(key):
        return _YESNO.get((index.get(key.lower()) or "").strip().lower())

    def v(key):
        return index.get(key.lower())

    aad, dj, ej, wpj = b("AzureAdJoined"), b("DomainJoined"), b("EnterpriseJoined"), \
        b("WorkplaceJoined")
    tenant = v("TenantName") or v("TenantId")
    if aad and dj:
        headline = "Hybrid Azure AD joined" + (f" to {tenant}" if tenant else "")
    elif aad:
        headline = "Azure AD joined" + (f" to {tenant}" if tenant else "")
    elif dj:
        headline = "On-prem domain joined" + (f" ({v('DomainName')})" if v("DomainName") else "")
    elif wpj:
        headline = "Workplace joined (registered)"
    else:
        headline = "Not joined (standalone)"

    notable = []

    def add(sev, title, detail):
        notable.append({"severity": sev, "title": title, "detail": detail})

    if b("AzureAdPrt"):
        add("medium", "Primary Refresh Token present",
            "AzureAdPrt = YES — a PRT is cached on this device. It's a high-value token-theft "
            "target that yields SSO to Entra ID resources.")
    if v("MdmUrl"):
        add("info", "MDM enrolled", f"Managed via {v('MdmUrl')}.")
    if b("TpmProtected") is False:
        add("low", "Device key not TPM-protected",
            "TpmProtected = NO — the device key is software-protected and easier to extract.")
    if ej:
        add("info", "Enterprise (on-prem AD FS) joined", "EnterpriseJoined = YES.")
    return {"headline": headline, "notable": notable}


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
    for key, label in SUMMARY_FIELDS:
        if key.lower() in index:
            value = index[key.lower()]
            is_bool = key in BOOL_KEYS
            summary.append({"key": key, "label": label, "value": value,
                            "bool": _YESNO.get(value.strip().lower()) if is_bool else None})
    return {"sections": sections, "summary": summary, **interpret(index)}


def looks_like_dsregcmd(text):
    """Cheap heuristic so the UI can route a paste automatically."""
    t = (text or "").lower()
    return ("dsregcmd" in t or "azureadjoined" in t
            or ("device state" in t and "tenant" in t))
