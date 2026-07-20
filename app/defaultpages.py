"""Recognise "nothing to see here" pages.

Screenshotting an estate produces a wall of identical server defaults — IIS splash pages,
"Welcome to nginx!", parked-domain holding pages. They're the majority of tiles and the
least interesting, so labelling them lets the gallery push them aside and show you the
handful of real applications.

Matching is on the page title first (cheap, already captured by the probe) with the Server
header as a weaker corroborating hint.
"""

# (label, title needles) — ordered most specific first.
TITLE_RULES = [
    ("IIS default", ("iis windows server", "welcome to iis", "iisstart",
                     "internet information services")),
    ("Apache default", ("apache2 ubuntu default page", "apache2 debian default page",
                        "apache http server test page", "test page for the apache",
                        "it works!")),
    ("nginx default", ("welcome to nginx",)),
    ("Tomcat default", ("apache tomcat",)),
    ("Plesk default", ("plesk", "default plesk page")),
    ("cPanel default", ("cpanel", "web hosting by")),
    ("Parked", ("this domain is parked", "domain is for sale", "buy this domain",
                "parked domain", "future home of")),
    ("Placeholder", ("coming soon", "under construction", "site not configured",
                     "default web site page", "index of /", "welcome to your new site")),
    ("Error page", ("403 forbidden", "404 not found", "401 unauthorized",
                    "service unavailable", "bad gateway", "access denied")),
]

# Used only to label a *blank* page, where the title tells us nothing.
SERVER_RULES = [
    ("IIS default", "microsoft-iis"),
    ("Apache default", "apache"),
    ("nginx default", "nginx"),
]


def classify(title=None, server=None, content_length=None):
    """Return a label like "IIS default", or None when the page looks like real content."""
    text = (title or "").strip().lower()
    for label, needles in TITLE_RULES:
        if any(n in text for n in needles):
            return label

    # No title and almost no body: a bare server response rather than an application.
    if not text and (content_length or 0) < 1024:
        srv = (server or "").lower()
        for label, needle in SERVER_RULES:
            if needle in srv:
                return label
        return "Blank"
    return None


def is_default(label):
    return bool(label)
