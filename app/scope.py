"""Engagement scope: which hosts Thoth is permitted to touch.

This is a safety control, not a convenience. A pasted subdomain list is exactly the kind of
input that quietly includes something you are not authorized to test — a shared-hosting
neighbour, a third-party SaaS host, a CDN edge belonging to someone else. Every request the
app makes passes through here first.

Rules are one per line (commas also work):

    example.com          exact host
    *.example.com        any subdomain (and, deliberately, the apex itself)
    !vendor.example.com  explicit deny, wins over any allow

Semantics:
  * No allow rules  -> everything is in scope (so existing workspaces keep working).
  * Any allow rules -> a host must match one of them.
  * Deny always wins, whether or not allow rules exist.
"""
import fnmatch


class Scope:
    """Compiled scope rules for one workspace. Immutable and cheap to pass to threads."""

    def __init__(self, allow=(), deny=()):
        self.allow = tuple(allow)
        self.deny = tuple(deny)

    @property
    def restricted(self):
        """True when an allow-list is in force (i.e. not everything is permitted)."""
        return bool(self.allow)

    def allows(self, host):
        """Is this host in scope? Unparseable/empty hosts are never allowed."""
        host = _norm(host)
        if not host:
            return False
        if any(_match(host, rule) for rule in self.deny):
            return False
        if not self.allow:
            return True
        return any(_match(host, rule) for rule in self.allow)

    def reason(self, host):
        """Human-readable explanation for a refusal, or None when allowed."""
        host = _norm(host)
        if not host:
            return "not a valid hostname"
        for rule in self.deny:
            if _match(host, rule):
                return f"excluded by scope rule '!{rule}'"
        if self.allow and not any(_match(host, rule) for rule in self.allow):
            return "not covered by the workspace's in-scope list"
        return None

    def partition(self, hosts):
        """Split an iterable of hosts into (in_scope, out_of_scope)."""
        inside, outside = [], []
        for h in hosts:
            (inside if self.allows(h) else outside).append(h)
        return inside, outside


def _norm(host):
    host = (host or "").strip().lower().rstrip(".")
    # Tolerate a pasted URL or host:port rather than silently failing to match.
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    if host.count(":") == 1:  # host:port (leave bare IPv6 alone)
        host = host.split(":", 1)[0]
    return host


def _match(host, rule):
    if rule.startswith("*."):
        # "*.example.com" covers the apex too — nobody means to exclude it.
        return host == rule[2:] or fnmatch.fnmatch(host, rule)
    return fnmatch.fnmatch(host, rule)


def parse(text):
    """Parse a scope block into a Scope. Blank/comment lines ignored."""
    allow, deny = [], []
    for chunk in (text or "").replace(",", "\n").splitlines():
        rule = chunk.strip().lower().rstrip(".")
        if not rule or rule.startswith("#"):
            continue
        target = allow
        if rule.startswith("!"):
            rule, target = rule[1:].strip(), deny
        rule = _norm(rule) if "*" not in rule else rule
        if rule:
            target.append(rule)
    return Scope(allow, deny)


def for_workspace(workspace):
    """Scope for a workspace, tolerating the pre-scope schema."""
    return parse(getattr(workspace, "scope", None))
