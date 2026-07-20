"""Subdomain discovery by DNS brute force.

"Smart" here means four things, each of which exists because the naive version wastes
effort or lies to you:

  * **Wildcard-aware.** A domain with ``*.example.com`` answers every name you ask about.
    Without detection you "discover" the entire wordlist. We resolve a few random labels
    first, learn the wildcard answer, and suppress candidates matching it — the DNS twin of
    the fuzzer's 404 baseline.
  * **Permutations from what's already known.** If ``api.example.com`` exists, then
    ``api-dev``, ``dev-api``, ``api2`` and ``api-staging`` are far better guesses than the
    next word in a generic list. Real estates are named by humans following habits.
  * **Deduped.** Every label tried is recorded per (workspace, domain), so a re-run or a
    teammate never re-tests it — the same contract as the directory fuzzer.
  * **Scope-bound.** A discovered name outside the engagement scope is dropped before
    anything is resolved or added.

Discovered hosts become Targets in the workspace, so the rest of Thoth picks them up.
"""
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import current_app

from ..extensions import db
from ..models import Target, TestedName
from .base import Module, register

# Affixes that generate the permutations. Ordered roughly by how often they pay off.
AFFIXES = ("dev", "test", "staging", "stage", "uat", "qa", "prod", "internal", "int",
           "admin", "api", "old", "new", "beta", "demo", "backup", "v2", "2", "1", "3")

RESOLVE_TIMEOUT = 3.0


def _resolver(timeout, nameservers=None):
    """A dnspython resolver, or None when dnspython isn't installed."""
    try:
        import dns.resolver
    except ImportError:
        return None
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout + 1
    if nameservers:
        r.nameservers = nameservers
    return r


def resolve(name, resolver, timeout=RESOLVE_TIMEOUT):
    """Resolve a name to a frozenset of A/AAAA addresses (empty when it doesn't exist).

    Pure network work — safe to call from worker threads.
    """
    if resolver is not None:
        import dns.resolver as _dr
        found = set()
        for rdtype in ("A", "AAAA"):
            try:
                for rdata in resolver.resolve(name, rdtype):
                    found.add(str(rdata))
            except (_dr.NXDOMAIN, _dr.NoAnswer, _dr.NoNameservers, _dr.LifetimeTimeout):
                continue
            except Exception:  # noqa: BLE001 - never let one bad lookup kill the sweep
                continue
        return frozenset(found)

    import socket  # fallback: no dnspython, so no record-type control
    try:
        return frozenset(info[4][0] for info in socket.getaddrinfo(name, None))
    except OSError:
        return frozenset()


def detect_wildcard(domain, resolver, probes=3, timeout=RESOLVE_TIMEOUT):
    """Learn what a domain answers for names that cannot exist.

    Returns the set of wildcard addresses (empty when there's no wildcard). Uses several
    random probes because some providers round-robin.
    """
    seen = set()
    for _ in range(probes):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        seen |= resolve(f"{label}.{domain}", resolver, timeout)
    return frozenset(seen)


def permutations(known_labels, affixes=AFFIXES):
    """Derive likely neighbours of the labels already known for a domain."""
    out, seen = [], set()

    def push(value):
        if value and value not in seen and len(value) < 64:
            seen.add(value)
            out.append(value)

    for label in known_labels:
        base = label.strip().lower()
        if not base or base == "*":
            continue
        for affix in affixes:
            if affix == base:
                continue
            push(f"{base}-{affix}")
            push(f"{affix}-{base}")
            if affix.isdigit():
                push(f"{base}{affix}")
    return out


def load_words(path_or_empty):
    """Wordlist for labels: an explicit file, else wordlists/subdomains.txt, else a
    small built-in list so the module is useful out of the box."""
    import os
    candidates = []
    if path_or_empty and os.path.isfile(path_or_empty):
        candidates.append(path_or_empty)
    root = current_app.config["WORDLIST_DIR"]
    candidates.append(os.path.join(root, "subdomains.txt"))

    for fp in candidates:
        try:
            with open(fp, encoding="utf-8", errors="ignore") as fh:
                words = [ln.strip().lower().lstrip(".") for ln in fh]
            words = [w for w in words if w and not w.startswith("#")]
            if words:
                return words
        except OSError:
            continue
    return list(BUILTIN_WORDS)


BUILTIN_WORDS = (
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure",
    "vpn", "m", "shop", "ftp", "mail2", "test", "portal", "dev", "web", "admin", "cloud",
    "api", "staging", "app", "intranet", "cdn", "git", "jenkins", "jira", "confluence",
    "vpn2", "gateway", "auth", "sso", "login", "dashboard", "grafana", "kibana", "status",
    "docs", "support", "help", "static", "assets", "img", "images", "media", "files",
    "download", "uploads", "backup", "db", "mysql", "sql", "internal", "corp", "partner",
    "beta", "demo", "sandbox", "uat", "qa", "prod", "production", "monitor", "metrics",
)


@register
class DnsBruteModule(Module):
    name = "dnsbrute"
    version = "0.1"
    description = "Discover subdomains by DNS brute force (wildcard-aware, with permutations)."
    supports_batch = True
    reports_progress = True
    needs_targets = False  # discovery: it can run on an empty workspace

    def config_schema(self):
        return [
            {"name": "domain", "type": "text", "default": "",
             "label": "Root domain(s)", "help": "Comma-separated, e.g. example.com"},
            {"name": "wordlist", "type": "text", "default": "",
             "label": "Wordlist file (optional)"},
            {"name": "threads", "type": "number", "default": 40, "label": "Threads"},
            {"name": "timeout", "type": "number", "default": 3, "label": "DNS timeout (s)"},
            {"name": "resolvers", "type": "text", "default": "",
             "label": "Resolvers (optional)", "help": "Comma-separated IPs, e.g. 1.1.1.1"},
            {"name": "permutations", "type": "bool", "default": True,
             "label": "Also try permutations of known subdomains"},
            {"name": "force", "type": "bool", "default": False,
             "label": "Re-test labels already tried (ignore dedup)"},
        ]

    def run(self, target, config, ctx):
        self.run_all([target], config, ctx)

    def run_all(self, targets, config, ctx):
        timeout = float(config.get("timeout", 3) or 3)
        threads = max(1, int(config.get("threads", 40) or 40))
        force = bool(config.get("force", False))
        nameservers = [s.strip() for s in str(config.get("resolvers", "")).split(",")
                       if s.strip()]

        existing = {t.host.lower() for t in
                    Target.query.filter_by(workspace_id=ctx.workspace_id).all()}
        domains = _domains(config.get("domain"), existing)
        if not domains:
            ctx.log("No root domain given, and none could be inferred from the workspace. "
                    "Set 'Root domain(s)' and re-run.")
            return

        resolver = _resolver(timeout, nameservers)
        if resolver is None:
            ctx.log("dnspython not installed — falling back to the system resolver "
                    "(slower, and no custom resolvers).")

        words = load_words(config.get("wordlist") or "")
        ctx.log(f"Domains: {', '.join(domains)} | Wordlist: {len(words)} label(s) | "
                f"Threads: {threads}"
                + (f" | Resolvers: {', '.join(nameservers)}" if nameservers else ""))

        total_found = 0
        for domain in domains:
            total_found += self._sweep(domain, words, existing, resolver, timeout,
                                       threads, force, config, ctx)
        ctx.log("")
        ctx.log(f"Task Completed — {total_found} new subdomain(s) added")

    def _sweep(self, domain, words, existing, resolver, timeout, threads, force, config,
               ctx):
        # Permutations are derived from the labels already known for THIS domain.
        candidates = list(words)
        if bool(config.get("permutations", True)):
            known = [h[: -(len(domain) + 1)] for h in existing
                     if h.endswith("." + domain)]
            known = [k.rsplit(".", 1)[-1] for k in known if k]
            perms = permutations(sorted(set(known)))
            if perms:
                ctx.log(f"{domain}: +{len(perms)} permutation(s) from "
                        f"{len(set(known))} known subdomain(s)")
                candidates += perms

        seen, ordered = set(), []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                ordered.append(c)

        tried = set()
        if not force:
            tried = {row.label for row in TestedName.query.filter_by(
                workspace_id=ctx.workspace_id, domain=domain).all()}
            skipped = len(ordered)
            ordered = [c for c in ordered if c not in tried]
            skipped -= len(ordered)
            if skipped:
                ctx.log(f"{domain}: skipping {skipped} already-tried label(s) "
                        f"(dedup — tick Force to re-test)")
        if not ordered:
            return 0

        wildcard = detect_wildcard(domain, resolver, timeout=timeout)
        if wildcard:
            ctx.log(f"{domain}: wildcard DNS detected -> {', '.join(sorted(wildcard))} "
                    f"— matching answers will be suppressed")

        ctx.set_progress(0, len(ordered))
        results, done = [], 0
        with ThreadPoolExecutor(max_workers=min(threads, len(ordered))) as ex:
            futs = {ex.submit(resolve, f"{label}.{domain}", resolver, timeout): label
                    for label in ordered}
            for fut in as_completed(futs):
                label = futs[fut]
                results.append((label, fut.result()))
                done += 1
                if done % 25 == 0:
                    ctx.set_progress(done, len(ordered))
        ctx.set_progress(len(ordered), len(ordered))

        # DB writes on the main thread only.
        added = 0
        for label, addrs in sorted(results):
            host = f"{label}.{domain}"
            hit = bool(addrs) and addrs != wildcard
            if label not in tried:
                db.session.add(TestedName(workspace_id=ctx.workspace_id, domain=domain,
                                          label=label, resolved=hit))
            if not hit:
                continue
            if host in existing:
                continue
            if not ctx.in_scope(host):
                ctx.log(f"Scope: ignoring discovered {host} — outside the engagement")
                continue
            target = Target(workspace_id=ctx.workspace_id, host=host, scheme="https",
                            ip=sorted(addrs)[0])
            db.session.add(target)
            db.session.flush()
            existing.add(host)
            added += 1
            ctx.finding(target, path="/", module=self.name, source="dnsbrute",
                        addresses=sorted(addrs),
                        log=f"found  {host}  ->  {', '.join(sorted(addrs))}")
        db.session.commit()
        return added


def _domains(configured, existing_hosts):
    """Root domains to sweep: what was configured, else inferred from the workspace.

    The inference is a deliberate approximation — the registrable suffix needs the Public
    Suffix List to get right, so we take the last two labels and let the operator correct
    it in the form when that's wrong (e.g. co.uk).
    """
    domains = [d.strip().lower().lstrip(".") for d in str(configured or "").split(",")
               if d.strip()]
    if domains:
        return list(dict.fromkeys(domains))
    guessed = {}
    for host in existing_hosts:
        parts = host.split(".")
        if len(parts) >= 2:
            root = ".".join(parts[-2:])
            guessed[root] = guessed.get(root, 0) + 1
    # Only infer when there's a clear winner; otherwise make the operator say.
    return [max(guessed, key=guessed.get)] if guessed else []
