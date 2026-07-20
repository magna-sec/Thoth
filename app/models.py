"""Data model. Everything scoped to a Workspace with ON DELETE CASCADE for easy wipe."""
from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    pw_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    memberships = db.relationship("WorkspaceMember", back_populates="user",
                                  cascade="all, delete-orphan")

    def set_password(self, pw):
        self.pw_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.pw_hash, pw)


class Workspace(db.Model):
    """One client engagement. The wipe boundary: deleting this cascades everything."""
    __tablename__ = "workspaces"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    client = db.Column(db.String(120))
    proxy = db.Column(db.String(255))  # e.g. http://127.0.0.1:8080 (Burp) for all requests
    # Engagement scope — see app/scope.py. Empty means "no restriction" so existing
    # workspaces are unaffected; once set, nothing outside it is ever requested.
    scope = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))

    members = db.relationship("WorkspaceMember", back_populates="workspace",
                              cascade="all, delete-orphan")
    targets = db.relationship("Target", back_populates="workspace",
                              cascade="all, delete-orphan")
    runs = db.relationship("Run", back_populates="workspace",
                           cascade="all, delete-orphan")
    findings = db.relationship("Finding", back_populates="workspace",
                               cascade="all, delete-orphan")


class WorkspaceMember(db.Model):
    __tablename__ = "workspace_members"
    id = db.Column(db.Integer, primary_key=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey("workspaces.id", ondelete="CASCADE"),
                             nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False)
    role = db.Column(db.String(20), default="operator")  # owner | operator | viewer

    workspace = db.relationship("Workspace", back_populates="members")
    user = db.relationship("User", back_populates="memberships")
    __table_args__ = (db.UniqueConstraint("workspace_id", "user_id"),)


class Target(db.Model):
    __tablename__ = "targets"
    id = db.Column(db.Integer, primary_key=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey("workspaces.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    host = db.Column(db.String(255), nullable=False)
    scheme = db.Column(db.String(8), default="https")
    port = db.Column(db.Integer)
    notes = db.Column(db.Text)

    # Latest quick-probe result, for colour-coding the domain card.
    last_status_code = db.Column(db.Integer)
    last_alive = db.Column(db.Boolean)
    last_checked_at = db.Column(db.DateTime)
    last_alive_at = db.Column(db.DateTime)  # last time it responded alive
    last_waf = db.Column(db.String(120))    # detected WAF(s), comma-separated
    last_server = db.Column(db.String(200)) # Server header from last probe
    last_title = db.Column(db.String(300))  # <title> from last probe
    last_tech = db.Column(db.String(300))   # detected tech, comma-separated
    open_ports = db.Column(db.String(120))  # alt-HTTP ports answering, e.g. "8080, 8443"
    # Operator-added labels for THIS host ("I logged in, it's Salesforce"). Kept apart
    # from last_tech because every alive probe overwrites that; these must survive.
    manual_tech = db.Column(db.String(300))
    ip = db.Column(db.String(64))           # resolved IP
    asn = db.Column(db.String(16))          # origin ASN (e.g. "15169")
    asn_name = db.Column(db.String(200))    # ASN owner (e.g. "GOOGLE, US")
    country = db.Column(db.String(8))       # country code from the ASN lookup

    workspace = db.relationship("Workspace", back_populates="targets")
    notes = db.relationship("Note", back_populates="target",
                            cascade="all, delete-orphan", order_by="Note.created_at.desc()")

    @property
    def base_url(self):
        if self.port:
            return f"{self.scheme}://{self.host}:{self.port}"
        return f"{self.scheme}://{self.host}"

    @property
    def open_port_list(self):
        """Every port known to answer HTTP: the primary one (when the host is live) plus
        any alt ports the sweep found. Used for the "open port" filter."""
        ports = []
        if self.last_alive:
            ports.append(self.port or (443 if self.scheme == "https" else 80))
        for chunk in (self.open_ports or "").split(","):
            chunk = chunk.strip()
            if chunk.isdigit() and int(chunk) not in ports:
                ports.append(int(chunk))
        return sorted(ports)

    @property
    def manual_tech_list(self):
        return [x.strip() for x in (self.manual_tech or "").split(",") if x.strip()]

    def add_manual_tech(self, labels):
        """Add operator labels, de-duped case-insensitively against what's already there.
        Returns the labels actually added."""
        current = self.manual_tech_list
        lowered = {x.lower() for x in current}
        added = []
        for label in labels:
            label = " ".join(label.split())[:60]
            if label and label.lower() not in lowered:
                lowered.add(label.lower())
                current.append(label)
                added.append(label)
        joined = ", ".join(current)
        if len(joined) > 300:  # column cap — keep what fits rather than truncating mid-label
            return []
        self.manual_tech = joined or None
        return added

    def remove_manual_tech(self, label):
        kept = [x for x in self.manual_tech_list if x.lower() != label.strip().lower()]
        self.manual_tech = ", ".join(kept) or None


class Run(db.Model):
    __tablename__ = "runs"
    id = db.Column(db.Integer, primary_key=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey("workspaces.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    module = db.Column(db.String(60), nullable=False)
    config_json = db.Column(db.JSON, default=dict)
    status = db.Column(db.String(20), default="queued")  # queued|running|done|error
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    error = db.Column(db.Text)
    log = db.Column(db.Text)  # persisted verbose output, viewable after the run
    progress_done = db.Column(db.Integer, default=0)
    progress_total = db.Column(db.Integer, default=0)

    workspace = db.relationship("Workspace", back_populates="runs")

    @property
    def progress_pct(self):
        if not self.progress_total:
            return 0
        return min(100, int(self.progress_done * 100 / self.progress_total))
    findings = db.relationship("Finding", back_populates="run",
                               cascade="all, delete-orphan")


class Finding(db.Model):
    __tablename__ = "findings"
    id = db.Column(db.Integer, primary_key=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey("workspaces.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    run_id = db.Column(db.Integer, db.ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id", ondelete="CASCADE"))
    path = db.Column(db.String(1024), default="/")
    status_code = db.Column(db.Integer)
    content_length = db.Column(db.Integer)
    redirect = db.Column(db.String(1024))
    extra_json = db.Column(db.JSON, default=dict)
    found_at = db.Column(db.DateTime, default=datetime.utcnow)

    workspace = db.relationship("Workspace", back_populates="findings")
    run = db.relationship("Run", back_populates="findings")
    target = db.relationship("Target")

    def to_dict(self):
        return {
            "id": self.id,
            "target_id": self.target_id,
            "host": self.target.host if self.target else None,
            "base_url": self.target.base_url if self.target else None,
            "waf": self.target.last_waf if self.target else None,
            "path": self.path,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "redirect": self.redirect,
            "extra": self.extra_json or {},
            "found_at": self.found_at.isoformat() if self.found_at else None,
        }


class Note(db.Model):
    """Freeform operator note on a domain, optionally tied to a path."""
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey("workspaces.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    path = db.Column(db.String(1024))
    body = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    target = db.relationship("Target", back_populates="notes")


class TestedName(db.Model):
    """Dedup ledger for DNS brute-forcing — the name-space twin of TestedPath.

    Deliberately a separate table rather than reusing TestedPath: that one is keyed by
    parent_path and drives the "directory fuzz coverage" UI, so folding DNS labels into it
    would make bogus base paths appear against a host.
    """
    __tablename__ = "tested_names"
    __test__ = False  # not a pytest test class despite the "Test*" name
    id = db.Column(db.Integer, primary_key=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey("workspaces.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    domain = db.Column(db.String(255), nullable=False)  # the root that was brute-forced
    label = db.Column(db.String(255), nullable=False)   # the label tried, e.g. "api"
    resolved = db.Column(db.Boolean, default=False)
    first_tested_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("workspace_id", "domain", "label", name="uq_tested_name"),
    )


class Signature(db.Model):
    """An operator-added fingerprint rule: "if <needle> shows up in <field>, label it X".

    Deliberately global rather than per-workspace — recognising Salesforce is knowledge the
    whole team keeps, not something to re-enter per engagement. Matching is a
    case-insensitive substring test, so rules stay predictable and can't blow up a scan.
    """
    __tablename__ = "signatures"
    FIELDS = ("server", "powered_by", "header", "cookie", "body")

    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(80), nullable=False)   # what to call it, e.g. "Salesforce"
    field = db.Column(db.String(20), nullable=False)   # one of FIELDS
    needle = db.Column(db.String(200), nullable=False)  # substring to look for
    notes = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint("field", "needle", "label", name="uq_signature"),)


class TestedPath(db.Model):
    """Dedup ledger (used from M4). Records every word we ever request, hit or miss,
    keyed per (workspace, host, parent_path)."""
    __tablename__ = "tested_paths"
    __test__ = False  # not a pytest test class despite the "Test*" name
    id = db.Column(db.Integer, primary_key=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey("workspaces.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    host = db.Column(db.String(255), nullable=False)
    parent_path = db.Column(db.String(1024), nullable=False, default="/")
    word = db.Column(db.String(512), nullable=False)
    status_code = db.Column(db.Integer)
    first_tested_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("workspace_id", "host", "parent_path", "word",
                            name="uq_tested_path"),
    )
