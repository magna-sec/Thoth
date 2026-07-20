"""Manage custom fingerprint signatures — "if I see this, call it Salesforce".

Global, not per-workspace: recognising a platform is team knowledge worth keeping across
engagements. Adding is open to any operator (it's additive and reversible); deleting a
shared rule is admin-only, like the other structural actions.
"""
from flask import (Blueprint, abort, flash, redirect, render_template, request, url_for)
from flask_login import current_user, login_required

from ..auth import admin_required
from ..extensions import db
from ..models import Signature, User
from ..modules.alive import BUILTIN_SIGNATURES

sigs_bp = Blueprint("signatures", __name__, url_prefix="/fingerprints")


@sigs_bp.route("/")
@login_required
def index():
    sigs = Signature.query.order_by(Signature.label, Signature.field).all()
    builtin = sorted(BUILTIN_SIGNATURES, key=lambda s: (s[2].lower(), s[0]))
    return render_template("signatures/list.html", signatures=sigs, builtin=builtin,
                           fields=Signature.FIELDS,
                           user_by_id=dict(db.session.query(User.id, User.email).all()))


@sigs_bp.route("/add", methods=["POST"])
@login_required
def add():
    """Create a signature. `next` lets the subdomain page send you back where you were."""
    label = request.form.get("label", "").strip()
    field = request.form.get("field", "").strip()
    needle = request.form.get("needle", "").strip()
    back = request.form.get("next") or url_for("signatures.index")

    if not label or not needle:
        flash("A label and something to match on are both required.", "error")
    elif field not in Signature.FIELDS:
        flash(f"Unknown match location '{field}'.", "error")
    elif len(needle) < 3:
        flash("Match text must be at least 3 characters — shorter needles match "
              "almost everything.", "error")
    elif Signature.query.filter_by(field=field, needle=needle, label=label).first():
        flash(f"That {label} signature already exists.", "error")
    else:
        db.session.add(Signature(label=label, field=field, needle=needle,
                                 notes=request.form.get("notes", "").strip() or None,
                                 created_by=current_user.id))
        db.session.commit()
        flash(f"Added fingerprint: {label} when {field} contains '{needle}'. "
              f"It applies from the next alive check.", "info")
    return redirect(back)


@sigs_bp.route("/<int:sig_id>/delete", methods=["POST"])
@admin_required
def delete(sig_id):
    sig = db.session.get(Signature, sig_id)
    if sig is None:
        abort(404)
    db.session.delete(sig)
    db.session.commit()
    flash(f"Deleted the {sig.label} signature.", "info")
    return redirect(request.form.get("next") or url_for("signatures.index"))
