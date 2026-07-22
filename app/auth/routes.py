"""Login / logout + admin-only user management (no open self-registration)."""
import secrets

from flask import (Blueprint, abort, flash, redirect, render_template, request,
                   url_for)
from flask_login import current_user, login_required, login_user, logout_user

from ..extensions import db
from ..models import LoginEvent, User
from . import admin_required

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            db.session.add(LoginEvent(
                user_id=user.id, ip=(request.remote_addr or "")[:64],
                user_agent=(request.headers.get("User-Agent") or "")[:300]))
            db.session.commit()
            return redirect(request.args.get("next") or url_for("index"))
        flash("Invalid credentials", "error")
    return render_template("auth/login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


@auth_bp.route("/users", methods=["GET", "POST"])
@admin_required
def users():
    """Admin-only: list users and create new ones (non-admin by default)."""
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        is_admin = request.form.get("is_admin") is not None
        if not email:
            flash("Email/username required", "error")
        elif User.query.filter_by(email=email).first():
            flash("A user with that email already exists", "error")
        else:
            generated = None
            if not password:
                password = generated = secrets.token_urlsafe(12)
            u = User(email=email, is_admin=is_admin)
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            flash(f"Created {'admin' if is_admin else 'user'} '{email}'"
                  + (f" — password: {generated}" if generated else ""), "info")
        return redirect(url_for("auth.users"))
    users = User.query.order_by(User.email).all()
    return render_template("auth/users.html", users=users)


@auth_bp.route("/users/<int:user_id>")
@admin_required
def user_detail(user_id):
    """Admin: one user's details + recent sign-in history (times / IPs)."""
    u = db.session.get(User, user_id)
    if u is None:
        abort(404)
    logins = (LoginEvent.query.filter_by(user_id=u.id)
              .order_by(LoginEvent.at.desc()).limit(100).all())
    return render_template("auth/user_detail.html", u=u, logins=logins,
                           login_count=LoginEvent.query.filter_by(user_id=u.id).count())


@auth_bp.route("/users/<int:user_id>/password", methods=["POST"])
@admin_required
def set_password(user_id):
    """Admin: set/reset a user's password (their own row = change my password)."""
    u = db.session.get(User, user_id)
    if u is None:
        abort(404)
    pw = request.form.get("password", "").strip()
    if len(pw) < 8:
        flash("Password must be at least 8 characters.", "error")
    else:
        u.set_password(pw)
        db.session.commit()
        who = "your password" if u.id == current_user.id else f"password for '{u.email}'"
        flash(f"Updated {who}.", "info")
    return redirect(url_for("auth.users"))


@auth_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    u = db.session.get(User, user_id)
    if u is None:
        abort(404)
    if u.id == current_user.id:
        flash("You can't delete your own account.", "error")
    else:
        db.session.delete(u)
        db.session.commit()
        flash(f"Deleted user '{u.email}'", "info")
    return redirect(url_for("auth.users"))
