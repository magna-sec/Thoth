"""The Plugins catalogue — what's plugged into the platform.

A global page (plugins are capabilities of the platform, not of one workspace) showing both
plugin kinds: modules that run against targets, and parsers that ingest artifacts.
"""
from flask import Blueprint, render_template
from flask_login import login_required

from ..modules import all_modules
from .base import all_parsers

plugins_bp = Blueprint("plugins", __name__, url_prefix="/plugins")


@plugins_bp.route("/")
@login_required
def catalog():
    modules = sorted(all_modules().values(), key=lambda m: m.name)
    parsers = sorted(all_parsers().values(), key=lambda p: p.name)
    return render_template("plugins/catalog.html", modules=modules, parsers=parsers)
