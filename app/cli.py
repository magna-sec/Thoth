"""CLI commands: seed an account, and wipe workspaces between engagements."""
import secrets
import shutil

import click

from .extensions import db
from .models import User, Workspace


def register_cli(app):
    @app.cli.command("seed")
    @click.option("--email", default="magna", help="Account email/username.")
    @click.option("--password", default=None,
                  help="Password. Omit to generate a random one (recommended).")
    @click.option("--force", is_flag=True,
                  help="Allow the insecure default password outside debug mode.")
    def seed(email, password, force):
        """Create an admin account.

        With no --password a strong random one is generated and printed once. The legacy
        'magna:magna' default is DEV-ONLY: it is refused outside FLASK debug unless --force.
        Never deploy with a default/shared password.
        """
        if password is None:
            if email == "magna" and app.debug and not force:
                password = "magna"  # convenience for local dev only
                click.secho("WARNING: created DEV account magna:magna - do NOT deploy this. "
                            "Change the password or delete this account before going live.",
                            fg="yellow")
            else:
                password = secrets.token_urlsafe(16)
                click.secho(f"Generated password for {email}: {password}", fg="green")
                click.echo("(shown once — store it now)")
        elif password == "magna" and not (app.debug or force):
            raise click.ClickException(
                "Refusing to set the insecure default password outside debug mode. "
                "Pass --force only if you really mean it.")

        u = User.query.filter_by(email=email).first()
        if u is None:
            u = User(email=email, is_admin=True)
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            click.echo(f"Created admin user '{email}'")
        else:
            click.echo(f"User '{email}' already exists — no change")

    @app.cli.command("passwd")
    @click.option("--email", default="magna", help="Account to update (default: magna).")
    @click.option("--password", default=None,
                  help="New password. Omit to be prompted (hidden input).")
    def passwd(email, password):
        """Set / reset a user's password."""
        u = User.query.filter_by(email=email).first()
        if u is None:
            raise click.ClickException(
                f"No user '{email}'. Existing users: "
                + (", ".join(x.email for x in User.query.all()) or "none"))
        if not password:
            password = click.prompt("New password", hide_input=True,
                                     confirmation_prompt=True)
        u.set_password(password)
        db.session.commit()
        click.secho(f"Password updated for '{email}'.", fg="green")

    @app.cli.command("wipe")
    @click.argument("workspace_id", required=False, type=int)
    @click.option("--all", "wipe_all", is_flag=True, help="Wipe every workspace")
    def wipe(workspace_id, wipe_all):
        """Wipe a workspace (DB cascade + on-disk files). Use between client work."""
        data_dir = app.config["DATA_DIR"] / "workspaces"
        targets = Workspace.query.all() if wipe_all else (
            [db.session.get(Workspace, workspace_id)] if workspace_id else [])
        if not targets or targets == [None]:
            click.echo("Nothing to wipe. Pass a WORKSPACE_ID or --all.")
            return
        for ws in targets:
            if ws is None:
                continue
            wid = ws.id
            db.session.delete(ws)  # cascades to targets/runs/findings/tested_paths
            db.session.commit()
            wdir = data_dir / str(wid)
            if wdir.exists():
                shutil.rmtree(wdir, ignore_errors=True)
            click.echo(f"Wiped workspace {wid}")
