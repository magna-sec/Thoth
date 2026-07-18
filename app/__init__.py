"""Application factory."""
from flask import Flask, redirect, url_for
from flask_login import login_required

from .config import Config
from .extensions import csrf, db, init_celery, login_manager, migrate


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)
    app.config["DATA_DIR"].mkdir(parents=True, exist_ok=True)

    # Recon targets routinely have bad/self-signed certs; we intentionally probe with
    # verify=False, so silence urllib3's per-request InsecureRequestWarning spam.
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    init_celery(app)

    from . import models  # noqa: F401  (register models)
    from . import modules  # noqa: F401  (trigger module registration)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(models.User, int(user_id))

    from .auth.routes import auth_bp
    from .runs.routes import runs_bp
    from .workspaces.routes import ws_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(ws_bp)
    app.register_blueprint(runs_bp)

    from .cli import register_cli
    register_cli(app)

    @app.route("/")
    @login_required
    def index():
        return redirect(url_for("workspaces.list_workspaces"))

    # Zero-friction local start: ensure tables exist (use migrations in production).
    with app.app_context():
        _enable_sqlite_concurrency()
        db.create_all()
        _lightweight_migrate()

    return app


def _enable_sqlite_concurrency():
    """SQLite defaults serialize readers/writers, so a background run thread writing while
    the UI polls /activity + SSE throws 'database is locked'. WAL + a busy timeout let
    reads and writes coexist. No-op on Postgres."""
    if db.engine.dialect.name != "sqlite":
        return
    from sqlalchemy import event

    @event.listens_for(db.engine, "connect")
    def _set_pragmas(dbapi_conn, _record):  # noqa: ANN001
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=8000")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")  # enforce ON DELETE CASCADE (e.g. wipe -> ledger)
        cur.close()


def _lightweight_migrate():
    """Add columns that create_all() can't add to pre-existing tables.
    A stopgap until Alembic migrations; safe/idempotent on SQLite and Postgres."""
    from sqlalchemy import inspect, text

    insp = inspect(db.engine)
    dt = "TIMESTAMP" if db.engine.dialect.name == "postgresql" else "DATETIME"
    wanted = {
        "workspaces": {
            "proxy": "VARCHAR(255)",
        },
        "runs": {
            "log": "TEXT",
            "progress_done": "INTEGER",
            "progress_total": "INTEGER",
        },
        "targets": {
            "last_status_code": "INTEGER",
            "last_alive": "BOOLEAN",
            "last_checked_at": dt,
            "last_alive_at": dt,
            "last_waf": "VARCHAR(120)",
            "last_server": "VARCHAR(200)",
            "last_title": "VARCHAR(300)",
            "last_tech": "VARCHAR(300)",
            "ip": "VARCHAR(64)",
            "asn": "VARCHAR(16)",
            "asn_name": "VARCHAR(200)",
            "country": "VARCHAR(8)",
        },
    }
    for table, cols in wanted.items():
        if table not in insp.get_table_names():
            continue
        existing = {c["name"] for c in insp.get_columns(table)}
        missing = {name: typ for name, typ in cols.items() if name not in existing}
        if missing:
            with db.engine.begin() as conn:
                for name, typ in missing.items():
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {typ}"))
