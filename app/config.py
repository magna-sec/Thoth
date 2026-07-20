"""Environment-driven config. Sensible local defaults; Docker overrides via env."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _abs_dir(value, default):
    """Resolve a configured directory to an absolute path, relative paths being taken
    from the project root rather than whatever the cwd happens to be."""
    if not value:
        return Path(default)
    path = Path(value).expanduser()
    return path if path.is_absolute() else (BASE_DIR / path).resolve()


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-me")

    # DB: default to local SQLite so the app runs with zero external services.
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'thoth.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Celery. No broker set => run tasks eagerly (inline) so local dev needs no Redis.
    CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL")
    CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND")
    CELERY_TASK_ALWAYS_EAGER = CELERY_BROKER_URL is None

    # Redis for realtime pub/sub. Optional — SSE falls back to DB polling.
    REDIS_URL = os.environ.get("REDIS_URL")

    # Always absolute. `.env` ships DATA_DIR=./data, and a relative path here breaks in two
    # ways: it resolves against the cwd (which differs between the web server and the
    # spawned task process) and Flask's send_from_directory resolves it against the app
    # package dir instead — so files got written in one place and served from another.
    DATA_DIR = _abs_dir(os.environ.get("DATA_DIR"), BASE_DIR / "data")
    WORDLIST_DIR = BASE_DIR / "wordlists"
