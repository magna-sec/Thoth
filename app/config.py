"""Environment-driven config. Sensible local defaults; Docker overrides via env."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


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

    DATA_DIR = Path(os.environ.get("DATA_DIR", BASE_DIR / "data"))
    WORDLIST_DIR = BASE_DIR / "wordlists"
