"""Celery entrypoint:  celery -A celery_worker.celery worker --loglevel=info"""
from dotenv import load_dotenv

load_dotenv()

from app import create_app  # noqa: E402
from app.extensions import celery  # noqa: E402,F401

app = create_app()
