"""Shared extension instances + Celery factory."""
from celery import Celery, Task
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
csrf = CSRFProtect()
celery = Celery(__name__)


def init_celery(app):
    """Bind Celery to the Flask app so tasks run inside an app context."""
    celery.conf.update(
        broker_url=app.config["CELERY_BROKER_URL"] or "memory://",
        result_backend=app.config["CELERY_RESULT_BACKEND"] or "cache+memory://",
        task_always_eager=app.config["CELERY_TASK_ALWAYS_EAGER"],
        task_eager_propagates=True,
    )

    class ContextTask(Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery
