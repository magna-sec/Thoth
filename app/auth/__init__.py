"""Auth helpers, including the admin-only access decorator."""
from functools import wraps

from flask import abort
from flask_login import current_user, login_required


def admin_required(view):
    """Require an authenticated admin. Non-admins get 403; anonymous users are redirected
    to login by the wrapped login_required."""
    @wraps(view)
    @login_required
    def wrapper(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)

    return wrapper
