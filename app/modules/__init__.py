"""Import modules so their @register decorators run at app startup."""
from . import alive  # noqa: F401
from . import dirsearch  # noqa: F401
from .base import Module, RunContext, all_modules, get_module, register  # noqa: F401
