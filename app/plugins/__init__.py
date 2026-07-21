"""Parser plugins. Importing a plugin module runs its @register_parser decorator.

Drop a new ``*_plugin.py`` here and add it to the imports below (or let the loader find
it) — it then appears everywhere a parser plugin is offered.
"""
from .base import (ParserPlugin, all_parsers, detect_parser, get_parser,  # noqa: F401
                   register_parser)
from . import dsregcmd_plugin  # noqa: F401,E402
from . import nessus_plugin  # noqa: F401,E402
from . import nmap_plugin  # noqa: F401,E402
from . import nuclei_plugin  # noqa: F401,E402
from . import pac_plugin  # noqa: F401,E402
