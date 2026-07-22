"""Parser-plugin framework — the drop-in half of Thoth's plugin story.

Thoth already auto-registers *module* plugins (things that run against targets: alive,
dirsearch, screenshot, …) in ``app/modules``. This is the twin for *parser* plugins: things
that ingest text an operator already has (a PAC file, ``dsregcmd /status`` output, …),
parse it, and render it tidily.

Adding one is the same one-file experience as a module: drop ``app/plugins/foo_plugin.py``
with a ``@register_parser`` class, and it appears in the upload picker, in auto-detect, in
the Plugins catalogue, and renders through its own partial — no other file touched.
"""
from abc import ABC, abstractmethod

PARSER_REGISTRY = {}


def register_parser(cls):
    """Class decorator: instantiate and register a parser plugin by its ``name``."""
    PARSER_REGISTRY[cls.name] = cls()
    return cls


def get_parser(name):
    return PARSER_REGISTRY.get(name)


def all_parsers():
    return PARSER_REGISTRY


def detect_parser(text):
    """The first plugin that recognises this text, or None. Used for 'auto-detect'."""
    for plugin in PARSER_REGISTRY.values():
        try:
            if plugin.detect(text):
                return plugin
        except Exception:  # noqa: BLE001 - a bad detect() must never block the others
            continue
    return None


class ParserPlugin(ABC):
    """Ingest text, parse it to structured data, and describe how to show it.

    ``parse`` may raise ``ValueError`` for input that looks like the right kind but is
    malformed; the ingestion route turns that into a flash message.
    """
    name: str = "base"            # slug + Artifact.kind, e.g. "pac"
    title: str = "Parser"         # display name, e.g. "PAC file"
    description: str = ""
    glyph: str = "🧩"             # catalogue icon (kept ASCII-safe elsewhere)
    placeholder: str = ""         # textarea hint
    partial: str = ""             # template partial that renders parsed data
    collect: str = ""             # command(s) to collect this input on the target host
    # "artifact" — parse() output is stored as an Artifact and rendered via `partial`.
    # "findings" — the plugin instead ingests into the workspace (Findings on targets) via
    #   ingest(); nothing is stored as an Artifact. e.g. nuclei → subdomain vulnerabilities.
    kind: str = "artifact"

    @abstractmethod
    def detect(self, text) -> bool:
        """Cheap heuristic: does this text look like ours? Drives auto-detect."""

    @abstractmethod
    def parse(self, text) -> dict:
        """Return JSON-serialisable structured data for storage + rendering."""

    def summary(self, data) -> str:
        """One-line summary for the artifact list. Override for something useful."""
        return ""

    def ingest(self, ws, data, user):
        """For kind == "findings": write `data` into the workspace and return
        ``{"message", "category", "redirect"}``. Unused for artifact plugins."""
        raise NotImplementedError
