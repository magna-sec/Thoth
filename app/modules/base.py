"""Pluggable module framework. A capability = a Module subclass; drop a file in this
package and it auto-registers. dirsearch will be just another module later."""
from abc import ABC, abstractmethod

from ..extensions import db
from ..models import Finding
from ..realtime import publish

REGISTRY = {}


def register(cls):
    """Class decorator: instantiate and register a module by its ``name``."""
    REGISTRY[cls.name] = cls()
    return cls


def get_module(name):
    return REGISTRY.get(name)


def all_modules():
    return REGISTRY


def to_proxies(url):
    """Build a requests proxies dict from a single proxy URL (Burp etc.), or None."""
    return {"http": url, "https": url} if url else None


class RunContext:
    """Handed to every module.run(). Persists findings and pushes live events."""

    def __init__(self, run):
        from ..scope import for_workspace
        self.run = run
        self.workspace_id = run.workspace_id
        self.proxy = run.workspace.proxy if run.workspace else None
        self.proxies = to_proxies(self.proxy)
        # Plain data, safe to consult from worker threads.
        self.scope = for_workspace(run.workspace) if run.workspace else for_workspace(None)

    def in_scope(self, host):
        """Modules that discover new hosts must check them before requesting anything."""
        return self.scope.allows(host)

    def set_progress(self, done, total):
        """Persist task progress (done/total requests) for the UI progress bar."""
        self.run.progress_done = done
        self.run.progress_total = total
        db.session.commit()

    def log(self, message):
        """Verbose progress line: persisted on the run (viewable later) and streamed live."""
        from datetime import datetime
        line = f"{datetime.utcnow():%H:%M:%S} {message}"
        self.run.log = (self.run.log or "") + line + "\n"
        db.session.commit()
        self.emit({"type": "log", "run_id": self.run.id, "msg": message})

    def finding(self, target, path="/", status_code=None, content_length=None,
                redirect=None, log=None, **extra):
        f = Finding(
            workspace_id=self.workspace_id,
            run_id=self.run.id,
            target_id=target.id,
            path=path,
            status_code=status_code,
            content_length=content_length,
            redirect=redirect,
            extra_json=extra or {},
        )
        db.session.add(f)
        if log is not None:  # append a CLI-style line in the same commit as the finding
            from datetime import datetime
            self.run.log = (self.run.log or "") + f"{datetime.utcnow():%H:%M:%S} {log}\n"
        db.session.commit()
        publish(self.workspace_id, {"type": "finding", "run_id": self.run.id,
                                    "finding": f.to_dict()})
        if log is not None:
            publish(self.workspace_id, {"type": "log", "run_id": self.run.id, "msg": log})
        return f

    def emit(self, event):
        publish(self.workspace_id, event)


class Module(ABC):
    name: str = "base"
    version: str = "0.1"
    description: str = ""
    reports_progress: bool = False  # True if the module drives ctx.set_progress itself
    supports_batch: bool = False     # True if the module implements run_all(targets, ...)
    needs_targets: bool = True       # False for discovery modules, which create targets

    def run_all(self, targets, config, ctx):  # optional batch entry point
        raise NotImplementedError

    def config_schema(self):
        """Return a list of field dicts used to render the run form.
        Each: {name, type, default, label, help?}. Types: number|text|select|bool."""
        return []

    @abstractmethod
    def run(self, target, config, ctx: RunContext):
        """Execute against a single target, emitting findings via ctx."""
        raise NotImplementedError
