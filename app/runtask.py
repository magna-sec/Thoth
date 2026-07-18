"""Entry point to run one task in its OWN process:  python -m app.runtask <run_id>

Executing scans in a separate process (rather than a background thread) keeps their CPU
and the requests thread-pool off the web server's GIL, so the UI stays responsive during a
dirsearch. The child talks to the same DB (SQLite WAL handles multi-process access)."""
import sys

from dotenv import load_dotenv

load_dotenv()

from app import create_app  # noqa: E402
from app.tasks import run_module_task  # noqa: E402


def main():
    if len(sys.argv) < 2:
        print("usage: python -m app.runtask <run_id>", file=sys.stderr)
        raise SystemExit(2)
    run_id = int(sys.argv[1])
    app = create_app()
    with app.app_context():
        run_module_task.run(run_id)  # raw function; we already hold an app context


if __name__ == "__main__":
    main()
