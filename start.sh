#!/usr/bin/env bash
# Thoth local launcher (Linux/macOS). No Docker/Postgres/Redis needed.
#
#   ./start.sh                 local only  — http://127.0.0.1:5000 (debug on)
#   ./start.sh --lan           share on the LAN — binds 0.0.0.0, debug OFF (gunicorn)
#   ./start.sh --host=IP --port=N   custom bind
#
# Any non-loopback bind runs WITHOUT Flask debug on purpose: the debug console is remote
# code execution for anyone who can reach the port.
set -e
cd "$(dirname "$0")"

HOST=127.0.0.1
PORT=5000
for arg in "$@"; do
  case "$arg" in
    --lan)      HOST=0.0.0.0 ;;
    --host=*)   HOST="${arg#*=}" ;;
    --port=*)   PORT="${arg#*=}" ;;
    -h|--help)  echo "usage: ./start.sh [--lan] [--host=IP] [--port=N]"; exit 0 ;;
    *) echo "unknown option: $arg"; exit 2 ;;
  esac
done

# Loopback => trusted local dev (debug ok). Anything else => exposed (debug off).
case "$HOST" in
  127.0.0.1|localhost|::1) EXPOSED=0 ;;
  *) EXPOSED=1 ;;
esac

if [ ! -d .venv ]; then
  echo "[thoth] creating virtualenv..."
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
echo "[thoth] installing dependencies..."
python -m pip install -q -r requirements.txt

export FLASK_APP=wsgi.py
[ -f .env ] || cp .env.example .env

if [ "$EXPOSED" = "1" ]; then
  echo "[thoth] seeding admin account (random password if new — shown once)..."
  flask seed                    # debug off => generates a strong password for a new account
  echo
  echo "[thoth] Sharing on the network (debug OFF, gunicorn)."
  echo "        URL:   http://$(hostname -I 2>/dev/null | awk '{print $1}'):$PORT   (your LAN IP)"
  echo "        Change the default password:  flask passwd            (see README)"
  echo "        Add teammates from the Users page (you are admin)."
  echo "        No TLS — keep this on a trusted LAN/VPN (e.g. Tailscale)."
  echo
  # gunicorn: no debug console; --threads gives headroom for live (SSE) connections.
  exec gunicorn -b "$HOST:$PORT" --threads 16 --timeout 120 wsgi:app
else
  export FLASK_DEBUG=1
  echo "[thoth] seeding local dev account magna:magna..."
  flask seed
  echo "[thoth] starting on http://$HOST:$PORT  (login: magna / magna)"
  exec flask run --debug --host "$HOST" --port "$PORT"
fi
