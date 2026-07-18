#!/usr/bin/env bash
# Thoth local launcher (Linux/macOS). No Docker/Postgres/Redis needed.
set -e
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "[thoth] creating virtualenv..."
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate
echo "[thoth] installing dependencies..."
python -m pip install -q -r requirements.txt

export FLASK_APP=wsgi.py
export FLASK_DEBUG=1
[ -f .env ] || cp .env.example .env

echo "[thoth] seeding local dev account magna:magna..."
flask seed

echo "[thoth] starting on http://127.0.0.1:5000  (login: magna / magna)"
flask run --debug
