@echo off
REM Thoth local launcher (Windows). No Docker/Postgres/Redis needed.
setlocal
cd /d "%~dp0"

if not exist .venv (
    echo [thoth] creating virtualenv...
    python -m venv .venv
)

call .venv\Scripts\activate.bat
echo [thoth] installing dependencies...
python -m pip install -q -r requirements.txt

set FLASK_APP=wsgi.py
set FLASK_DEBUG=1
if not exist .env copy .env.example .env >nul

echo [thoth] seeding local dev account magna:magna...
flask seed

echo [thoth] starting on http://127.0.0.1:5000  (login: magna / magna)
flask run --debug
