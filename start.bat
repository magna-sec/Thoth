@echo off
REM Thoth local launcher (Windows). No Docker/Postgres/Redis needed.
REM
REM   start.bat            local only  - http://127.0.0.1:5000 (debug on)
REM   start.bat --lan      share on the LAN - binds 0.0.0.0, debug OFF
REM
REM Exposing on the network runs WITHOUT Flask debug on purpose: the debug console is
REM remote code execution for anyone who can reach the port.
setlocal
cd /d "%~dp0"

set HOST=127.0.0.1
set PORT=5000
set EXPOSED=0
if /I "%~1"=="--lan" ( set HOST=0.0.0.0& set EXPOSED=1 )

if not exist .venv (
    echo [thoth] creating virtualenv...
    python -m venv .venv
)
call .venv\Scripts\activate.bat
echo [thoth] installing dependencies...
python -m pip install -q -r requirements.txt

set FLASK_APP=wsgi.py
if not exist .env copy .env.example .env >nul

if "%EXPOSED%"=="1" (
    echo [thoth] seeding admin account ^(random password if new - shown once^)...
    flask seed
    echo.
    echo [thoth] Sharing on the network ^(debug OFF^). Find your IP with:  ipconfig
    echo         URL:   http://YOUR-IP:%PORT%
    echo         Change the default password:  flask passwd
    echo         Add teammates from the Users page ^(you are admin^).
    echo         No TLS - keep this on a trusted LAN/VPN ^(e.g. Tailscale^).
    echo.
    REM Native Windows can't run gunicorn ^(no fork^); this is the dev server, debug off.
    flask run --host %HOST% --port %PORT%
) else (
    set FLASK_DEBUG=1
    echo [thoth] seeding local dev account magna:magna...
    flask seed
    echo [thoth] starting on http://127.0.0.1:%PORT%  ^(login: magna / magna^)
    flask run --debug
)
