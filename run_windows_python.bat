@echo off
title TeleCloud Vault - Native Windows Server (No Docker Required)
echo ===============================================================
echo   TeleCloud Vault - Starting Local FastAPI + PostgreSQL Server
echo ===============================================================
echo This requires a PostgreSQL server already running locally
echo (e.g. installed from https://www.postgresql.org/download/windows/
echo  with a "telecloud_vault" database created for the user below).
echo.
if not exist ".venv" (
    echo [1/3] Creating Python virtual environment...
    python -m venv .venv
)
echo [2/3] Installing requirements...
call .venv\Scripts\activate.bat
pip install --upgrade pip >nul
pip install -r backend\requirements.txt
if not defined DATABASE_URL set DATABASE_URL=postgresql://telecloud:telecloud@localhost:5432/telecloud_vault
set VAULT_MASTER_KEY=8f4e2a9c1b7d6e3f5a0c9b8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f
echo Using DATABASE_URL=%DATABASE_URL%
echo [3/3] Starting TeleCloud Vault at http://localhost:8000 ...
start "" http://localhost:8000
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
pause
