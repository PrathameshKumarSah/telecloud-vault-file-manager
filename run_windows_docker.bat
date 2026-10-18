@echo off
title TeleCloud Vault - Docker Compose Launcher
echo ===============================================================
echo   TeleCloud Vault - Checking Docker Desktop Engine...
echo ===============================================================
if not exist ".env" (
    copy .env.example .env >nul
)
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Docker Desktop is not running yet.
    echo     Starting Docker Desktop... Please wait 20-30 seconds until the whale icon in your system tray is steady, then run this script again.
    if exist "C:\Program Files\Docker\Docker\Docker Desktop.exe" (
        start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    )
    pause
    exit /b 1
)
docker compose up -d --build
echo.
echo [OK] TeleCloud Vault is live at http://localhost and http://localhost:8000
start "" http://localhost:8000
pause
