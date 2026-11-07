@echo off
chcp 936 >nul
title xyVless - local dev

setlocal
cd /d "%~dp0"

echo [*] Checking port 8788 ...
powershell -NoProfile -Command "if (Get-NetTCPConnection -LocalPort 8788 -State Listen -ErrorAction SilentlyContinue) { exit 1 } else { exit 0 }"
if errorlevel 1 (
  echo [!] Port 8788 is already in use.
  echo     Stop the running service before starting a new one.
  echo     Check with: netstat -ano ^| findstr :8788
  echo.
  pause
  exit /b 1
)

echo [*] Port is free, clearing Wrangler local cache ...
if exist ".wrangler" rmdir /s /q ".wrangler"
if exist "node_modules\.cache\wrangler" rmdir /s /q "node_modules\.cache\wrangler"
if exist ".dev.vars" echo [i] .dev.vars kept as is.

echo [*] Starting Wrangler Pages dev on http://127.0.0.1:8788
echo.
npx wrangler pages dev public

echo.
echo [*] Dev server stopped.
pause
