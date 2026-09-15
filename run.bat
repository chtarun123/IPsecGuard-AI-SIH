@echo off
title IPsecGuard AI Launcher
color 0b
echo ============================================================
echo         Launching IPsecGuard AI (Frontend + Backend)
echo ============================================================
echo.
echo [1/2] Starting FastAPI Backend on port 8000...
start "IPsecGuard Backend" cmd /k "cd /d %~dp0backend && python -m uvicorn main:app --reload --port 8000"

echo [2/2] Starting React Frontend on port 5173...
start "IPsecGuard Frontend" cmd /k "cd /d %~dp0frontend && npm.cmd run dev"

echo.
echo Waiting for servers to initialize...
timeout /t 3 /nobreak >nul

echo Opening browser at http://localhost:5173 ...
start http://localhost:5173

echo.
echo ============================================================
echo  [OK] BOTH SERVERS ARE RUNNING! BROWSER OPENED.
echo ============================================================
echo.
