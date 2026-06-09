@echo off
cd /d "%~dp0"

echo.
echo ==========================================
echo  AI Code Scanner - Starting...
echo ==========================================
echo.

docker compose up -d

echo.
echo  Waiting for services to be ready...

:wait
curl -s -f http://localhost:8000/health >nul 2>&1
if errorlevel 1 (
    timeout /t 3 /nobreak >nul
    goto wait
)

echo.
echo ==========================================
echo.
echo   AI Code Scanner is ready!
echo.
echo   http://localhost:8000
echo.
echo   To view logs:  docker compose logs -f
echo   To stop:       docker compose down
echo.
echo ==========================================
echo.

start http://localhost:8000
