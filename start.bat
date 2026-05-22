@echo off
REM AI Code Scanner — double-clickable launcher (Docker mode, all languages)
REM For host mode or different rule scope, run the .ps1 scripts directly.

cd /d "%~dp0"
powershell -NoExit -ExecutionPolicy Bypass -File ".\start-docker.ps1"
