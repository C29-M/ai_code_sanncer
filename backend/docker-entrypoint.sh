#!/bin/sh
set -e
# Prepare writable Semgrep state directory for the scanner user.
mkdir -p "${HOME}/.semgrep"
if [ -d /opt/semgrep-seed ] && [ -n "$(ls -A /opt/semgrep-seed 2>/dev/null)" ]; then
  cp -a /opt/semgrep-seed/. "${HOME}/.semgrep/"
fi
# Start the FastAPI backend
exec uvicorn main:app --host 0.0.0.0 --port 8000
