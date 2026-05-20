#!/bin/sh
set -e
# $HOME is a tmpfs owned by uid 10001 (scanner). Prepare writable Semgrep state.
mkdir -p "${HOME}/.semgrep"
if [ -d /opt/semgrep-seed ] && [ -n "$(ls -A /opt/semgrep-seed 2>/dev/null)" ]; then
  cp -a /opt/semgrep-seed/. "${HOME}/.semgrep/"
fi
exec semgrep "$@"
