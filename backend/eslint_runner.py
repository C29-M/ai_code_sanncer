"""
ESLint Security runner for AI Code Scanner — Week 4.

Runs ESLint with eslint-plugin-security rules against JS/TS files.
Uses an isolated config (--no-eslintrc) so the repo's own .eslintrc
cannot interfere with security rule results (Problem #5).

Activated only when the repo contains JS/TS source files.
Requires: npm i -g eslint eslint-plugin-security
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from exceptions import ScannerError

ESLINT_TIMEOUT = 120

# Security rules to enforce — isolated from any repo config
SECURITY_RULES = {
    "security/detect-eval-with-expression": "error",
    "security/detect-non-literal-regexp": "warn",
    "security/detect-non-literal-require": "warn",
    "security/detect-object-injection": "warn",
    "security/detect-possible-timing-attacks": "warn",
    "security/detect-pseudoRandomBytes": "error",
    "security/detect-unsafe-regex": "warn",
    "security/detect-buffer-noassert": "warn",
    "security/detect-child-process": "warn",
    "security/detect-disable-mustache-escape": "error",
    "security/detect-new-buffer": "warn",
    "security/detect-no-csrf-before-method-override": "error",
}

ISOLATED_ESLINT_CONFIG = {
    "plugins": ["security"],
    "rules": SECURITY_RULES,
    "env": {"node": True, "browser": True, "es2021": True},
    "parserOptions": {"ecmaVersion": 2021, "sourceType": "module"},
}


class ESLintScanError(ScannerError):
    def __init__(self, message: str = "ESLint scan failed.") -> None:
        super().__init__(message, status_code=500)


def _eslint_cli() -> str:
    """Find the ESLint binary."""
    for name in ("eslint", "eslint.cmd"):
        exe = shutil.which(name)
        if exe:
            return exe
    raise ESLintScanError(
        "ESLint is not installed or not on PATH. "
        "Install with: npm i -g eslint eslint-plugin-security"
    )


def _find_plugin_root() -> str | None:
    """
    Find where eslint-plugin-security is installed.
    Returns the node_modules directory that contains the plugin, or None.
    """
    # Check global npm root
    try:
        res = subprocess.run(
            ["npm", "root", "-g"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        global_root = res.stdout.strip()
        if global_root and (Path(global_root) / "eslint-plugin-security").exists():
            return global_root
    except Exception:  # noqa: BLE001
        pass

    # Check next to the eslint binary
    try:
        eslint = shutil.which("eslint")
        if eslint:
            # e.g. /usr/local/bin/eslint → /usr/local/lib/node_modules
            bin_parent = Path(eslint).parent.parent
            for candidate in (
                bin_parent / "lib" / "node_modules",
                bin_parent / "node_modules",
            ):
                if (candidate / "eslint-plugin-security").exists():
                    return str(candidate)
    except Exception:  # noqa: BLE001
        pass

    return None


def run_eslint_scan(repo_path: Path) -> list[dict]:
    """
    Run ESLint with security rules against the cloned repository.

    Uses an isolated config so the repo's own ESLint setup is ignored.
    Returns a flat list of ESLint message dicts, each with a 'filePath' key added.
    Raises ESLintScanError if ESLint or the security plugin is not available.
    """
    if not repo_path.is_dir():
        raise ESLintScanError(f"Repository path does not exist: {repo_path}")

    eslint = _eslint_cli()
    plugin_root = _find_plugin_root()
    if not plugin_root:
        raise ESLintScanError(
            "eslint-plugin-security is not installed. "
            "Install with: npm i -g eslint-plugin-security"
        )

    findings: list[dict] = []

    # Write the isolated config to a temp dir so it's completely separate
    # from anything in the repo
    with tempfile.TemporaryDirectory() as tmp_dir:
        config_path = Path(tmp_dir) / ".eslintrc.json"
        config_path.write_text(
            json.dumps(ISOLATED_ESLINT_CONFIG, indent=2), encoding="utf-8"
        )

        # Extend NODE_PATH so ESLint can find eslint-plugin-security
        env = os.environ.copy()
        existing_node_path = env.get("NODE_PATH", "")
        env["NODE_PATH"] = (
            f"{plugin_root}{os.pathsep}{existing_node_path}"
            if existing_node_path
            else plugin_root
        )

        # Target: all JS/TS files, skipping node_modules and build dirs
        cmd = [
            eslint,
            "--no-config-lookup",  # Problem #5 fix: ignore repo config
            "--config",
            str(config_path),
            "--format",
            "json",
            "--ext",
            ".js,.jsx,.mjs,.cjs,.ts,.tsx",
            "--ignore-pattern",
            "node_modules/",
            "--ignore-pattern",
            "dist/",
            "--ignore-pattern",
            "build/",
            "--ignore-pattern",
            "*.min.js",
            str(repo_path),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=ESLINT_TIMEOUT,
                check=False,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise ESLintScanError(
                f"ESLint scan timed out after {ESLINT_TIMEOUT}s."
            ) from exc
        except OSError as exc:
            raise ESLintScanError(f"Failed to run ESLint: {exc}") from exc

        # ESLint exits 0 (no issues), 1 (lint errors found), 2 (config/fatal error)
        if result.returncode == 2:
            stderr = (result.stderr or "").strip()
            raise ESLintScanError(f"ESLint config error: {stderr[:200]}")

        stdout = (result.stdout or "").strip()
        if not stdout:
            return []

        try:
            file_results = json.loads(stdout)
        except json.JSONDecodeError:
            return []

        # Flatten: one dict per message, with filePath attached
        for file_result in file_results or []:
            file_path = file_result.get("filePath", "")
            for msg in file_result.get("messages") or []:
                findings.append({**msg, "filePath": file_path})

    return findings
