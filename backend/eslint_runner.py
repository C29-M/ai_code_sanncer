"""ESLint Security runner — supports v9/v10 flat config. Uses project-local eslint."""

from __future__ import annotations
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from exceptions import ScannerError

ESLINT_TIMEOUT = 120  # seconds


class ESLintScanError(ScannerError):
    def __init__(self, message: str = "ESLint scan failed.") -> None:
        super().__init__(message, status_code=500)


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


def _find_eslint_and_plugin(repo_path: Path):
    """Return (eslint_exe, node_modules_path) or raise ESLintScanError."""
    # On Windows, prefer .cmd files
    bin_names = (
        ("node_modules/.bin/eslint.cmd", "node_modules/.bin/eslint")
        if sys.platform == "win32"
        else ("node_modules/.bin/eslint", "node_modules/.bin/eslint.cmd")
    )

    # 1. Scanner project local (ai_code_sanncer/node_modules)
    scanner_root = Path(__file__).resolve().parent.parent
    for rel in bin_names:
        c = scanner_root / rel
        if c.exists():
            nm = scanner_root / "node_modules"
            if (nm / "eslint-plugin-security").exists():
                return str(c), nm

    # 2. Target repo local
    for rel in bin_names:
        c = repo_path / rel
        if c.exists():
            nm = repo_path / "node_modules"
            if (nm / "eslint-plugin-security").exists():
                return str(c), nm

    # 3. Global eslint + any known node_modules location for plugin
    candidate_nm_roots = [
        scanner_root / "node_modules",  # local dev
        Path("/usr/lib/node_modules"),  # Docker global npm (Linux)
        Path("/usr/local/lib/node_modules"),
    ]
    for name in (
        ("eslint.cmd", "eslint")
        if sys.platform == "win32"
        else ("eslint", "eslint.cmd")
    ):
        exe = shutil.which(name)
        if not exe:
            continue
        for nm in candidate_nm_roots:
            if (nm / "eslint-plugin-security").exists():
                return exe, nm

    raise ESLintScanError(
        "eslint-plugin-security not found. Run: npm install (in the ai_code_sanncer directory)"
    )


def _eslint_version(exe: str) -> int:
    try:
        r = subprocess.run(
            [exe, "--version"], capture_output=True, text=True, timeout=10, check=False
        )
        return int(r.stdout.strip().lstrip("v").split(".")[0])
    except Exception:
        return 9


def _write_flat_config(tmp_dir: str, node_modules: Path) -> str:
    plugin_path = str(node_modules / "eslint-plugin-security").replace("\\", "/")
    content = f"""const security = require({json.dumps(plugin_path)});
module.exports = [
  {{
    files: ["**/*.js","**/*.jsx","**/*.mjs","**/*.cjs","**/*.ts","**/*.tsx"],
    plugins: {{ security }},
    rules: {json.dumps(SECURITY_RULES, indent=4)},
    languageOptions: {{
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {{ require: "readonly", module: "readonly", process: "readonly", __dirname: "readonly" }},
    }},
  }},
];"""
    p = Path(tmp_dir) / "eslint.config.cjs"
    p.write_text(content, encoding="utf-8")
    return str(p)


def _write_legacy_config(tmp_dir: str) -> str:
    config = {
        "plugins": ["security"],
        "rules": SECURITY_RULES,
        "env": {"node": True, "browser": True, "es2021": True},
        "parserOptions": {"ecmaVersion": 2021, "sourceType": "module"},
    }
    p = Path(tmp_dir) / ".eslintrc.json"
    p.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return str(p)


def run_eslint_scan(repo_path: Path) -> list[dict]:
    if not repo_path.is_dir():
        raise ESLintScanError(f"Repository path does not exist: {repo_path}")

    eslint, node_modules = _find_eslint_and_plugin(repo_path)
    major = _eslint_version(eslint)
    is_v9_plus = major >= 9

    env = os.environ.copy()
    existing = env.get("NODE_PATH", "")
    env["NODE_PATH"] = (
        f"{node_modules}{os.pathsep}{existing}" if existing else str(node_modules)
    )

    findings: list[dict] = []
    with tempfile.TemporaryDirectory() as tmp_dir:
        if is_v9_plus:
            config_path = _write_flat_config(tmp_dir, node_modules)
            cmd = [
                eslint,
                "--no-config-lookup",
                "--config",
                config_path,
                "--format",
                "json",
                ".",
                "--ignore-pattern",
                "**/vendor/**",
                "--ignore-pattern",
                "**/*.min.js",
                "--ignore-pattern",
                "**/node_modules/**",
                "--ignore-pattern",
                "**/dist/**",
            ]
        else:
            config_path = _write_legacy_config(tmp_dir)
            cmd = [
                eslint,
                "--no-eslintrc",
                "--config",
                config_path,
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
                cwd=str(repo_path),
            )
        except subprocess.TimeoutExpired as exc:
            raise ESLintScanError(
                f"ESLint scan timed out after {ESLINT_TIMEOUT}s."
            ) from exc
        except OSError as exc:
            raise ESLintScanError(f"Failed to run ESLint: {exc}") from exc

        if result.returncode == 2:
            raise ESLintScanError(f"ESLint config error: {(result.stderr or '')[:300]}")

        stdout = (result.stdout or "").strip()
        if not stdout:
            return []

        try:
            file_results = json.loads(stdout)
        except json.JSONDecodeError:
            return []

        for fr in file_results or []:
            fp = fr.get("filePath", "")
            for msg in fr.get("messages") or []:
                findings.append({**msg, "filePath": fp})

    return findings
