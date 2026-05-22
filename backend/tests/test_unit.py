"""
Fast unit tests that do not need Docker or a network. These run in every CI
job and verify the validation, language-detection, and exception layers.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from exceptions import InvalidRepoUrlError, RepoTooLargeError, ScannerError
from language_detection import detect_languages, select_rule_paths
from repo_cloner import _measure_repo_size, validate_git_url


# ---------- URL validation ----------


class TestValidateGitUrl:
    def test_accepts_github(self):
        assert validate_git_url("https://github.com/OWASP/NodeGoat") == (
            "https://github.com/OWASP/NodeGoat"
        )

    def test_accepts_gitlab(self):
        assert validate_git_url("https://gitlab.com/owner/repo") == (
            "https://gitlab.com/owner/repo"
        )

    def test_accepts_bitbucket(self):
        assert validate_git_url("https://bitbucket.org/owner/repo") == (
            "https://bitbucket.org/owner/repo"
        )

    def test_strips_dot_git_suffix(self):
        assert validate_git_url("https://github.com/OWASP/NodeGoat.git") == (
            "https://github.com/OWASP/NodeGoat"
        )

    def test_rejects_http(self):
        with pytest.raises(InvalidRepoUrlError):
            validate_git_url("http://github.com/OWASP/NodeGoat")

    def test_rejects_unknown_host(self):
        with pytest.raises(InvalidRepoUrlError):
            validate_git_url("https://evil.example.com/owner/repo")

    def test_rejects_non_repo_path(self):
        # Only one path segment
        with pytest.raises(InvalidRepoUrlError):
            validate_git_url("https://github.com/OWASP")

    def test_rejects_too_many_segments(self):
        with pytest.raises(InvalidRepoUrlError):
            validate_git_url("https://github.com/owner/repo/blob/main/file.py")


# ---------- Repo size measurement ----------


class TestMeasureRepoSize:
    def test_empty_dir_is_zero(self, tmp_path: Path):
        assert _measure_repo_size(tmp_path) == 0

    def test_single_file(self, tmp_path: Path):
        (tmp_path / "f.txt").write_bytes(b"x" * 1234)
        assert _measure_repo_size(tmp_path) == 1234

    def test_recursive(self, tmp_path: Path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        (tmp_path / "a.txt").write_bytes(b"a" * 100)
        (sub / "b.txt").write_bytes(b"b" * 200)
        assert _measure_repo_size(tmp_path) == 300


# ---------- Language detection ----------


class TestLanguageDetection:
    def test_python_dominant(self, tmp_path: Path):
        for i in range(5):
            (tmp_path / f"m{i}.py").write_text("x = 1\n")
        counts = detect_languages(tmp_path)
        assert counts == {"python": 5}

    def test_mixed_languages(self, tmp_path: Path):
        for i in range(3):
            (tmp_path / f"a{i}.py").write_text("x = 1\n")
        for i in range(3):
            (tmp_path / f"b{i}.js").write_text("var x = 1;\n")
        counts = detect_languages(tmp_path)
        assert counts == {"python": 3, "javascript": 3}

    def test_skips_node_modules(self, tmp_path: Path):
        nm = tmp_path / "node_modules" / "junk"
        nm.mkdir(parents=True)
        (nm / "x.js").write_text("var x = 1;\n")
        (tmp_path / "real.py").write_text("x = 1\n")
        counts = detect_languages(tmp_path)
        assert counts == {"python": 1}

    def test_skips_minified(self, tmp_path: Path):
        (tmp_path / "bundle.min.js").write_text("var a;")
        (tmp_path / "real.js").write_text("var b;")
        (tmp_path / "other.js").write_text("var c;")
        counts = detect_languages(tmp_path)
        assert counts == {"javascript": 2}

    def test_unknown_repo_falls_back_to_full_pack(self, tmp_path: Path):
        # No recognised source files at all
        (tmp_path / "README.md").write_text("hello")
        paths = select_rule_paths(tmp_path)
        assert paths == ["/opt/semgrep-rules"]

    def test_routes_to_python_path(self, tmp_path: Path):
        for i in range(5):
            (tmp_path / f"x{i}.py").write_text("x = 1\n")
        paths = select_rule_paths(tmp_path)
        assert "/opt/semgrep-rules/python" in paths


# ---------- Exception hierarchy ----------


class TestExceptions:
    def test_invalid_url_is_scanner_error(self):
        assert issubclass(InvalidRepoUrlError, ScannerError)

    def test_too_large_is_scanner_error(self):
        assert issubclass(RepoTooLargeError, ScannerError)

    def test_invalid_url_status_code(self):
        try:
            raise InvalidRepoUrlError("bad url")
        except InvalidRepoUrlError as e:
            assert e.status_code == 400

    def test_too_large_status_code(self):
        try:
            raise RepoTooLargeError("too big")
        except RepoTooLargeError as e:
            assert e.status_code == 413
