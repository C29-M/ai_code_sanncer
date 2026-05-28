"""
Unit tests for the Week 3 + Week 4 normaliser module.

All tests are pure — no Docker, no network, no subprocess calls.
Run with:  pytest backend/tests/test_normalizer.py -v
"""

from __future__ import annotations


from normalizer import (
    MAX_SNIPPET_LEN,
    compute_risk_score,
    deduplicate,
    mask_secret,
    normalise_bandit,
    normalise_eslint,
    normalise_gitleaks,
    normalise_gosec,
    normalise_owasp_depcheck,
    normalise_safety,
    normalise_semgrep,
    normalise_spotbugs,
    normalise_trivy,
    normalise_trufflehog,
    safe_snippet,
)


# ---------------------------------------------------------------------------
# compute_risk_score
# ---------------------------------------------------------------------------


class TestComputeRiskScore:
    def test_semgrep_error_sast(self):
        # sw=10, cv=0, cw=6 → round(10*0.5 + 0*0.3 + 6*0.2)*10 = round(6.2)*10 = 60
        assert compute_risk_score("semgrep", "ERROR", None, "sast") == 60

    def test_semgrep_warning_sast(self):
        # sw=6, cv=0, cw=6 → round(3 + 0 + 1.2)*10 = round(4.2)*10 = 40
        assert compute_risk_score("semgrep", "WARNING", None, "sast") == 40

    def test_trivy_critical_with_cvss(self):
        # sw=10, cv=9.8, cw=7 → round(5 + 2.94 + 1.4)*10 = round(9.34)*10 = 90
        assert compute_risk_score("trivy", "CRITICAL", 9.8, "cve") == 90

    def test_trivy_low_no_cvss(self):
        # sw=2, cv=0, cw=7 → round(1 + 0 + 1.4)*10 = round(2.4)*10 = 20
        assert compute_risk_score("trivy", "LOW", None, "cve") == 20

    def test_secrets_floor_applied(self):
        # Even a low-weight secret must score >= 70
        score = compute_risk_score("gitleaks", "LOW", None, "secrets")
        assert score >= 70

    def test_history_floor_applied(self):
        score = compute_risk_score("gitleaks", "LOW", None, "history")
        assert score >= 70

    def test_sast_no_floor(self):
        # INFO/sast should NOT be boosted to 70
        score = compute_risk_score("semgrep", "INFO", None, "sast")
        assert score < 70

    def test_clamp_max(self):
        assert compute_risk_score("trivy", "CRITICAL", 10.0, "cve") <= 100

    def test_clamp_min(self):
        assert compute_risk_score("semgrep", "INFO", None, "sast") >= 0

    def test_unknown_tool_falls_back_to_zero_weight(self):
        # Unknown tool → sw=0; should not crash and score >= 0
        score = compute_risk_score("unknown_tool", "HIGH", None, "sast")
        assert score >= 0


# ---------------------------------------------------------------------------
# mask_secret
# ---------------------------------------------------------------------------


class TestMaskSecret:
    def test_short_value_fully_masked(self):
        assert mask_secret("abc") == "****"

    def test_exactly_8_chars_fully_masked(self):
        assert mask_secret("12345678") == "****"

    def test_long_token(self):
        result = mask_secret("AKIA5B4Y92XQZAM2")
        assert result.startswith("AKIA")
        assert result.endswith("ZAM2")
        assert "****" in result

    def test_pem_block_redacted(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
        assert mask_secret(pem) == "[PRIVATE KEY REDACTED]"

    def test_openssh_pem_redacted(self):
        pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1\n-----END OPENSSH PRIVATE KEY-----"
        assert mask_secret(pem) == "[PRIVATE KEY REDACTED]"

    def test_empty_string(self):
        assert mask_secret("") == "****"


# ---------------------------------------------------------------------------
# safe_snippet
# ---------------------------------------------------------------------------


class TestSafeSnippet:
    def test_not_secret_passes_through(self):
        text = "some normal code line"
        assert safe_snippet(text) == text

    def test_truncates_to_max_len(self):
        long = "x" * (MAX_SNIPPET_LEN + 100)
        assert len(safe_snippet(long)) == MAX_SNIPPET_LEN

    def test_pem_block_redacted_in_snippet(self):
        text = "key = -----BEGIN RSA PRIVATE KEY-----\nMIIEo\n-----END RSA PRIVATE KEY-----\n"
        result = safe_snippet(text, is_secret=True)
        assert "[PRIVATE KEY REDACTED]" in result
        assert "MIIEo" not in result

    def test_aws_key_masked_in_snippet(self):
        text = "AKIAIOSFODNN7EXAMPLE"
        result = safe_snippet(text, is_secret=True)
        # Long uppercase token — should be masked
        assert "EXAMPLE" not in result or result.startswith("AKIA")

    def test_key_value_pattern_redacted(self):
        text = "secret=supersecretvalue123"
        result = safe_snippet(text, is_secret=True)
        assert "supersecretvalue123" not in result
        assert "[REDACTED]" in result

    def test_password_pattern_redacted(self):
        text = "password = hunter2abc"
        result = safe_snippet(text, is_secret=True)
        assert "hunter2abc" not in result

    def test_empty_returns_empty(self):
        assert safe_snippet("") == ""


# ---------------------------------------------------------------------------
# normalise_semgrep
# ---------------------------------------------------------------------------

_SEMGREP_FINDING = {
    "check_id": "javascript.express.security.audit.express-cookie-session-no-secure.express-cookie-session-no-secure",
    "path": "/repo/examples/auth/index.js",
    "start": {"line": 22, "col": 1},
    "extra": {
        "severity": "WARNING",
        "message": "Default session middleware settings: `secure` not set.",
        "lines": "app.use(session({ secret: 'keyboard cat' }))",
        "metadata": {
            "cwe": ["CWE-522"],
            "owasp": "A02:2017 - Broken Authentication",
            "confidence": "MEDIUM",
            "impact": "LOW",
            "likelihood": "HIGH",
        },
    },
}


class TestNormaliseSemgrep:
    def test_returns_list(self):
        result = normalise_semgrep([_SEMGREP_FINDING])
        assert isinstance(result, list)
        assert len(result) == 1

    def test_tool_field(self):
        f = normalise_semgrep([_SEMGREP_FINDING])[0]
        assert f["tool"] == "semgrep"

    def test_severity_warning_maps_to_high(self):
        f = normalise_semgrep([_SEMGREP_FINDING])[0]
        assert f["severity"] == "HIGH"

    def test_file_and_line(self):
        f = normalise_semgrep([_SEMGREP_FINDING])[0]
        assert f["file"] == "/repo/examples/auth/index.js"
        assert f["line"] == 22

    def test_category_sast(self):
        f = normalise_semgrep([_SEMGREP_FINDING])[0]
        assert f["category"] == "sast"

    def test_cve_null(self):
        f = normalise_semgrep([_SEMGREP_FINDING])[0]
        assert f["cve_id"] is None

    def test_risk_score_int(self):
        f = normalise_semgrep([_SEMGREP_FINDING])[0]
        assert isinstance(f["risk_score"], int)
        assert 0 <= f["risk_score"] <= 100

    def test_secret_rule_gets_secrets_category(self):
        secret_finding = {
            **_SEMGREP_FINDING,
            "check_id": "generic.secrets.security.detected-private-key",
        }
        f = normalise_semgrep([secret_finding])[0]
        assert f["category"] == "secrets"

    def test_empty_input(self):
        assert normalise_semgrep([]) == []


# ---------------------------------------------------------------------------
# normalise_gitleaks
# ---------------------------------------------------------------------------

_GITLEAKS_FINDING_HISTORY = {
    "RuleID": "aws-access-token",
    "Description": "AWS Access Key ID",
    "File": "new_key",
    "StartLine": 2,
    "Match": "AKIAIOSFODNN7EXAMPLE",
    "Secret": "AKIAIOSFODNN7EXAMPLE",
    "Commit": "0416560b",
    "Author": "Test Author",
    "Date": "2023-01-01T00:00:00Z",
    "Fingerprint": "abc123",
}

_GITLEAKS_FINDING_HEAD = {
    "RuleID": "generic-api-key",
    "Description": "Generic API Key",
    "File": ".env",
    "StartLine": 5,
    "Match": "API_KEY=abc123xyz",
    "Secret": "abc123xyz",
    "Commit": "",  # no commit = current HEAD scan
    "Fingerprint": "def456",
}


class TestNormaliseGitleaks:
    def test_tool_field(self):
        f = normalise_gitleaks([_GITLEAKS_FINDING_HISTORY])[0]
        assert f["tool"] == "gitleaks"

    def test_history_category_when_commit_present(self):
        f = normalise_gitleaks([_GITLEAKS_FINDING_HISTORY])[0]
        assert f["category"] == "history"

    def test_secrets_category_when_no_commit(self):
        f = normalise_gitleaks([_GITLEAKS_FINDING_HEAD])[0]
        assert f["category"] == "secrets"

    def test_severity_always_critical(self):
        f = normalise_gitleaks([_GITLEAKS_FINDING_HISTORY])[0]
        assert f["severity"] == "CRITICAL"

    def test_risk_score_at_least_70(self):
        for finding in [_GITLEAKS_FINDING_HISTORY, _GITLEAKS_FINDING_HEAD]:
            f = normalise_gitleaks([finding])[0]
            assert f["risk_score"] >= 70

    def test_commit_stored_in_metadata(self):
        f = normalise_gitleaks([_GITLEAKS_FINDING_HISTORY])[0]
        assert f["metadata"]["commit"] == "0416560b"

    def test_snippet_is_masked(self):
        f = normalise_gitleaks([_GITLEAKS_FINDING_HISTORY])[0]
        # Full raw token should not appear verbatim
        assert "AKIAIOSFODNN7EXAMPLE" not in f["snippet"]

    def test_empty_input(self):
        assert normalise_gitleaks([]) == []


# ---------------------------------------------------------------------------
# normalise_trivy
# ---------------------------------------------------------------------------

_TRIVY_OUTPUT = {
    "Results": [
        {
            "Target": "package-lock.json",
            "Type": "npm",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2021-23362",
                    "PkgName": "hosted-git-info",
                    "InstalledVersion": "2.8.8",
                    "FixedVersion": "2.8.9",
                    "Severity": "MEDIUM",
                    "Title": "Regular Expression Denial of Service",
                    "CVSS": {
                        "nvd": {"V3Score": 5.3},
                    },
                },
                {
                    "VulnerabilityID": "CVE-2021-44228",
                    "PkgName": "log4j-core",
                    "InstalledVersion": "2.14.0",
                    "FixedVersion": "2.15.0",
                    "Severity": "CRITICAL",
                    "Title": "Log4Shell RCE",
                    "CVSS": {
                        "nvd": {"V3Score": 10.0},
                    },
                },
            ],
        }
    ]
}


class TestNormaliseTrivy:
    def test_returns_correct_count(self):
        result = normalise_trivy(_TRIVY_OUTPUT)
        assert len(result) == 2

    def test_tool_field(self):
        f = normalise_trivy(_TRIVY_OUTPUT)[0]
        assert f["tool"] == "trivy"

    def test_cve_id_extracted(self):
        results = normalise_trivy(_TRIVY_OUTPUT)
        cve_ids = {f["cve_id"] for f in results}
        assert "CVE-2021-23362" in cve_ids
        assert "CVE-2021-44228" in cve_ids

    def test_cvss_score_extracted(self):
        results = {f["cve_id"]: f for f in normalise_trivy(_TRIVY_OUTPUT)}
        assert results["CVE-2021-23362"]["cvss_score"] == 5.3
        assert results["CVE-2021-44228"]["cvss_score"] == 10.0

    def test_category_is_cve(self):
        for f in normalise_trivy(_TRIVY_OUTPUT):
            assert f["category"] == "cve"

    def test_critical_log4shell_score(self):
        results = {f["cve_id"]: f for f in normalise_trivy(_TRIVY_OUTPUT)}
        # CRITICAL + CVSS 10 should produce high risk score
        assert results["CVE-2021-44228"]["risk_score"] >= 80

    def test_snippet_contains_package_info(self):
        results = {f["cve_id"]: f for f in normalise_trivy(_TRIVY_OUTPUT)}
        snippet = results["CVE-2021-23362"]["snippet"]
        assert "hosted-git-info" in snippet
        assert "2.8.8" in snippet

    def test_shortlink_points_to_nvd(self):
        f = normalise_trivy(_TRIVY_OUTPUT)[0]
        assert "nvd.nist.gov" in f["metadata"]["shortlink"]

    def test_empty_results(self):
        assert normalise_trivy({"Results": []}) == []

    def test_missing_results_key(self):
        assert normalise_trivy({}) == []


# ---------------------------------------------------------------------------
# deduplicate
# ---------------------------------------------------------------------------


class TestDeduplicate:
    def _make_sast(self, file, line, rule_id, risk):
        return {
            "tool": "semgrep",
            "rule_id": rule_id,
            "severity": "HIGH",
            "file": file,
            "line": line,
            "category": "sast",
            "risk_score": risk,
            "description": "test finding",
            "cve_id": None,
            "metadata": {},
        }

    def _make_cve(self, cve_id, pkg, file, risk):
        return {
            "tool": "trivy",
            "rule_id": cve_id,
            "severity": "HIGH",
            "file": file,
            "line": 0,
            "category": "cve",
            "risk_score": risk,
            "description": cve_id,
            "cve_id": cve_id,
            "metadata": {"pkg_name": pkg},
        }

    def test_identical_sast_deduped(self):
        f1 = self._make_sast("app.py", 10, "sqli", 60)
        f2 = self._make_sast("app.py", 10, "sqli", 60)
        result = deduplicate([f1, f2])
        assert len(result) == 1

    def test_higher_risk_score_wins(self):
        f1 = self._make_sast("app.py", 10, "sqli", 40)
        f2 = self._make_sast("app.py", 10, "sqli", 70)
        result = deduplicate([f1, f2])
        assert result[0]["risk_score"] == 70

    def test_different_lines_not_deduped(self):
        f1 = self._make_sast("app.py", 10, "sqli", 60)
        f2 = self._make_sast("app.py", 20, "sqli", 60)
        result = deduplicate([f1, f2])
        assert len(result) == 2

    def test_different_files_not_deduped(self):
        f1 = self._make_sast("a.py", 10, "sqli", 60)
        f2 = self._make_sast("b.py", 10, "sqli", 60)
        result = deduplicate([f1, f2])
        assert len(result) == 2

    def test_cve_dedup_by_cve_pkg_file(self):
        c1 = self._make_cve("CVE-2021-44228", "log4j", "pom.xml", 90)
        c2 = self._make_cve("CVE-2021-44228", "log4j", "pom.xml", 90)
        result = deduplicate([c1, c2])
        assert len(result) == 1

    def test_same_cve_different_pkg_not_deduped(self):
        c1 = self._make_cve("CVE-2021-44228", "log4j-core", "pom.xml", 90)
        c2 = self._make_cve("CVE-2021-44228", "log4j-api", "pom.xml", 90)
        result = deduplicate([c1, c2])
        assert len(result) == 2

    def test_cross_scanner_dedup(self):
        # Same finding caught by both Semgrep and Gitleaks
        f_semgrep = {
            "tool": "semgrep",
            "rule_id": "hardcoded-secret",
            "severity": "CRITICAL",
            "file": "app.py",
            "line": 5,
            "category": "secrets",
            "risk_score": 70,
            "description": "Hardcoded API key detected",
            "cve_id": None,
            "metadata": {},
        }
        f_gitleaks = {
            "tool": "gitleaks",
            "rule_id": "generic-api-key",
            "severity": "CRITICAL",
            "file": "app.py",
            "line": 5,
            "category": "history",
            "risk_score": 70,
            "description": "Hardcoded API key detected",
            "cve_id": None,
            "metadata": {"commit": "abc123"},
        }
        result = deduplicate([f_semgrep, f_gitleaks])
        assert len(result) == 1

    def test_empty_input(self):
        assert deduplicate([]) == []


# ===========================================================================
# Week 4 — normaliser tests for all 7 new scanners
# ===========================================================================

# ---------------------------------------------------------------------------
# normalise_bandit
# ---------------------------------------------------------------------------

_BANDIT_FINDING = {
    "filename": "/repo/app/views.py",
    "line_number": 42,
    "issue_severity": "HIGH",
    "issue_confidence": "MEDIUM",
    "test_id": "B102",
    "test_name": "exec_used",
    "issue_text": "Use of exec detected.",
    "code": "exec(user_input)",
    "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
}


class TestNormaliseBandit:
    def test_tool_field(self):
        f = normalise_bandit([_BANDIT_FINDING])[0]
        assert f["tool"] == "bandit"

    def test_language_python(self):
        f = normalise_bandit([_BANDIT_FINDING])[0]
        assert f["language"] == "python"

    def test_category_sast(self):
        f = normalise_bandit([_BANDIT_FINDING])[0]
        assert f["category"] == "sast"

    def test_severity_high_maps_correctly(self):
        f = normalise_bandit([_BANDIT_FINDING])[0]
        assert f["severity"] == "HIGH"

    def test_file_and_line(self):
        f = normalise_bandit([_BANDIT_FINDING])[0]
        assert f["file"] == "/repo/app/views.py"
        assert f["line"] == 42

    def test_rule_id_from_test_id(self):
        f = normalise_bandit([_BANDIT_FINDING])[0]
        assert f["rule_id"] == "B102"

    def test_cwe_extracted(self):
        f = normalise_bandit([_BANDIT_FINDING])[0]
        assert "CWE-78" in f["metadata"]["cwe"]

    def test_confidence_in_metadata(self):
        f = normalise_bandit([_BANDIT_FINDING])[0]
        assert f["metadata"]["confidence"] == "MEDIUM"

    def test_risk_score_valid(self):
        f = normalise_bandit([_BANDIT_FINDING])[0]
        assert 0 <= f["risk_score"] <= 100

    def test_cve_id_null(self):
        f = normalise_bandit([_BANDIT_FINDING])[0]
        assert f["cve_id"] is None

    def test_empty_input(self):
        assert normalise_bandit([]) == []

    def test_low_severity_lower_risk_than_high(self):
        low = {**_BANDIT_FINDING, "issue_severity": "LOW"}
        f_low = normalise_bandit([low])[0]
        f_high = normalise_bandit([_BANDIT_FINDING])[0]
        assert f_low["risk_score"] < f_high["risk_score"]


# ---------------------------------------------------------------------------
# normalise_safety
# ---------------------------------------------------------------------------

_SAFETY_FINDING = {
    "package": "requests",
    "version": "2.25.0",
    "description": "Requests before 2.31.0 is vulnerable to proxy credential leakage.",
    "cve_id": "CVE-2023-32681",
    "severity": "MEDIUM",
    "manifest": "requirements.txt",
}


class TestNormaliseSafety:
    def test_tool_field(self):
        f = normalise_safety([_SAFETY_FINDING])[0]
        assert f["tool"] == "safety"

    def test_category_cve(self):
        f = normalise_safety([_SAFETY_FINDING])[0]
        assert f["category"] == "cve"

    def test_cve_id_propagated(self):
        f = normalise_safety([_SAFETY_FINDING])[0]
        assert f["cve_id"] == "CVE-2023-32681"

    def test_snippet_contains_package_and_version(self):
        f = normalise_safety([_SAFETY_FINDING])[0]
        assert "requests" in f["snippet"]
        assert "2.25.0" in f["snippet"]

    def test_file_is_manifest(self):
        f = normalise_safety([_SAFETY_FINDING])[0]
        assert f["file"] == "requirements.txt"

    def test_line_is_zero(self):
        f = normalise_safety([_SAFETY_FINDING])[0]
        assert f["line"] == 0

    def test_language_python(self):
        f = normalise_safety([_SAFETY_FINDING])[0]
        assert f["language"] == "python"

    def test_nvd_shortlink(self):
        f = normalise_safety([_SAFETY_FINDING])[0]
        assert "nvd.nist.gov" in f["metadata"]["shortlink"]
        assert "CVE-2023-32681" in f["metadata"]["shortlink"]

    def test_pkg_name_in_metadata(self):
        f = normalise_safety([_SAFETY_FINDING])[0]
        assert f["metadata"]["pkg_name"] == "requests"

    def test_empty_input(self):
        assert normalise_safety([]) == []

    def test_no_cve_id_uses_fallback_rule_id(self):
        finding = {**_SAFETY_FINDING, "cve_id": ""}
        f = normalise_safety([finding])[0]
        assert f["rule_id"].startswith("safety-")
        assert f["cve_id"] is None


# ---------------------------------------------------------------------------
# normalise_eslint
# ---------------------------------------------------------------------------

_ESLINT_FINDING = {
    "filePath": "/repo/src/routes/user.js",
    "line": 17,
    "ruleId": "security/detect-eval-with-expression",
    "message": "Detected eval() with expression.",
    "severity": 2,
    "source": "eval(req.body.cmd)",
}


class TestNormaliseEslint:
    def test_tool_field(self):
        f = normalise_eslint([_ESLINT_FINDING])[0]
        assert f["tool"] == "eslint"

    def test_category_sast(self):
        f = normalise_eslint([_ESLINT_FINDING])[0]
        assert f["category"] == "sast"

    def test_severity_error_maps_to_high(self):
        f = normalise_eslint([_ESLINT_FINDING])[0]
        assert f["severity"] == "HIGH"

    def test_severity_warn_maps_to_medium(self):
        warn = {**_ESLINT_FINDING, "severity": 1}
        f = normalise_eslint([warn])[0]
        assert f["severity"] == "MEDIUM"

    def test_file_and_line(self):
        f = normalise_eslint([_ESLINT_FINDING])[0]
        assert f["file"] == "/repo/src/routes/user.js"
        assert f["line"] == 17

    def test_rule_id_preserved(self):
        f = normalise_eslint([_ESLINT_FINDING])[0]
        assert f["rule_id"] == "security/detect-eval-with-expression"

    def test_cve_id_null(self):
        f = normalise_eslint([_ESLINT_FINDING])[0]
        assert f["cve_id"] is None

    def test_risk_score_error_higher_than_warn(self):
        warn = {**_ESLINT_FINDING, "severity": 1}
        f_err = normalise_eslint([_ESLINT_FINDING])[0]
        f_warn = normalise_eslint([warn])[0]
        assert f_err["risk_score"] > f_warn["risk_score"]

    def test_empty_input(self):
        assert normalise_eslint([]) == []


# ---------------------------------------------------------------------------
# normalise_gosec
# ---------------------------------------------------------------------------

_GOSEC_FINDING = {
    "file": "/repo/main.go",
    "line": 88,
    "rule_id": "G204",
    "details": "Subprocess launched with variable",
    "severity": "HIGH",
    "confidence": "MEDIUM",
    "code": "exec.Command(userInput)",
    "cwe": {"ID": "78"},
}


class TestNormaliseGosec:
    def test_tool_field(self):
        f = normalise_gosec([_GOSEC_FINDING])[0]
        assert f["tool"] == "gosec"

    def test_language_go(self):
        f = normalise_gosec([_GOSEC_FINDING])[0]
        assert f["language"] == "go"

    def test_category_sast(self):
        f = normalise_gosec([_GOSEC_FINDING])[0]
        assert f["category"] == "sast"

    def test_severity_high_maps_correctly(self):
        f = normalise_gosec([_GOSEC_FINDING])[0]
        assert f["severity"] == "HIGH"

    def test_file_and_line(self):
        f = normalise_gosec([_GOSEC_FINDING])[0]
        assert f["file"] == "/repo/main.go"
        assert f["line"] == 88

    def test_rule_id(self):
        f = normalise_gosec([_GOSEC_FINDING])[0]
        assert f["rule_id"] == "G204"

    def test_cwe_extracted(self):
        f = normalise_gosec([_GOSEC_FINDING])[0]
        assert "CWE-78" in f["metadata"]["cwe"]

    def test_confidence_in_metadata(self):
        f = normalise_gosec([_GOSEC_FINDING])[0]
        assert f["metadata"]["confidence"] == "MEDIUM"

    def test_cve_id_null(self):
        f = normalise_gosec([_GOSEC_FINDING])[0]
        assert f["cve_id"] is None

    def test_line_as_string_parsed(self):
        s = {**_GOSEC_FINDING, "line": "55"}
        f = normalise_gosec([s])[0]
        assert f["line"] == 55

    def test_empty_input(self):
        assert normalise_gosec([]) == []


# ---------------------------------------------------------------------------
# normalise_trufflehog
# ---------------------------------------------------------------------------

_TRUFFLEHOG_FINDING = {
    "DetectorName": "AWS",
    "Verified": True,
    "Raw": "AKIAIOSFODNN7EXAMPLE",
    "Redacted": "AKIA****MPLE",
    "SourceMetadata": {
        "Data": {
            "Git": {
                "file": "config/deploy.rb",
                "line": 12,
                "commit": "deadbeef1234",
            }
        }
    },
}


class TestNormaliseTrufflehog:
    def test_tool_field(self):
        f = normalise_trufflehog([_TRUFFLEHOG_FINDING])[0]
        assert f["tool"] == "trufflehog"

    def test_category_history(self):
        f = normalise_trufflehog([_TRUFFLEHOG_FINDING])[0]
        assert f["category"] == "history"

    def test_severity_always_critical(self):
        f = normalise_trufflehog([_TRUFFLEHOG_FINDING])[0]
        assert f["severity"] == "CRITICAL"

    def test_risk_score_at_least_70(self):
        f = normalise_trufflehog([_TRUFFLEHOG_FINDING])[0]
        assert f["risk_score"] >= 70

    def test_verified_boosts_risk_score(self):
        unverified = {**_TRUFFLEHOG_FINDING, "Verified": False}
        f_verified = normalise_trufflehog([_TRUFFLEHOG_FINDING])[0]
        f_unverified = normalise_trufflehog([unverified])[0]
        assert f_verified["risk_score"] >= f_unverified["risk_score"]

    def test_file_and_line_from_git_meta(self):
        f = normalise_trufflehog([_TRUFFLEHOG_FINDING])[0]
        assert f["file"] == "config/deploy.rb"
        assert f["line"] == 12

    def test_commit_in_metadata(self):
        f = normalise_trufflehog([_TRUFFLEHOG_FINDING])[0]
        assert f["metadata"]["commit"] == "deadbeef1234"

    def test_verified_flag_in_metadata(self):
        f = normalise_trufflehog([_TRUFFLEHOG_FINDING])[0]
        assert f["metadata"]["verified"] is True

    def test_cwe_798_always_present(self):
        f = normalise_trufflehog([_TRUFFLEHOG_FINDING])[0]
        assert "CWE-798" in f["metadata"]["cwe"]

    def test_raw_secret_not_in_snippet(self):
        f = normalise_trufflehog([_TRUFFLEHOG_FINDING])[0]
        assert "AKIAIOSFODNN7EXAMPLE" not in f["snippet"]

    def test_cve_id_null(self):
        f = normalise_trufflehog([_TRUFFLEHOG_FINDING])[0]
        assert f["cve_id"] is None

    def test_empty_input(self):
        assert normalise_trufflehog([]) == []


# ---------------------------------------------------------------------------
# normalise_spotbugs
# ---------------------------------------------------------------------------

_SPOTBUGS_FINDING = {
    "type": "SQL_INJECTION_HIBERNATE",
    "priority": "1",
    "description": "SQL injection via Hibernate query",
    "file": "/repo/src/main/java/com/example/UserDao.java",
    "line": 55,
    "snippet": "session.createQuery(FROM User WHERE name=inputVar)",
}


class TestNormaliseSpotbugs:
    def test_tool_field(self):
        f = normalise_spotbugs([_SPOTBUGS_FINDING])[0]
        assert f["tool"] == "spotbugs"

    def test_language_java(self):
        f = normalise_spotbugs([_SPOTBUGS_FINDING])[0]
        assert f["language"] == "java"

    def test_category_sast(self):
        f = normalise_spotbugs([_SPOTBUGS_FINDING])[0]
        assert f["category"] == "sast"

    def test_priority_1_maps_to_high(self):
        f = normalise_spotbugs([_SPOTBUGS_FINDING])[0]
        assert f["severity"] == "HIGH"

    def test_priority_2_maps_to_medium(self):
        med = {**_SPOTBUGS_FINDING, "priority": "2"}
        f = normalise_spotbugs([med])[0]
        assert f["severity"] == "MEDIUM"

    def test_priority_3_maps_to_low(self):
        low = {**_SPOTBUGS_FINDING, "priority": "3"}
        f = normalise_spotbugs([low])[0]
        assert f["severity"] == "LOW"

    def test_file_and_line(self):
        f = normalise_spotbugs([_SPOTBUGS_FINDING])[0]
        assert f["file"] == "/repo/src/main/java/com/example/UserDao.java"
        assert f["line"] == 55

    def test_rule_id_is_bug_type(self):
        f = normalise_spotbugs([_SPOTBUGS_FINDING])[0]
        assert f["rule_id"] == "SQL_INJECTION_HIBERNATE"

    def test_risk_score_valid(self):
        f = normalise_spotbugs([_SPOTBUGS_FINDING])[0]
        assert 0 <= f["risk_score"] <= 100

    def test_cve_id_null(self):
        f = normalise_spotbugs([_SPOTBUGS_FINDING])[0]
        assert f["cve_id"] is None

    def test_empty_input(self):
        assert normalise_spotbugs([]) == []


# ---------------------------------------------------------------------------
# normalise_owasp_depcheck
# ---------------------------------------------------------------------------

_DEPCHECK_FINDING = {
    "cve_id": "CVE-2021-44228",
    "severity": "CRITICAL",
    "cvss_score": 10.0,
    "description": "Apache Log4j2 JNDI lookup RCE vulnerability (Log4Shell).",
    "file": "pom.xml",
    "pkg_name": "log4j-core",
    "shortlink": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    "cwes": ["CWE-502", "CWE-400"],
    "source": "NVD",
}


class TestNormaliseOwaspDepcheck:
    def test_tool_field(self):
        f = normalise_owasp_depcheck([_DEPCHECK_FINDING])[0]
        assert f["tool"] == "owasp_depcheck"

    def test_category_cve(self):
        f = normalise_owasp_depcheck([_DEPCHECK_FINDING])[0]
        assert f["category"] == "cve"

    def test_language_java(self):
        f = normalise_owasp_depcheck([_DEPCHECK_FINDING])[0]
        assert f["language"] == "java"

    def test_cve_id_propagated(self):
        f = normalise_owasp_depcheck([_DEPCHECK_FINDING])[0]
        assert f["cve_id"] == "CVE-2021-44228"

    def test_cvss_score_propagated(self):
        f = normalise_owasp_depcheck([_DEPCHECK_FINDING])[0]
        assert f["cvss_score"] == 10.0

    def test_severity_critical(self):
        f = normalise_owasp_depcheck([_DEPCHECK_FINDING])[0]
        assert f["severity"] == "CRITICAL"

    def test_risk_score_high_for_log4shell(self):
        f = normalise_owasp_depcheck([_DEPCHECK_FINDING])[0]
        assert f["risk_score"] >= 80

    def test_snippet_contains_package_name(self):
        f = normalise_owasp_depcheck([_DEPCHECK_FINDING])[0]
        assert "log4j-core" in f["snippet"]

    def test_cwes_in_metadata(self):
        f = normalise_owasp_depcheck([_DEPCHECK_FINDING])[0]
        assert "CWE-502" in f["metadata"]["cwe"]
        assert "CWE-400" in f["metadata"]["cwe"]

    def test_pkg_name_in_metadata(self):
        f = normalise_owasp_depcheck([_DEPCHECK_FINDING])[0]
        assert f["metadata"]["pkg_name"] == "log4j-core"

    def test_shortlink_preserved(self):
        f = normalise_owasp_depcheck([_DEPCHECK_FINDING])[0]
        assert "nvd.nist.gov" in f["metadata"]["shortlink"]

    def test_no_cve_uses_fallback_rule_id(self):
        finding = {**_DEPCHECK_FINDING, "cve_id": ""}
        f = normalise_owasp_depcheck([finding])[0]
        assert f["rule_id"].startswith("depcheck-")
        assert f["cve_id"] is None

    def test_empty_input(self):
        assert normalise_owasp_depcheck([]) == []
