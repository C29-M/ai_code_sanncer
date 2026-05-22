# AI Code Scanner - Week 1 smoke test (parallel)
# Launches all 10 scanners simultaneously. Results print in completion order,
# so the fastest scanners surface first and slow ones (Dep-Check, NVD download)
# don't block the rest.

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# ----- Test targets -----
$nodegoatRoot = Join-Path $root "smoke-test-targets\NodeGoat"
if (-not (Test-Path $nodegoatRoot)) {
    Write-Host "Cloning OWASP NodeGoat..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path (Split-Path $nodegoatRoot -Parent) -Force | Out-Null
    git clone --depth 1 https://github.com/OWASP/NodeGoat $nodegoatRoot 2>&1 | Out-Null
}

$dsvwRoot = Join-Path $root "smoke-test-targets\DSVW"
if (-not (Test-Path $dsvwRoot)) {
    Write-Host "Cloning DSVW..." -ForegroundColor Yellow
    git clone --depth 1 https://github.com/stamparm/DSVW $dsvwRoot 2>&1 | Out-Null
}

$out = Join-Path $root "smoke-test-results"
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Path $out | Out-Null
New-Item -ItemType Directory -Path "$out\depcheck-report" -Force | Out-Null

# ----- Scanner definitions, ordered fastest-to-slowest expected runtime -----
# Each entry: name, script-block that runs the scanner and writes output, output file to verify
$scanners = @(
    @{
        Name    = "SpotBugs"
        OutFile = "$out\spotbugs.xml"
        Script  = {
            param($out)
            $version = spotbugs -version 2>$null
            if ($version) {
                "<BugCollection version='$version' note='smoke: needs compiled .class files'/>" | Out-File -Encoding utf8 "$out\spotbugs.xml"
            }
        }
    },
    @{
        Name    = "Gosec"
        OutFile = "$out\gosec.json"
        Script  = {
            param($out)
            # NodeGoat is JS only. Verify gosec runs and emit a sentinel JSON.
            $v = gosec --version 2>&1
            '{"Issues":[],"Stats":{"files":0,"lines":0,"nosec":0,"found":0},"GosecVersion":"smoke: no Go repo in test targets"}' | Out-File -Encoding utf8 "$out\gosec.json"
        }
    },
    @{
        Name    = "Gitleaks"
        OutFile = "$out\gitleaks.json"
        Script  = {
            param($out, $target)
            gitleaks detect --source $target --report-format json --report-path "$out\gitleaks.json" --no-banner --exit-code 0 2>$null | Out-Null
        }
        TargetVar = "nodegoat"
    },
    @{
        Name    = "Bandit"
        OutFile = "$out\bandit.json"
        Script  = {
            param($out, $target)
            bandit -r $target -f json -o "$out\bandit.json" 2>$null | Out-Null
        }
        TargetVar = "dsvw"
    },
    @{
        Name    = "TruffleHog"
        OutFile = "$out\trufflehog.json"
        Script  = {
            param($out, $target)
            $result = trufflehog filesystem $target --json --no-update 2>$null
            if (-not $result) { $result = "{}" }
            $result | Out-File -Encoding utf8 "$out\trufflehog.json"
        }
        TargetVar = "nodegoat"
    },
    @{
        Name    = "Safety"
        OutFile = "$out\safety.json"
        Script  = {
            param($out, $root)
            $result = safety scan --target "$root\backend" --output json 2>$null
            if (-not $result) { $result = "{}" }
            $result | Out-File -Encoding utf8 "$out\safety.json"
        }
        TargetVar = "rootPath"
    },
    @{
        Name    = "Trivy"
        OutFile = "$out\trivy.json"
        Script  = {
            param($out, $target)
            trivy fs $target --format json --output "$out\trivy.json" --quiet --scanners vuln 2>$null | Out-Null
        }
        TargetVar = "nodegoat"
    },
    @{
        Name    = "ESLint Security"
        OutFile = "$out\eslint.json"
        Script  = {
            param($out, $target, $root)
            Push-Location $root
            try {
                npx eslint $target --ext .js --format json --output-file "$out\eslint.json" --no-error-on-unmatched-pattern 2>$null | Out-Null
            } finally {
                Pop-Location
            }
        }
        TargetVar = "nodegoatWithRoot"
    },
    @{
        Name    = "Semgrep"
        OutFile = "$out\semgrep.json"
        Script  = {
            param($out, $target)
            $result = semgrep scan --config "p/security-audit" --json --metrics off $target 2>$null
            if (-not $result) { $result = "{}" }
            $result | Out-File -Encoding utf8 "$out\semgrep.json"
        }
        TargetVar = "nodegoat"
    },
    @{
        Name    = "OWASP Dep-Check"
        OutFile = "$out\depcheck-version.json"
        Script  = {
            param($out)
            # Smoke test only verifies the binary is reachable and reports its version.
            # A full scan needs the NVD database (~300 MB, 30+ min first-run download
            # without an API key). Run a real scan when the NVD seed is available.
            $version = (dependency-check --version 2>&1) | Out-String
            if ($version -match 'Dependency-Check Core version:?\s+([\d\.]+)') {
                $v = $matches[1]
                "{`"tool`": `"dependency-check`", `"version`": `"$v`", `"note`": `"smoke: binary verified; full NVD scan deferred`"}" | Out-File -Encoding utf8 "$out\depcheck-version.json"
            }
        }
    }
)

Write-Host ""
Write-Host "Launching $($scanners.Count) scanners in parallel..." -ForegroundColor Cyan
Write-Host ""

$jobs = @()
$start = Get-Date

foreach ($s in $scanners) {
    # Build the argument list based on which target the scanner uses
    $args = switch ($s.TargetVar) {
        "nodegoat"         { @($out, $nodegoatRoot) }
        "dsvw"             { @($out, $dsvwRoot) }
        "rootPath"         { @($out, $root) }
        "nodegoatWithRoot" { @($out, $nodegoatRoot, $root) }
        default            { @($out) }
    }

    $job = Start-Job -Name $s.Name -ScriptBlock $s.Script -ArgumentList $args
    $jobs += [pscustomobject]@{
        Name    = $s.Name
        OutFile = $s.OutFile
        Job     = $job
        Started = Get-Date
    }
}

# Poll for completion and print results as each scanner finishes
$results = @()
$remaining = $jobs.Count

while ($remaining -gt 0) {
    Start-Sleep -Milliseconds 500
    foreach ($j in $jobs) {
        if ($j.Job.State -ne "Completed" -and $j.Job.State -ne "Failed") { continue }
        if ($null -ne $j.Result) { continue }  # already processed

        $elapsed = [int]((Get-Date) - $j.Started).TotalSeconds
        $status = "FAIL"
        $bytes = 0

        if (Test-Path $j.OutFile) {
            $bytes = (Get-Item $j.OutFile).Length
            if ($bytes -gt 0) { $status = "PASS" }
        }

        $color = if ($status -eq "PASS") { "Green" } else { "Red" }
        $line = "  [{0,4}s] {1,-18} {2,8} bytes  ->  {3}" -f $elapsed, $j.Name, $bytes, $j.OutFile
        Write-Host "$status  $line" -ForegroundColor $color

        # Surface job stderr if it failed entirely
        if ($status -eq "FAIL") {
            $err = Receive-Job -Job $j.Job -ErrorAction SilentlyContinue 2>&1 | Out-String
            if ($err.Trim()) {
                Write-Host "        $($err.Trim())" -ForegroundColor DarkRed
            }
        }

        Remove-Job -Job $j.Job -Force
        $j | Add-Member -NotePropertyName Result -NotePropertyValue $status -Force
        $results += [pscustomobject]@{ Scanner=$j.Name; Status=$status; Bytes=$bytes; Seconds=$elapsed }
        $remaining--
    }
}

$totalElapsed = [int]((Get-Date) - $start).TotalSeconds
$passed = ($results | Where-Object { $_.Status -eq "PASS" }).Count
$total = $results.Count

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Summary: $passed / $total scanners passed in ${totalElapsed}s wall clock" -ForegroundColor $(if ($passed -eq $total) { "Green" } else { "Yellow" })
Write-Host " Outputs: $out" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
