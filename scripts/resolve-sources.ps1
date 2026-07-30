[CmdletBinding()]
param(
    [ValidateSet("Audit", "LicenseAudit", "LfsAudit", "SelectionAudit", "Resolve")]
    [string]$Command = "Audit",

    [string]$InputsPath = (Join-Path $PSScriptRoot "..\locks\source-inputs.v1.json"),
    [string]$LockPath = (Join-Path $PSScriptRoot "..\locks\sources.lock.json"),
    [string]$CacheDirectory = (Join-Path $PSScriptRoot "..\cache"),
    [string]$AuditReport = (Join-Path $PSScriptRoot "..\artifacts\source-input-audit.json"),
    [string]$LicenseAuditReport = (Join-Path $PSScriptRoot "..\artifacts\source-license-audit.json"),
    [string]$LfsAuditReport = (Join-Path $PSScriptRoot "..\artifacts\source-lfs-public-audit.json"),
    [string]$SelectionAuditReport = (Join-Path $PSScriptRoot "..\artifacts\source-selection-audit.json"),
    [string[]]$LfsRepository = @("build-tools-data"),
    [string]$SelfRoot = (Join-Path $PSScriptRoot "..")
)

$outputPath = switch ($Command) {
    "Audit" { $AuditReport }
    "LicenseAudit" { $LicenseAuditReport }
    "LfsAudit" { $LfsAuditReport }
    "SelectionAudit" { $SelectionAuditReport }
    "Resolve" { $LockPath }
}
if ($outputPath -and (Test-Path -LiteralPath $outputPath)) {
    try {
        $output = Get-Item -LiteralPath $outputPath -Force -ErrorAction Stop
        if ($output.PSIsContainer) {
            Write-Error "$outputPath`: previous output is not a file."
            exit 3
        }
        Remove-Item -LiteralPath $outputPath -Force -ErrorAction Stop
    }
    catch {
        Write-Error "$outputPath`: cannot remove previous output: $($_.Exception.Message)"
        exit 3
    }
}

$python = $null
$pythonCandidates = if ($IsWindows) { @("python", "python3") } else { @("python3", "python") }
foreach ($candidate in $pythonCandidates) {
    $pythonCommand = Get-Command $candidate -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        continue
    }
    & $pythonCommand.Source -c "import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)" 2>$null
    if ($LASTEXITCODE -eq 0) {
        $python = $pythonCommand.Source
        break
    }
}
if (-not $python) {
    Write-Error "Python 3 is required to resolve JetOnlyOffice sources."
    exit 2
}

$tool = Join-Path $PSScriptRoot "source_resolver.py"
$schemaDirectory = Join-Path $PSScriptRoot "..\schemas"
$arguments = @($tool)

switch ($Command) {
    "Audit" {
        $arguments += @("audit", "--inputs", $InputsPath, "--report", $AuditReport)
    }
    "LicenseAudit" {
        $arguments += @(
            "license-audit",
            "--inputs", $InputsPath,
            "--cache-directory", $CacheDirectory,
            "--report", $LicenseAuditReport,
            "--schema-dir", $schemaDirectory
        )
    }
    "LfsAudit" {
        $arguments += @(
            "lfs-audit",
            "--inputs", $InputsPath,
            "--cache-directory", $CacheDirectory,
            "--report", $LfsAuditReport,
            "--schema-dir", $schemaDirectory
        )
        foreach ($repository in ($LfsRepository | Sort-Object -Unique)) {
            $arguments += @("--repository", $repository)
        }
    }
    "SelectionAudit" {
        $arguments += @(
            "selection-audit",
            "--inputs", $InputsPath,
            "--cache-directory", $CacheDirectory,
            "--self-root", $SelfRoot,
            "--report", $SelectionAuditReport,
            "--schema-dir", $schemaDirectory
        )
    }
    "Resolve" {
        $arguments += @(
            "resolve",
            "--inputs", $InputsPath,
            "--cache-directory", $CacheDirectory,
            "--lock-output", $LockPath,
            "--self-root", $SelfRoot,
            "--schema-dir", $schemaDirectory
        )
    }
}

& $python @arguments
exit $LASTEXITCODE
