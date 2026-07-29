[CmdletBinding()]
param(
    [string]$SourceLockPath = (Join-Path $PSScriptRoot "..\locks\sources.lock.json"),
    [string]$ArtifactManifestPath = (Join-Path $PSScriptRoot "..\artifacts\artifact-manifest.json"),
    [string]$ReferenceArtifactManifestPath = (Join-Path $PSScriptRoot "..\artifacts-reference\artifact-manifest.json"),
    [string]$ArtifactDirectory = (Join-Path $PSScriptRoot "..\artifacts"),
    [string]$ReferenceArtifactDirectory,
    [string]$ReleasePolicyPath = (Join-Path $PSScriptRoot "..\artifacts\release-policy.json"),
    [string]$GateResultDirectory = (Join-Path $PSScriptRoot "..\artifacts\gate-results"),
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot ".."),
    [string]$RunId = "verify-local",
    [string]$Image,
    [string]$OutputPath = (Join-Path $PSScriptRoot "..\artifacts\release-evidence.json")
)

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
    Write-Error "Python 3 is required to verify the locked JetOnlyOffice release."
    exit 2
}

$tool = Join-Path $PSScriptRoot "offline_baseline.py"
if (-not $ReferenceArtifactDirectory) {
    $ReferenceArtifactDirectory = Split-Path -Parent $ReferenceArtifactManifestPath
}
$arguments = @(
    $tool,
    "verify",
    "--artifact-manifest", $ArtifactManifestPath,
    "--reference-artifact-manifest", $ReferenceArtifactManifestPath,
    "--source-lock", $SourceLockPath,
    "--artifact-directory", $ArtifactDirectory,
    "--reference-artifact-directory", $ReferenceArtifactDirectory,
    "--release-policy", $ReleasePolicyPath,
    "--gate-result-directory", $GateResultDirectory,
    "--repository-root", $RepositoryRoot,
    "--run-id", $RunId,
    "--schema-dir", (Join-Path $PSScriptRoot "..\schemas"),
    "--output", $OutputPath
)
if ($Image) {
    $arguments += @("--image", $Image)
}
& $python @arguments
exit $LASTEXITCODE
