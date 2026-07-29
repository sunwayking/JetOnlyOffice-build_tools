[CmdletBinding()]
param(
    [ValidateSet("linux-amd64")]
    [string]$Platform = "linux-amd64",

    [string]$BootstrapManifestPath,
    [string]$SourceLockPath = (Join-Path $PSScriptRoot "..\locks\sources.lock.json"),
    [string]$ToolchainLockPath = (Join-Path $PSScriptRoot "..\locks\toolchain.lock.json"),
    [string]$ImageLockPath = (Join-Path $PSScriptRoot "..\locks\images.lock.json"),
    [string]$BuildManifestPath = (Join-Path $PSScriptRoot "..\artifacts\build-manifest.json"),
    [string]$CacheDirectory = (Join-Path $PSScriptRoot "..\cache"),
    [string]$ArtifactDirectory = (Join-Path $PSScriptRoot "..\artifacts"),
    [string]$DockerExecutable = "docker",
    [string]$OutputPath
)

if (-not $BootstrapManifestPath) {
    $BootstrapManifestPath = Join-Path $CacheDirectory "bootstrap-manifest.json"
}
if (-not $OutputPath) {
    $OutputPath = Join-Path $ArtifactDirectory "artifact-manifest.json"
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
    Write-Error "Python 3 is required to package the locked JetOnlyOffice build."
    exit 2
}

$tool = Join-Path $PSScriptRoot "offline_baseline.py"
& $python $tool package `
    --build-manifest $BuildManifestPath `
    --bootstrap-manifest $BootstrapManifestPath `
    --source-lock $SourceLockPath `
    --toolchain-lock $ToolchainLockPath `
    --image-lock $ImageLockPath `
    --cache-directory $CacheDirectory `
    --artifact-directory $ArtifactDirectory `
    --docker $DockerExecutable `
    --schema-dir (Join-Path $PSScriptRoot "..\schemas") `
    --output $OutputPath
exit $LASTEXITCODE
