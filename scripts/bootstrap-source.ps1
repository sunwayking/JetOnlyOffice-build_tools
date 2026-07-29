[CmdletBinding()]
param(
    [ValidateSet("Bootstrap", "Verify")]
    [string]$Command = "Bootstrap",

    [string]$LockPath = (Join-Path $PSScriptRoot "..\locks\sources.lock.json"),
    [string]$ToolchainLockPath = (Join-Path $PSScriptRoot "..\locks\toolchain.lock.json"),
    [string]$ImageLockPath = (Join-Path $PSScriptRoot "..\locks\images.lock.json"),
    [string]$CacheDirectory = (Join-Path $PSScriptRoot "..\cache"),
    [string]$SourceDirectory = (Join-Path $PSScriptRoot "..\workspace"),
    [string]$BootstrapManifestPath = (Join-Path $PSScriptRoot "..\cache\bootstrap-manifest.json"),
    [string]$DockerExecutable = "docker"
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
    Write-Error "Python 3 is required to resolve JetOnlyOffice sources."
    exit 2
}

$tool = Join-Path $PSScriptRoot "source_resolver.py"
$schemaDirectory = Join-Path $PSScriptRoot "..\schemas"
$arguments = @($tool)

if ($Command -eq "Bootstrap") {
    $baselineTool = Join-Path $PSScriptRoot "offline_baseline.py"
    & $python $baselineTool preflight-bootstrap `
        --source-lock $LockPath `
        --toolchain-lock $ToolchainLockPath `
        --image-lock $ImageLockPath `
        --schema-dir $schemaDirectory
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

switch ($Command) {
    "Bootstrap" {
        $arguments += @(
            "bootstrap",
            "--lock", $LockPath,
            "--cache-directory", $CacheDirectory,
            "--source-directory", $SourceDirectory,
            "--schema-dir", $schemaDirectory
        )
    }
    "Verify" {
        $arguments += @(
            "verify",
            "--lock", $LockPath,
            "--source-directory", $SourceDirectory,
            "--schema-dir", $schemaDirectory
        )
    }
}

& $python @arguments
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

if ($Command -eq "Bootstrap") {
    $baselineTool = Join-Path $PSScriptRoot "offline_baseline.py"
    & $python $baselineTool bootstrap `
        --source-lock $LockPath `
        --toolchain-lock $ToolchainLockPath `
        --image-lock $ImageLockPath `
        --cache-directory $CacheDirectory `
        --docker $DockerExecutable `
        --schema-dir $schemaDirectory `
        --output $BootstrapManifestPath
    exit $LASTEXITCODE
}

exit 0
