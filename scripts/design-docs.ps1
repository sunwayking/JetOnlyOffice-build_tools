[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Generate", "Verify")]
    [string]$Command,

    [string]$Root = (Join-Path $PSScriptRoot ".."),
    [string]$Manifest
)

if (-not $Manifest) {
    $Manifest = Join-Path $Root "manifests\authoritative-design-docs.v1.json"
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
        $python = $pythonCommand
        break
    }
}
if (-not $python) {
    Write-Error "Python 3 is required to manage JetOnlyOffice design-document manifests."
    exit 2
}

$tool = Join-Path $PSScriptRoot "design_docs\design_docs_manifest.py"
& $python.Source $tool $Command.ToLowerInvariant() --root $Root --manifest $Manifest
exit $LASTEXITCODE
