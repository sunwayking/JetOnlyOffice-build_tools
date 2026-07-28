[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Validate", "ValidateEntrypoints", "Canonicalize", "Digest")]
    [string]$Command,

    [ValidateSet("source-lock", "toolchain-lock", "image-lock", "build-manifest", "artifact-manifest", "command-catalog", "corpus-manifest", "gate-result", "release-policy", "release-evidence", "gate-catalog")]
    [string]$Contract,

    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$Output,
    [string]$Sidecar,
    [string]$SchemaDirectory = (Join-Path $PSScriptRoot "..\schemas")
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
        $python = $pythonCommand
        break
    }
}
if (-not $python) {
    Write-Error "Python 3 is required to evaluate JetOnlyOffice contracts."
    exit 2
}

$tool = Join-Path $PSScriptRoot "contracts\contract_tool.py"
$arguments = @($tool)

switch ($Command) {
    "Validate" {
        if (-not $Contract) {
            Write-Error "-Contract is required for Validate."
            exit 2
        }
        $arguments += @("validate", "--contract", $Contract, "--schema-dir", $SchemaDirectory, $Path)
    }
    "ValidateEntrypoints" {
        $arguments += @("validate-entrypoints", $Path)
    }
    "Canonicalize" {
        $arguments += @("canonicalize", $Path)
        if ($Output) {
            $arguments += @("--output", $Output)
        }
    }
    "Digest" {
        $arguments += @("digest", $Path)
        if ($Sidecar) {
            $arguments += @("--sidecar", $Sidecar)
        }
    }
}

& $python.Source @arguments
exit $LASTEXITCODE
