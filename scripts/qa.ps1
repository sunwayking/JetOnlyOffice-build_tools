[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("aggregate", "bind-policy", "verify-corpus", "check-commands", "evaluate-performance")]
    [string]$Command,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
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
    Write-Error "Python 3 is required to evaluate JetOnlyOffice QA evidence."
    exit 2
}

$tool = Join-Path $PSScriptRoot "qa\qa_tool.py"
& $python.Source $tool $Command @Arguments
exit $LASTEXITCODE
