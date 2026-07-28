[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Serial,

    [Parameter(Mandatory = $true)]
    [string]$Output,

    [string]$AdbPath = "adb",
    [string]$ExpectedModel,
    [switch]$RequireChrome,
    [string]$ApkSignerPath,
    [switch]$RequireSignatures
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "device-facts.psm1") -Force

function Invoke-Adb {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    $result = & $AdbPath -s $Serial @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "adb failed: $($result -join [Environment]::NewLine)"
    }
    return ($result -join "`n").Trim()
}

function Get-Sha256Text {
    param([Parameter(Mandatory = $true)][string]$Value)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $digest = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return [Convert]::ToHexString($digest).ToLowerInvariant()
}

function Get-PackageFacts {
    param([Parameter(Mandatory = $true)][string]$Package)
    $dump = Invoke-Adb shell dumpsys package $Package
    $version = [regex]::Match($dump, '(?m)^\s*versionName=(\S+)').Groups[1].Value
    $certificate = $null
    if ($version -and $ApkSignerPath) {
        $remotePath = (Invoke-Adb shell pm path $Package).Split("`n") |
            Where-Object { $_ -like "package:*" } |
            Select-Object -First 1
        if ($remotePath) {
            $temporaryApk = [System.IO.Path]::GetTempFileName()
            try {
                $pullResult = & $AdbPath -s $Serial pull $remotePath.Substring(8) $temporaryApk 2>&1
                if ($LASTEXITCODE -ne 0) {
                    throw "adb pull failed: $($pullResult -join [Environment]::NewLine)"
                }
                $signerOutput = & $ApkSignerPath verify --print-certs $temporaryApk 2>&1
                if ($LASTEXITCODE -ne 0) {
                    throw "apksigner failed: $($signerOutput -join [Environment]::NewLine)"
                }
                $certificate = Get-ApkSignerCertificateSha256 -SignerOutput $signerOutput
            }
            finally {
                Remove-Item -LiteralPath $temporaryApk -Force -ErrorAction SilentlyContinue
            }
        }
    }
    if ($RequireSignatures -and $version -and -not $certificate) {
        throw "Signing certificate for '$Package' was not captured; record INFRA_INCOMPLETE."
    }
    return [ordered]@{
        package = $Package
        version = if ($version) { $version } else { $null }
        signingCertificateSha256 = $certificate
    }
}

$state = (& $AdbPath -s $Serial get-state 2>$null).Trim()
if ($LASTEXITCODE -ne 0 -or $state -ne "device") {
    throw "Android device '$Serial' is unavailable; record INFRA_INCOMPLETE."
}

$model = Invoke-Adb shell getprop ro.product.model
$device = Invoke-Adb shell getprop ro.product.device
$apiLevel = [int](Invoke-Adb shell getprop ro.build.version.sdk)
$androidVersion = Invoke-Adb shell getprop ro.build.version.release
$fingerprint = Invoke-Adb shell getprop ro.build.fingerprint
$abi = Invoke-Adb shell getprop ro.product.cpu.abi
$memoryLine = Invoke-Adb shell cat /proc/meminfo | Select-String -Pattern '^MemTotal:' | Select-Object -First 1
$memoryKiB = [int64]([regex]::Match($memoryLine.Line, '\d+').Value)

if ($ExpectedModel -and $model -ne $ExpectedModel) {
    throw "Device model '$model' does not match expected '$ExpectedModel'; record INFRA_INCOMPLETE."
}

$chrome = Get-PackageFacts -Package "com.android.chrome"
if ($RequireChrome -and -not $chrome.version) {
    throw "Official Chrome Stable is not installed; record INFRA_INCOMPLETE."
}

$webViewDump = Invoke-Adb shell dumpsys webviewupdate
$webViewMatch = [regex]::Match(
    $webViewDump,
    'Current WebView package \(name, version\): \(([^,]+),\s*([^\)]+)\)'
)
if (-not $webViewMatch.Success) {
    throw "Current System WebView could not be resolved; record INFRA_INCOMPLETE."
}

$facts = [ordered]@{
    schemaVersion = 1
    serialSha256 = Get-Sha256Text -Value $Serial
    model = $model
    device = $device
    apiLevel = $apiLevel
    androidVersion = $androidVersion
    buildFingerprint = $fingerprint
    abi = $abi
    memoryKiB = $memoryKiB
    chrome = $chrome
    systemWebView = [ordered]@{
        package = $webViewMatch.Groups[1].Value
        version = $webViewMatch.Groups[2].Value
        signingCertificateSha256 = (Get-PackageFacts -Package $webViewMatch.Groups[1].Value).signingCertificateSha256
    }
}

$outputPath = [System.IO.Path]::GetFullPath($Output)
$outputDirectory = [System.IO.Path]::GetDirectoryName($outputPath)
if ($outputDirectory) {
    [System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
}
$json = $facts | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($outputPath, $json + "`n", [System.Text.UTF8Encoding]::new($false))
