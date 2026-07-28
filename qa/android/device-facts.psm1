function Get-ApkSignerCertificateSha256 {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [string[]]$SignerOutput
    )

    $text = $SignerOutput -join "`n"
    $match = [regex]::Match(
        $text,
        '(?m)^(?:(?:V\d+(?:\.\d+)?)\s+Signer:\s+|Signer #\d+\s+)' +
            'certificate SHA-256 digest:\s*([0-9a-fA-F]{64})\s*$'
    )
    if (-not $match.Success) {
        return $null
    }
    return $match.Groups[1].Value.ToLowerInvariant()
}

Export-ModuleMember -Function Get-ApkSignerCertificateSha256
