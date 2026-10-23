Set-StrictMode -Version Latest

function Get-UtcNowString { (Get-Date).ToUniversalTime().ToString('o') }

function Find-VBoxManage {
    param([string]$ConfiguredPath)
    $candidates = @($ConfiguredPath, (Get-Command VBoxManage.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source),
        'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe') | Where-Object { $_ }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return (Resolve-Path -LiteralPath $candidate).Path }
    }
    return $null
}

function New-Result {
    param([string]$Target, [string]$Phase, [string]$Status, [int]$ExitCode = 0, [string]$EvidencePath = '', [string]$Message = '', [datetime]$StartedAt = (Get-Date))
    [pscustomobject]@{
        target = $Target; phase = $Phase; started_at = $StartedAt.ToUniversalTime().ToString('o')
        duration = [math]::Round(((Get-Date) - $StartedAt).TotalSeconds, 3); status = $Status
        exit_code = $ExitCode; evidence_path = $EvidencePath; message = $Message
    }
}

function Write-JsonEvidence {
    param([object]$Data, [string]$Directory, [string]$Name)
    if (-not (Test-Path -LiteralPath $Directory)) { New-Item -ItemType Directory -Path $Directory -Force | Out-Null }
    $path = Join-Path $Directory ("{0}.json" -f $Name)
    $Data | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding utf8
    return $path
}

Export-ModuleMember -Function Get-UtcNowString,Find-VBoxManage,New-Result,Write-JsonEvidence
