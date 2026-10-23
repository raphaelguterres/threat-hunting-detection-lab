Set-StrictMode -Version Latest
function Get-TransportReadiness {
    param([Parameter(Mandatory)]$Target, [string]$Phase = 'Health')
    $started = Get-Date
    $transport = [string]$Target.transport
    if ([string]::IsNullOrWhiteSpace($transport) -or $transport -eq 'unconfigured') {
        return [pscustomobject]@{
            target = $Target.id; phase = $Phase; started_at = $started.ToUniversalTime().ToString('o')
            duration = 0; status = 'BLOCKED'; exit_code = 0; evidence_path = ''
            message = 'Remote transport is not configured. No network or guest command was attempted.'
        }
    }
    return [pscustomobject]@{
        target = $Target.id; phase = $Phase; started_at = $started.ToUniversalTime().ToString('o')
        duration = 0; status = 'BLOCKED'; exit_code = 0; evidence_path = ''
        message = "Transport '$transport' is declared, but this safe host-only scaffold does not execute remote commands or handle credentials. Configure and validate it explicitly before extending the adapter."
    }
}

Export-ModuleMember -Function Get-TransportReadiness
