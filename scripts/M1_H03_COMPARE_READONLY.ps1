$ErrorActionPreference = 'Stop'
function Fingerprint([byte[]]$bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToBase64String($sha.ComputeHash($bytes)) } finally { $sha.Dispose() }
}
function Load-SafeXml([string]$text) {
    if ($text -match '(?i)<!DOCTYPE|<!ENTITY') { throw 'DtdNotAllowed' }
    $doc = New-Object Xml.XmlDocument
    $doc.PreserveWhitespace = $false
    $doc.XmlResolver = $null
    $doc.LoadXml($text)
    return ,$doc
}
function Collect-Fields($node,[string]$path,$result) {
    foreach ($attribute in $node.Attributes) { $result[$path + '/@' + $attribute.Name] = $attribute.Value }
    $elements = @($node.ChildNodes | Where-Object { $_.NodeType -eq 'Element' })
    if ($elements.Count -eq 0) { $result[$path] = $node.InnerText; return }
    $indexes = @{}
    foreach ($child in $elements) {
        if (-not $indexes.ContainsKey($child.Name)) { $indexes[$child.Name] = 0 }
        $indexes[$child.Name]++
        Collect-Fields $child ($path + '/' + $child.Name + '[' + $indexes[$child.Name] + ']') $result
    }
}
try {
    $stage = Join-Path $env:LOCALAPPDATA 'WazuhH03ChangeC-20261110'
    $oldFile = Join-Path $stage 'baseline.conf'
    $proposalFile = Join-Path $stage 'proposal.conf'
    $liveFile = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
    $oldBytes = [IO.File]::ReadAllBytes($oldFile)
    $liveBytes = [IO.File]::ReadAllBytes($liveFile)
    $proposalBytes = [IO.File]::ReadAllBytes($proposalFile)
    $oldText = [IO.File]::ReadAllText($oldFile)
    $liveText = [IO.File]::ReadAllText($liveFile)
    Write-Output ('BASELINE_BYTES=' + $oldBytes.Length)
    Write-Output ('CURRENT_BYTES=' + $liveBytes.Length)
    Write-Output ('CURRENT_EQUALS_BASELINE_BYTES=' + ((Fingerprint $liveBytes) -ceq (Fingerprint $oldBytes)))
    Write-Output ('CURRENT_EQUALS_PREPARED_PROPOSAL=' + ((Fingerprint $liveBytes) -ceq (Fingerprint $proposalBytes)))
    Write-Output ('TEXT_EQUAL_AFTER_BOM_DECODING=' + ($oldText -ceq $liveText))
    Write-Output ('TEXT_EQUAL_AFTER_NEWLINE_NORMALIZATION=' + (($oldText.Replace("`r`n","`n")) -ceq ($liveText.Replace("`r`n","`n"))))
    $oldXml = Load-SafeXml $oldText
    $liveXml = Load-SafeXml $liveText
    Write-Output ('XML_EQUAL_IGNORING_INDENTATION=' + ($oldXml.OuterXml -ceq $liveXml.OuterXml))
    $oldFields = @{}; $liveFields = @{}
    Collect-Fields $oldXml.DocumentElement '/ossec_config' $oldFields
    Collect-Fields $liveXml.DocumentElement '/ossec_config' $liveFields
    $changes = @()
    foreach ($key in @(@($oldFields.Keys) + @($liveFields.Keys) | Sort-Object -Unique)) {
        if (-not $oldFields.ContainsKey($key)) { $changes += ('ADDED_FIELD=' + $key) }
        elseif (-not $liveFields.ContainsKey($key)) { $changes += ('REMOVED_FIELD=' + $key) }
        elseif ($oldFields[$key] -cne $liveFields[$key]) { $changes += ('CHANGED_FIELD=' + $key) }
    }
    Write-Output ('CHANGED_FIELDS_COUNT=' + $changes.Count)
    $changes | Select-Object -First 35 | Write-Output
    $targets = @($liveXml.SelectNodes('/ossec_config/syscheck/directories') | Where-Object { $_.InnerText -ieq 'C:\SecurityLab\H03' })
    Write-Output ('CURRENT_H03_DIRECTIVES=' + $targets.Count)
    if ($targets.Count -eq 1) {
        Write-Output ('CURRENT_H03_REALTIME=' + $targets[0].GetAttribute('realtime'))
        Write-Output ('CURRENT_H03_CHECK_ALL=' + $targets[0].GetAttribute('check_all'))
    }
    Write-Output ('CURRENT_ACL_EQUALS_BASELINE=' + ((Get-Acl -LiteralPath $liveFile).Sddl -ceq [IO.File]::ReadAllText((Join-Path $stage 'baseline-acl.sddl'))))
    Write-Output ('WAZUH_SERVICE=' + (Get-Service WazuhSvc).Status)
    Write-Output 'VALUES_HASHES_CREDENTIALS=NOT_PRINTED'
    Write-Output 'ACTIVE_FILES_AND_SERVICES_MODIFIED=NO'
    exit 0
} catch {
    Write-Output ('COMPARISON_FAILED_TYPE=' + $_.Exception.GetType().Name)
    Write-Output ('ERROR_LINE=' + $_.InvocationInfo.ScriptLineNumber)
    exit 2
}
