# Orquestrador dual-VM (host Windows)

Esta pasta implementa a Fase C: descoberta e saúde local das VMs no VirtualBox, com relatórios estruturados. Ela não abre rede, não instala software, não modifica convidados e não armazena senhas.

## Preparação

1. Copie `inventory.example.json` para `inventory.local.json`.
2. Preencha os valores depois de conferir cada VM por UUID com `VBoxManage list vms`. Use somente transportes já provisionados e aprovados; `unconfigured` é o padrão seguro.
3. Não versione o inventário local nem `automation/artifacts/`.

## Uso

```powershell
Set-Location 'C:\Users\rapha\Downloads\wazuh projeto'
.\automation\orchestrate.ps1 -Mode Discover
.\automation\orchestrate.ps1 -Mode Health
.\automation\orchestrate.ps1 -Mode Collect-Evidence
.\automation\orchestrate.ps1 -Mode Status
.\automation\orchestrate.ps1 -Mode Validate-Sysmon -WhatIf
```

`Health` consulta as VMs locais em paralelo quando o PowerShell oferece jobs. `Discover` vincula cada alvo pelo UUID. `Collect-Evidence` lê apenas propriedades publicadas pelo VirtualBox (por exemplo, Guest Additions e sessão informada), sem executar comandos no convidado. Cada execução produz JSON e um sumário Markdown em `automation/artifacts/`.

## Limite deliberado de transporte

SSH, WinRM e `guestcontrol` exigem autenticação e confiança prévias. Este scaffold não tenta conexão remota, não aceita fingerprints SSH automaticamente, não passa credenciais e não executa comandos nos convidados. Para `transport: unconfigured` — e também para qualquer transporte apenas declarado — `Validate-Sysmon` retorna **BLOCKED** com a causa. Isso evita declarar uma validação Sysmon sem evidência real.

Para ampliar o adaptador, mantenha a autenticação fora do repositório (SSH agent, Credential Manager ou mecanismo corporativo), valide fingerprints e implemente primeiro uma leitura inofensiva com timeout. Não habilite WinRM/SSH, crie regras de firewall, encaminhamentos de porta ou reinicie VMs por meio deste script.

## Interpretação e rollback

- `PASS`: a consulta local solicitada completou.
- `FAIL`: VirtualBox, inventário ou comando local falhou.
- `BLOCKED`: faltou um transporte remoto explicitamente configurado; nenhuma tentativa de rede foi feita.

Os únicos artefatos são arquivos locais em `automation/artifacts/`. Para reverter, remova esses artefatos locais; o orquestrador não muda estado de VM ou convidado. Antes de publicar evidências, revise e redija nomes, endereços e dados do laboratório.

## Smoke test

```powershell
$tokens = $null; $errors = $null
[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path .\automation\orchestrate.ps1), [ref]$tokens, [ref]$errors) | Out-Null
$errors
```

O resultado esperado é nenhuma linha de erro.
