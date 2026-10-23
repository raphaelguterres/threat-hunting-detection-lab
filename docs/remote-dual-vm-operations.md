# Operação remota do laboratório com duas VMs

## Topologia lógica

```text
Host Windows
  └─ VirtualBox
      ├─ WindowsServer (Sysmon + Wazuh Agent)
      └─ Kali / Wazuh (manager e análise)
```

As duas VMs usam uma combinação de NAT e rede interna. Não há port forwarding configurado e não deve ser criado para esta operação.

## Orquestrador host

O ponto de entrada é `automation/orchestrate.ps1`. Ele vincula os alvos por UUID do VirtualBox e nunca por um endereço DHCP presumido.

```powershell
Set-Location 'C:\Users\rapha\Downloads\wazuh projeto'
.\automation\orchestrate.ps1 -Mode Discover
.\automation\orchestrate.ps1 -Mode Health
.\automation\orchestrate.ps1 -Mode Collect-Evidence
.\automation\orchestrate.ps1 -Mode Validate-Sysmon -WhatIf
```

`Health` executa consultas locais independentes às duas VMs em paralelo. `Collect-Evidence` coleta apenas propriedades publicadas pelo VirtualBox. Os relatórios locais ficam em `automation/artifacts/`, que não é versionado até revisão e redação manual.

## Estado de acesso atual

| Alvo | Estado da VM | Canal remoto autenticado | Resultado operacional |
| --- | --- | --- | --- |
| WindowsServer | Online | Não confirmado | `BLOCKED` para comandos remotos |
| Kali / Wazuh | Online | Não confirmado | `BLOCKED` para comandos remotos |

O SSH do Kali não estava acessível pela rota testada. WinRM, OpenSSH no Windows e `VBoxManage guestcontrol` não foram habilitados nem presumidos. O orquestrador marca essa condição como `BLOCKED`; ele não cria serviços, regras de firewall, port forwarding nem usa credenciais.

## Fluxo seguro para Sysmon → Wazuh

1. `Health`: confirmar que ambas as VMs permanecem online.
2. No Windows, verificar o `ossec.conf` do agente e criar um backup antes de qualquer edição.
3. Inserir uma única vez o coletor do canal `Microsoft-Windows-Sysmon/Operational`.
4. Reiniciar apenas `WazuhSvc` se houve mudança e confirmar sua recuperação.
5. Gerar testes benignos identificáveis para Sysmon IDs 1 e 11.
6. Confirmar localmente no Windows e no Wazuh que os eventos possuem o mesmo marcador, horário e agente.
7. Repetir uma vez para estabilidade e só então fechar a Issue #2.

## Rollback

Antes de editar o `ossec.conf`, salvar uma cópia com timestamp no próprio Windows. Se `WazuhSvc` não recuperar após a alteração, restaurar essa cópia e reiniciar somente o serviço. O orquestrador não altera convidados e, portanto, não tem rollback de VM.

## Limites conhecidos

Clipboard configurado no VirtualBox não comprova que Guest Additions ou `guestcontrol` estejam funcionais. Não registrar credenciais, endereços privados, tokens ou logs integrais no repositório.
