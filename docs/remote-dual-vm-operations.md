# Operação remota do laboratório com duas VMs

## Topologia lógica

```text
Host Windows
  └─ VirtualBox
      ├─ WindowsServer (Sysmon + Wazuh Agent)
      ├─ Kali / Wazuh (manager e análise)
      └─ rede host-only isolada de administração
```

As duas VMs usam NAT, rede interna e uma terceira interface host-only isolada para administração pelo host. Não há port forwarding configurado e não deve ser criado para esta operação.

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
| WindowsServer | Online | WinRM HTTP responde, mas não há confiança/autenticação remota segura configurada | `BLOCKED` para comandos remotos |
| Kali / Wazuh | Online | SSH autenticado por chave de laboratório, com validação da chave do host | `AVAILABLE` para administração do Kali e do Manager em contêiner |

O SSH do Kali está restrito à rede host-only e usa chave de laboratório com validação de identidade do host. O WinRM HTTP do Windows responde, mas usar IP fora de domínio exigiria `TrustedHosts`, o que reduz as garantias de autenticação e não foi aplicado. OpenSSH no Windows e `VBoxManage guestcontrol` não foram habilitados nem presumidos. O orquestrador não cria port forwarding nem reduz garantias de autenticação.

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
