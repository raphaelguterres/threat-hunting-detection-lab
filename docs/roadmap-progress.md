# Painel de progresso do laboratório

Atualizado em 25/10/2026. Este painel consolida o estado confirmado do ambiente; não substitui os critérios de aceite definidos no [roadmap](../ROADMAP.md).

```text
[concluída] Base do laboratório
      -> [concluída] Telemetria e visibilidade
      -> [em execução] Engenharia de detecção
      -> [estruturada] Investigação
      -> [estruturada] Resposta segura
      -> [em preparação] Portfólio e publicação
```

| Fase | Estado | Situação verificável | Issue |
| --- | --- | --- | --- |
| 1. Base | Concluída | Arquitetura, inventário e limites documentados. | #1 fechada |
| 2. Telemetria | **Concluída** | Sysmon IDs 1 e 11 recebidos no Manager; FIM Linux validado no agente Kali nativo com controle negativo. | #2 e #3 fechadas |
| 3. Detecção | Em execução | FIM, login inválido, alteração de conta e conexão privada foram validados com telemetria nativa; PowerShell ainda depende de evidência própria no Windows. | #4 e #5 abertas |
| 4. Investigação | Estruturada | Casos e critérios de qualidade existem; linhas do tempo dependem da telemetria validada. | #6 aberta |
| 5. Resposta | Estruturada | Playbooks e governança de aprovação humana foram definidos. | #7 aberta |
| 6. Portfólio | Em preparação | README e documentação redigida estão em evolução; publicação depende das evidências das fases anteriores. | #8 aberta |

## Evidências confirmadas agora

- Windows Server e Kali/Wazuh estão em execução, conforme o health check local do VirtualBox.
- O serviço `Sysmon64` está em execução no Windows e a configuração foi aceita pelo Sysmon.
- O Manager registrou 36 alertas do canal Sysmon Windows, incluindo IDs 1 e 11, para o agente Windows ativo.
- O agente Kali nativo `kali-native-fim` foi registrado, teve FIM ativado em diretório do filesystem do convidado e gerou regras 554 (criação) e 550 (mudança de checksum).
- O controle FIM fora do escopo monitorado gerou zero alertas.
- Os quatro marcadores sintéticos `100100`–`100103` geraram exatamente quatro alertas no agente Kali nativo; uma linha de controle sem assinatura gerou zero alertas.
- As regras e arquivos de configuração versionados passam em `scripts/validate_lab_config.ps1`.
- A recarga autorizada do painel HTTPS privado pelo Edge gerou Sysmon ID 3 no agente Windows; a regra 100105 registrou processo e porta, e o controle ocioso não gerou novo alerta.

## Ponto atual e bloqueio real

O trabalho está na **Fase 3**, Issue #4. A conexão privada autorizada no Windows já foi validada. O Kali possui acesso SSH autenticado com validação de host; o Windows continua sem um canal de administração remota autenticado, e o projeto não reduz a segurança do WinRM com `TrustedHosts`. Essa limitação impede concluir apenas o cenário nativo de PowerShell até que sua evidência específica seja consultada no Manager.

## Próxima sequência ao disponibilizar acesso autenticado

1. Validar falha de login e alteração de conta com telemetria nativa e controles negativos seguros.
2. Gerar e correlacionar um PowerShell benigno no Windows.
3. Completar as consultas, linhas do tempo e justificativas de severidade dos cinco casos.
4. Registrar falsos positivos esperados e revisão MITRE antes de encerrar as Issues #4 e #5.

O roteiro detalhado dos dois cenários Windows pendentes está em [windows-pending-validation.md](windows-pending-validation.md).

Consulte também o [status operacional](STATUS_ATUAL_LAB.md), o [roteiro de validação do Sysmon](../tests/windows-sysmon-validation.md) e as [operações seguras entre as VMs](remote-dual-vm-operations.md).
