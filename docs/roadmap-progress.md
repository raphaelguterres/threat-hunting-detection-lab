# Painel de progresso do laboratório

Atualizado em 25/10/2026. Este painel consolida o estado confirmado do ambiente; não substitui os critérios de aceite definidos no [roadmap](../ROADMAP.md).

```text
[concluída] Base do laboratório
      -> [concluída] Telemetria e visibilidade
      -> [em execução] Engenharia de detecção
      -> [concluída] Investigação
      -> [concluída] Resposta segura
      -> [em preparação] Portfólio e publicação
```

| Fase | Estado | Situação verificável | Issue |
| --- | --- | --- | --- |
| 1. Base | Concluída | Arquitetura, inventário e limites documentados. | #1 fechada |
| 2. Telemetria | **Concluída** | Sysmon IDs 1 e 11 recebidos no Manager; FIM Linux validado no agente Kali nativo com controle negativo. | #2 e #3 fechadas |
| 3. Detecção | Concluída | Os cinco casos possuem evidência apropriada; PowerShell e conexão privada foram validados no Windows, e os demais no Kali. | #4 pronta para encerramento; #5 fechada |
| 4. Investigação | Concluída | Cinco linhas do tempo redigidas respondem evento, ativo, evidência, classificação e ação recomendada. | #6 pronta para encerramento |
| 5. Resposta | Concluída | Playbooks de autenticação, PowerShell, FIM e rede exigem preservação de evidências, aprovação humana e rollback. | #7 pronta para encerramento |
| 6. Portfólio | Em preparação | README, diagrama textual e documentação foram saneados; falta selecionar capturas redigidas para publicação externa. | #8 aberta |

## Evidências confirmadas agora

- Windows Server e Kali/Wazuh estão em execução, conforme o health check local do VirtualBox.
- O serviço `Sysmon64` está em execução no Windows e a configuração foi aceita pelo Sysmon.
- O Manager registrou 36 alertas do canal Sysmon Windows, incluindo IDs 1 e 11, para o agente Windows ativo.
- O agente Kali nativo `kali-native-fim` foi registrado, teve FIM ativado em diretório do filesystem do convidado e gerou regras 554 (criação) e 550 (mudança de checksum).
- O controle FIM fora do escopo monitorado gerou zero alertas.
- Os quatro marcadores sintéticos `100100`–`100103` geraram exatamente quatro alertas no agente Kali nativo; uma linha de controle sem assinatura gerou zero alertas.
- As regras e arquivos de configuração versionados passam em `scripts/validate_lab_config.ps1`.
- A recarga autorizada do painel HTTPS privado pelo Edge gerou Sysmon ID 3 no agente Windows; a regra 100105 registrou processo e porta, e o controle ocioso não gerou novo alerta.
- O processo PowerShell filho com marcador benigno gerou Sysmon ID 1 e foi recebido pela regra nativa 92027 com comando, usuário e processo-pai.

## Ponto atual e bloqueio real

O trabalho de detecção da **Fase 3** foi concluído em termos técnicos. O Kali possui acesso SSH autenticado com validação de host; o Windows continua sem um canal de administração remota autenticado, mas isso não impede a evidência já recebida pelo Manager. A Issue #4 está pronta para encerramento após revisão humana do repositório.

## Próxima sequência ao disponibilizar acesso autenticado

1. Iniciar a Fase 4 com investigações e linhas do tempo para as evidências validadas.
2. Revisar a severidade e os falsos positivos antes de cada publicação de case study.
3. Encerrar a Issue #4 após revisão humana do repositório.

O roteiro detalhado dos dois cenários Windows pendentes está em [windows-pending-validation.md](windows-pending-validation.md).

Consulte também o [status operacional](STATUS_ATUAL_LAB.md), o [roteiro de validação do Sysmon](../tests/windows-sysmon-validation.md) e as [operações seguras entre as VMs](remote-dual-vm-operations.md).

As linhas do tempo de investigação estão em [case-study-timelines.md](case-study-timelines.md).
