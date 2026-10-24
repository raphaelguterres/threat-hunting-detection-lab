# Painel de progresso do laboratório

Atualizado em 24/10/2026. Este painel consolida o estado confirmado do ambiente; não substitui os critérios de aceite definidos no [roadmap](../ROADMAP.md).

```text
[concluída] Base do laboratório
      -> [em execução] Telemetria e visibilidade
      -> [preparada] Engenharia de detecção
      -> [estruturada] Investigação
      -> [estruturada] Resposta segura
      -> [em preparação] Portfólio e publicação
```

| Fase | Estado | Situação verificável | Issue |
| --- | --- | --- | --- |
| 1. Base | Concluída | Arquitetura, inventário e limites documentados. | #1 fechada |
| 2. Telemetria | **Em execução** | VMs ativas; Sysmon instalado e executando no Windows; FIM Windows para Wazuh observado. Falta confirmar eventos Sysmon no Wazuh e validar FIM no endpoint Linux. | #2 e #3 abertas |
| 3. Detecção | Preparada, sem validação ponta a ponta | Regras, matriz MITRE e casos documentados; ainda faltam evidências positiva e negativa para encerrar os casos. | #4 e #5 abertas |
| 4. Investigação | Estruturada | Casos e critérios de qualidade existem; linhas do tempo dependem da telemetria validada. | #6 aberta |
| 5. Resposta | Estruturada | Playbooks e governança de aprovação humana foram definidos. | #7 aberta |
| 6. Portfólio | Em preparação | README e documentação redigida estão em evolução; publicação depende das evidências das fases anteriores. | #8 aberta |

## Evidências confirmadas agora

- Windows Server e Kali/Wazuh estão em execução, conforme o health check local do VirtualBox.
- O serviço `Sysmon64` está em execução no Windows e a configuração foi aceita pelo Sysmon.
- Um evento de integridade de arquivo do Windows chegou ao Wazuh (`syscheck_integrity_changed`).
- As regras e arquivos de configuração versionados passam em `scripts/validate_lab_config.ps1`.

## Ponto atual e bloqueio real

O trabalho está no fechamento da **Fase 2**, especificamente na Issue #2. A rede de gerenciamento isolada entre host e VMs está disponível, mas não há uma sessão remota autenticada de forma segura para alterar ou verificar o agente Wazuh nas VMs. O projeto deliberadamente não reduz a segurança do WinRM com `TrustedHosts` nem expõe SSH sem autenticação.

## Próxima sequência ao disponibilizar acesso autenticado

1. Inspecionar e preservar uma cópia da configuração atual do agente Windows.
2. Confirmar ou aplicar o coletor de `Microsoft-Windows-Sysmon/Operational` e reiniciar apenas `WazuhSvc` se houver alteração.
3. Gerar eventos benignos e identificáveis do Sysmon (IDs 1 e 11).
4. Confirmar a chegada ao Wazuh, anexar a evidência redigida e encerrar a Issue #2; então validar o FIM Linux da Issue #3.

Consulte também o [status operacional](STATUS_ATUAL_LAB.md), o [roteiro de validação do Sysmon](../tests/windows-sysmon-validation.md) e as [operações seguras entre as VMs](remote-dual-vm-operations.md).
