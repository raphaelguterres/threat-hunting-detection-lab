# CASE-003 — PowerShell benigno

## Situação

**Estado:** execução local confirmada; ingestão no Wazuh pendente.

## Hipótese de investigação

PowerShell é ferramenta administrativa legítima. A triagem deve verificar usuário, processo-pai, linha de comando, horário e aprovação da atividade antes de associar o evento à técnica T1059.001.

## Evidência exigida

- Evento local PowerShell/Sysmon com comando inofensivo.
- Evento correspondente no Wazuh para o mesmo ativo e horário.
- Processo-pai e contexto administrativo redigidos.

## Linha do tempo

| Horário | Evento | Fonte | Observação |
| --- | --- | --- | --- |
| Pendente | Comando administrativo inofensivo | PowerShell Operational + Sysmon ID 1 | Depende da Issue #2 |

## Classificação e ação

Classificar como atividade administrativa autorizada quando o contexto coincidir. Caso contrário, preservar telemetria e aplicar o playbook de PowerShell.
