# Caso 03 — PowerShell benigno no Windows

## Estado

A execução de teste e a coleta do canal `Microsoft-Windows-PowerShell/Operational` foram configuradas. Falta confirmar no Manager um evento com contexto suficiente para investigação.

## Hipótese

PowerShell não é suspeito por si só. A triagem deve distinguir administração legítima de execução fora do padrão por usuário, comando, processo-pai, horário e ativo.

## Dados a registrar

| Campo | Valor |
|---|---|
| Data/hora | Preencher na execução |
| Endpoint e usuário | Preencher na execução |
| Comando benigno | Preencher na execução |
| Evento/canal recebido | Preencher na execução |
| Processo-pai, se disponível | Requer Sysmon ou telemetria equivalente |
| Conclusão | Simulação autorizada / requer investigação |

## Critério de conclusão

O caso estará concluído quando o evento for visível no Wazuh e uma consulta reproduzível permitir localizar a execução no Dashboard ou índice.
