# Caso 03 — PowerShell benigno no Windows

## Estado

Validado em 25/10/2026. O comando controlado com o marcador benigno `WAZUH-LAB-PS` foi recebido no Manager pela regra nativa 92027, com contexto suficiente para investigação.

## Hipótese

PowerShell não é suspeito por si só. A triagem deve distinguir administração legítima de execução fora do padrão por usuário, comando, processo-pai, horário e ativo.

## Dados a registrar

| Campo | Valor |
|---|---|
| Data/hora | Preencher na execução |
| Endpoint e usuário | Preencher na execução |
| Comando benigno | `Write-Output WAZUH-LAB-PS` |
| Evento/canal recebido | Sysmon ID 1; regra nativa 92027 |
| Processo-pai, se disponível | Requer Sysmon ou telemetria equivalente |
| Conclusão | Simulação autorizada / requer investigação |

## Critério de conclusão

O caso foi concluído com imagem, linha de comando, usuário e processo-pai. Execuções internas do agente Wazuh que não continham o marcador foram observadas como contexto distinto e não substituíram o teste controlado.
