# Caso 03 — PowerShell benigno no Windows

## Estado

A coleta foi configurada e a regra `100106` está implantada no Manager. Falta confirmar a execução controlada com o marcador benigno `WAZUH-LAB-PS` e contexto suficiente para investigação.

## Hipótese

PowerShell não é suspeito por si só. A triagem deve distinguir administração legítima de execução fora do padrão por usuário, comando, processo-pai, horário e ativo.

## Dados a registrar

| Campo | Valor |
|---|---|
| Data/hora | Preencher na execução |
| Endpoint e usuário | Preencher na execução |
| Comando benigno | `Write-Output WAZUH-LAB-PS` |
| Evento/canal recebido | Sysmon ID 1; regra 100106 após a execução |
| Processo-pai, se disponível | Requer Sysmon ou telemetria equivalente |
| Conclusão | Simulação autorizada / requer investigação |

## Critério de conclusão

O caso estará concluído quando o evento for visível no Wazuh com imagem, linha de comando, usuário e processo-pai. Execuções internas do agente Wazuh não substituem o teste controlado.
