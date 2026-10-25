# Caso 01 — Falhas repetidas de login simuladas

## Objetivo

Validar o alerta local `100100` e exercitar uma triagem de possível tentativa de força bruta sem realizar tentativas contra serviços reais.

## Evidência disponível

- Fonte: `/var/log/wazuh-lab/events.log` no agente Linux.
- Regra: `100100` — `LAB_BRUTE_FORCE`.
- Captura: `../evidencias/alerta-bruteforce-confirmado.png`.
- Telemetria nativa adicional: tentativa única com usuário inexistente no Kali gerou a regra `5710` (nível 5) no Manager.

## Linha do tempo de investigação

| Horário | Evidência | Interpretação | Próxima ação |
|---|---|---|---|
| 25/10/2026 | Regra 5710 para usuário inexistente no Kali | Tentativa nativa única, sem senha e sem repetição. | Não classificar como brute force isolado. |
| 25/10/2026 | Marcador `100100` indexado | Simulação autorizada do pipeline. | Registrar como marcador sintético. |

## Conclusão

O alerta confirma o pipeline agente → Manager → Indexer. Não deve ser relatado como incidente: o evento possui o marcador `LAB_BRUTE_FORCE` e foi gerado pelo simulador autorizado. Em uma detecção de produção, correlacionar logs nativos de autenticação, sucesso posterior e reputação/origem do endereço.
