# Caso 01 — Falhas repetidas de login simuladas

## Objetivo

Validar o alerta local `100100` e exercitar uma triagem de possível tentativa de força bruta sem realizar tentativas contra serviços reais.

## Evidência disponível

- Fonte: `/var/log/wazuh-lab/events.log` no agente Linux.
- Regra: `100100` — `LAB_BRUTE_FORCE`.
- Captura: `../evidencias/alerta-bruteforce-confirmado.png`.

## Linha do tempo de investigação

| Horário | Evidência | Interpretação | Próxima ação |
|---|---|---|---|
| Preencher na execução | Alerta `100100` indexado | Marcador de simulação autorizado recebido. | Conferir `full_log` e agente. |
| Preencher na execução | Usuário, origem e janela de tempo | Dados declarados pelo simulador, não por uma autenticação real. | Registrar como simulação. |

## Conclusão

O alerta confirma o pipeline agente → Manager → Indexer. Não deve ser relatado como incidente: o evento possui o marcador `LAB_BRUTE_FORCE` e foi gerado pelo simulador autorizado. Em uma detecção de produção, correlacionar logs nativos de autenticação, sucesso posterior e reputação/origem do endereço.
