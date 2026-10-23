# Registro de investigação — Laboratório Wazuh

Preencha este documento durante a demonstração. Ele é a parte que transforma alertas em análise de segurança.

## Identificação

| Campo | Registro |
|---|---|
| Data/hora (BRT) | |
| Analista | |
| Agente / hostname | |
| Sistema operacional | |
| Regra / severidade | |
| ID do alerta no Dashboard | |

## Caso 1 — Possível brute force

**Alerta esperado:** `100100` — múltiplas falhas de autenticação simuladas.

| Pergunta | Conclusão |
|---|---|
| Qual conta foi alvo? | |
| De qual origem vieram as tentativas? | |
| Quantas tentativas e em qual intervalo? | |
| Há login bem-sucedido posterior? | |
| Classificação | Simulação autorizada / falso positivo / incidente |
| Ação recomendada | |

**Conclusão modelo:** o padrão é compatível com tentativa automatizada de autenticação. Em um ambiente real, eu validaria sucesso posterior, bloquearia a origem conforme política e avaliaria MFA ou rate limiting.

## Caso 2 — Execução suspeita

**Alerta esperado:** `100101` — execução suspeita simulada.

| Pergunta | Conclusão |
|---|---|
| Usuário e endpoint envolvidos | |
| Processo/comando identificado | |
| O comando é esperado naquele ativo? | |
| Há alertas correlatos no mesmo período? | |
| Classificação | Simulação autorizada / falso positivo / incidente |
| Ação recomendada | |

## Caso 3 — Alteração de integridade

**Alerta esperado:** evento nativo de FIM para `/opt/wazuh-lab/monitorado/configuracao.conf`.

| Pergunta | Conclusão |
|---|---|
| Arquivo alterado | |
| Tipo de mudança (criado/modificado) | |
| Hash/atributo alterado, se disponível | |
| Mudança possui solicitação aprovada? | |
| Classificação | Simulação autorizada / mudança não autorizada |
| Ação recomendada | |

## Caso 4 — Possível exfiltração

**Alerta esperado:** `100102` — possível exfiltração simulada.

| Pergunta | Conclusão |
|---|---|
| Destino, protocolo e volume | |
| O destino é permitido? | |
| Quais dados poderiam estar envolvidos? | |
| Quais ativos/usuários correlacionar? | |
| Severidade e justificativa | |
| Ação imediata | |

**Conclusão modelo:** por envolver volume relevante e destino externo, a prioridade é alta. Em produção, eu preservaria evidências, restringiria a comunicação conforme playbook, verificaria escopo e acionaria resposta a incidentes.

## Linha do tempo

| Horário | Evidência | Interpretação | Próxima ação |
|---|---|---|---|
| | | | |
| | | | |
| | | | |

## Fechamento executivo

**Resumo em três linhas:**

> O Wazuh coletou eventos do endpoint e identificou tentativas de autenticação, execução suspeita, alteração de arquivo monitorado e possível transferência externa. A investigação usou severidade, ativo, usuário, origem e contexto do log para separar a simulação de um incidente real. As recomendações são reforçar autenticação, controlar privilégios, aprovar mudanças e investigar comunicações externas anômalas.
