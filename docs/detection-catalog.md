# Catálogo de detecções

Este catálogo separa o que foi validado do que é apenas mapeamento planejado. Os quatro alertas Linux abaixo são marcadores sintéticos autorizados; eles treinam o fluxo de detecção e investigação, mas não constituem prova de uma técnica ATT&CK executada.

| ID / caso | Fonte | Nível | Estado | Hipótese de triagem | ATT&CK planejado |
|---|---|---:|---|---|---|
| `100100` — falhas repetidas de login | Log de laboratório Linux | 10 | Validado | Avaliar volume, origem e eventual login posterior. | T1110 — Brute Force |
| `100101` — comando suspeito | Log de laboratório Linux | 9 | Validado | Confirmar usuário, processo e legitimidade do comando. | T1059 — Command and Scripting Interpreter |
| `100102` — possível exfiltração | Log de laboratório Linux | 12 | Validado | Confirmar destino, volume, protocolo e classificação dos dados. | T1041 — Exfiltration Over C2 Channel, se aplicável |
| `100103` — elevação de privilégio | Log de laboratório Linux | 11 | Validado | Validar solicitação aprovada, usuário e contexto. | T1548 — Abuse Elevation Control |
| Alteração de arquivo monitorado | FIM Windows | Nativo | Validado | Identificar arquivo, hashes antes/depois, usuário e mudança aprovada. | Sem mapeamento automático; depende do contexto da alteração |
| PowerShell de laboratório | PowerShell Operational / Windows | A validar no Manager | Execução local confirmada | Validar comando, usuário, processo-pai e alertas correlatos. | T1059.001 — PowerShell |

## Critério de qualidade para novas detecções

Cada nova regra deve ter: fonte de telemetria validada, condição de disparo, evidência positiva, teste negativo, hipótese investigativa, severidade justificada, mapeamento ATT&CK quando aplicável e tratamento de falsos positivos.
