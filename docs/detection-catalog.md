# Catálogo de detecções

Este catálogo separa o que foi validado do que é apenas mapeamento planejado. Os quatro alertas Linux abaixo são marcadores sintéticos autorizados; eles treinam o fluxo de detecção e investigação, mas não constituem prova de uma técnica ATT&CK executada.

| ID / caso | Fonte | Nível | Validação | Falso positivo esperado | Hipótese de triagem | ATT&CK planejado |
|---|---|---:|---|---|---|---|
| `100100` — falhas repetidas de login | Log de laboratório Linux | 10 | Pipeline sintético validado | Marcador `LAB_*` autorizado | Avaliar volume, origem e eventual login posterior. | T1110 — hipótese |
| `100101` — comando suspeito | Log de laboratório Linux | 9 | Pipeline sintético validado | Marcador `LAB_*` autorizado | Confirmar usuário, processo e legitimidade do comando. | T1059 — hipótese |
| `100102` — possível exfiltração | Log de laboratório Linux | 12 | Pipeline sintético validado | Marcador `LAB_*` autorizado | Confirmar destino, volume, protocolo e classificação dos dados. | T1041 — hipótese |
| `100103` — elevação de privilégio | Log de laboratório Linux | 11 | Pipeline sintético validado | Marcador `LAB_*` autorizado | Validar solicitação aprovada, usuário e contexto. | T1548 — hipótese |
| `100104` — alteração de conta | Auditd no Kali | 8 | Positivo e negativo validados | Criação ou remoção aprovada de conta de serviço | Confirmar ator, comando, conta e aprovação da mudança. | T1098 — hipótese |
| FIM Linux nativo | Wazuh FIM | 5 / 7 | Positivo e negativo validados | Mudança aprovada no diretório monitorado | Confirmar caminho, hashes antes/depois, processo de mudança e aprovação. | Sem mapeamento automático |
| Alteração de arquivo monitorado | FIM Windows | Nativo | Validado | Mudança aprovada no caminho monitorado | Identificar arquivo, hashes antes/depois, usuário e mudança aprovada. | Sem mapeamento automático |
| `100105` — conexão HTTPS do Edge | Sysmon ID 3 / Windows | 3 | Positivo e negativo validados | Navegação autorizada do Edge para serviço interno HTTPS | Confirmar processo, destino aprovado, porta, horário e contexto da navegação. | Técnica definida após contexto |
| PowerShell de laboratório | Sysmon ID 1 / Windows | 4 | Positivo e controle de contexto validados pela regra 92027 | Administração aprovada em janela de manutenção | Confirmar comando, usuário, processo-pai e alertas correlatos. | T1059.001 — hipótese |

## Critério de qualidade para novas detecções

Cada nova regra deve ter: fonte de telemetria validada, condição de disparo, evidência positiva, teste negativo, hipótese investigativa, severidade justificada, mapeamento ATT&CK quando aplicável e tratamento de falsos positivos.
