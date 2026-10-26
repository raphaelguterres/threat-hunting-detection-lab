# Cobertura MITRE ATT&CK

Esta matriz descreve hipóteses de detecção do laboratório, não uma alegação de que cada técnica foi executada. A coluna de evidência evita que marcadores sintéticos sejam apresentados como telemetria nativa.

| Cenário | Técnica ATT&CK | Fonte pretendida | Tipo de evidência | Status ATT&CK | Próxima validação |
|---|---|---|---|---|---|
| Falhas repetidas de login | [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) | Eventos nativos de autenticação Windows/Linux | Marcador sintético `100100` | Não reivindicado como cobertura | Gerar falhas controladas em conta de teste e correlacionar com sucesso posterior. |
| Alteração de conta | [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/) quando aplicável | Auditoria de conta Windows/Linux | Planejado | Hipótese | Criar e remover conta de teste e confirmar evento nativo. |
| PowerShell benigno | [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) | Sysmon ID 1 | Comando benigno controlado recebido pela regra 92027, com usuário e processo-pai | Hipótese | A telemetria foi validada; não inferir intenção maliciosa a partir de PowerShell isolado. |
| Alteração de arquivo | Sem mapeamento automático | Wazuh FIM + Sysmon ID 11 | FIM Windows e Kali nativo validados | Não aplicável; alteração não prova intenção | Correlacionar arquivo, processo e mudança aprovada. |
| Conexão de rede inesperada | Técnica definida após contexto | Sysmon ID 3 | Conexão HTTPS autorizada do Edge validada; regra 100105 | Hipótese | Usar processo, destino aprovado e janela temporal; não mapear automaticamente uma navegação a ATT&CK. |
| Execução de comando | [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) | Sysmon ID 1 / logs do endpoint | Marcador sintético `100101` | Não reivindicado como cobertura | Criar teste benigno e confirmar comando e processo-pai. |
| Possível exfiltração | [T1041 — Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) somente se aplicável | Sysmon ID 3 + contexto de proxy/firewall | Marcador sintético `100102` | Não reivindicado como cobertura | Não criar regra até possuir telemetria de rede e contexto de dados. |
| Elevação de privilégio | [T1548 — Abuse Elevation Control](https://attack.mitre.org/techniques/T1548/) quando aplicável | Auditoria de privilégios e autenticação | Marcador sintético `100103` | Não reivindicado como cobertura | Definir evento nativo seguro e validar antes de mapear como cobertura. |

## Regras de interpretação

1. Uma técnica só passa a “validada” quando há evento nativo ou telemetria de processo/rede correspondente no Wazuh.
2. Um evento isolado não prova intenção maliciosa; a triagem requer contexto, ativo, usuário, horário e mudança aprovada.
3. Severidade não é herdada diretamente da técnica ATT&CK. Ela depende do impacto, confiança e escopo observados.
4. IDs Sysmon 1 e 11 já foram observados no Manager; o ID 3 e a correlação de um PowerShell benigno continuam pendentes.
5. Consulte o [registro de falsos positivos](false-positive-register.md) antes de criar qualquer exceção ou supressão.
