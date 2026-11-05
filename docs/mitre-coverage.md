# Cobertura MITRE ATT&CK

Esta matriz descreve hipóteses de detecção do laboratório, não uma alegação de que cada técnica foi executada. A coluna de evidência evita que marcadores sintéticos sejam apresentados como telemetria nativa.

| Cenário | Técnica ATT&CK | Fonte pretendida | Tipo de evidência | Status ATT&CK | Próxima validação |
|---|---|---|---|---|---|
| Falhas repetidas de login | [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) | Eventos nativos de autenticação Windows/Linux | Marcador sintético `100100` | Não reivindicado como cobertura | Gerar falhas controladas em conta de teste e correlacionar com sucesso posterior. |
| Acesso SSH administrativo | [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/) + [T1021 — Remote Services](https://attack.mitre.org/techniques/T1021/) | Eventos SSH nativos do Kali | Eventos visualizados no Dashboard MITRE em 26/10/2026 | Telemetria observada; não classificada como incidente | Validar conta, origem, janela aprovada e sequência de eventos antes de decidir pela contenção. |
| Alteração de conta | [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/) quando aplicável | Auditoria de conta Windows/Linux | Planejado | Hipótese | Criar e remover conta de teste e confirmar evento nativo. |
| PowerShell benigno | [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) | Sysmon ID 1 | Comando benigno controlado recebido pela regra 92027, com usuário e processo-pai | Hipótese | A telemetria foi validada; não inferir intenção maliciosa a partir de PowerShell isolado. |
| Alteração de arquivo | Sem mapeamento automático | Wazuh FIM + Sysmon ID 11 | FIM Windows e Kali nativo validados | Não aplicável; alteração não prova intenção | Correlacionar arquivo, processo e mudança aprovada. |
| Conexão de rede inesperada | Técnica definida após contexto | Sysmon ID 3 | Conexão HTTPS autorizada do Edge validada; regra 100105 | Hipótese | Usar processo, destino aprovado e janela temporal; não mapear automaticamente uma navegação a ATT&CK. |
| Execução de comando | [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) | Sysmon ID 1 / logs do endpoint | Marcador sintético `100101` | Não reivindicado como cobertura | Criar teste benigno e confirmar comando e processo-pai. |
| Possível exfiltração | [T1041 — Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) somente se aplicável | Sysmon ID 3 + contexto de proxy/firewall | Marcador sintético `100102` | Não reivindicado como cobertura | Não criar regra até possuir telemetria de rede e contexto de dados. |
| Elevação de privilégio | [T1548 — Abuse Elevation Control](https://attack.mitre.org/techniques/T1548/) quando aplicável | Auditoria de privilégios e autenticação | Marcador sintético `100103` | Não reivindicado como cobertura | Definir evento nativo seguro e validar antes de mapear como cobertura. |

## M1 — cobertura condicionada das hipóteses H01/H02/H03 (revisão 05/11/2026)

**Não confundir técnicas ATT&CK mapeadas com comportamento adversário detectado.** Os recortes reais servem à análise da qualidade da junção e das fontes; os testes de contrato sintéticos não são prova operacional. [Relatório de tuning, falsos candidatos e ATT&CK](m1-hunting-tuning-fp-attack-review-20261105.md).

| Hipótese | Técnica(s) possíveis | Evidência real no recorte | Cobertura ATT&CK M1 reivindicada? | Requisito que ainda falta |
| --- | --- | --- | --- | --- |
| **H01 — PowerShell → tarefa** | [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) + [T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) | `110100` PowerShell e `110120` tentativa de `schtasks /create` em **ordem invertida e fora da janela de 15 min**; `4698` não coletado no último baseline | **Não. Apenas hipóteses/técnicas candidatas** | Security `4698` real, mesmo ator/host e sequência temporal após autorização de auditoria |
| **H02 — conta local → logon privilegiado** | [T1136.001 — Local Account](https://attack.mitre.org/techniques/T1136/001/) + [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/) **condicional à evidência de abuso** | Um `4720` real, **sem** `4624/4672` do mesmo SID nos 30 min; totais genéricos não compõem par | **Não. Conta nova e logon genérico não demonstram abuso** | Vínculo ao mesmo SID e Logon ID, contexto/autorização e revisão de identidade |
| **H03 — FIM → execução** | **Nenhuma técnica atribuída automaticamente** à simples alteração de arquivo | **9 eventos FIM reais benignos** (002/004/005, `added/modified/deleted`); **não há par verificado com Sysmon 1 do mesmo artefato** | **Não. FIM prova monitoramento de arquivo, não execução adversária** | Sysmon 1 com mesma identidade de arquivo/ativo, janela de até 20 min, contexto antes do mapeamento |

A revisão de tuning decidiu **não alterar regras nem aplicar supressões** diante das lacunas. H01 e H02 oferecem controles reais que **não satisfazem** uma condição necessária da correlação; H03 oferece controles de contexto benigno, mas **não um experimento negativo independente**. [Registro de falsos positivos/correlações indevidas](false-positive-register.md). A revisão está documentada; **a validação real completa das três hipóteses permanece aberta**.

## Regras de interpretação

1. Uma técnica só passa a “validada” quando há evento nativo ou telemetria de processo/rede correspondente no Wazuh.
2. Um evento isolado não prova intenção maliciosa; a triagem requer contexto, ativo, usuário, horário e mudança aprovada.
3. Severidade não é herdada diretamente da técnica ATT&CK. Ela depende do impacto, confiança e escopo observados.
4. IDs Sysmon 1, 3 e 11 já foram observados no Manager; um PowerShell benigno também foi correlacionado pela regra nativa 92027. Isso valida a telemetria, não uma intenção maliciosa.
5. Consulte o [registro de falsos positivos](false-positive-register.md) antes de criar qualquer exceção ou supressão.
