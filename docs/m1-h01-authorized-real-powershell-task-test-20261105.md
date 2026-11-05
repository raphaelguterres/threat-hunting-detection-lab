# M1 — H01: PowerShell → tarefa agendada (teste benigno real de 05/11/2026)

**Status:** `H01_NATIVE_PAIR=PASS`; `H01_4698_INDEXER_DISCOVER=PASS`; `H01_SYSMON_EID1_INDEXER_DISCOVER=NOT_VERIFIED`; **correlação Wazuh completa ainda pendente**.

## Autorização, limites e método

O proprietário confirmou **“bora”** após a solicitação explícita de janela específica para **um** teste benigno H01. Janela de 30 minutos **16h17min24s–16h47min24s BRT**, exclusivamente no Windows Server de laboratório, agente `004`. Foram mantidos o `4698` já ativo, os coletores e todas as regras sem alterações.

A ação foi iniciar **um novo processo PowerShell**, registrar **uma tarefa agendada inerte** para o dia seguinte (sem executar ação) e excluí-la imediatamente. Nenhuma conta, firewall, regra de detecção, política de auditoria, serviço, VM ou configuração de Wazuh foi alterada. O teste foi executado **uma vez**; não houve repetição para compensar lacunas no índice.

### Pré-check e segurança

- Conta de operação com privilégios administrativos na VM, **4698 Success-only** ativo e Security habilitado (**20 MiB/circular**).
- Canal **Sysmon/Operational** ativo, com eventos de processo anteriores visíveis.
- Serviço `WazuhSvc` executando, tarefa de teste ainda inexistente antes do início.
- Backup `auditpol` e rollback da mudança 4698 preservados dentro da VM.
- Pós-check somente leitura: os controles anteriores permaneceram aprovados e a tarefa foi verificada **ausente**. Nenhuma ação de tarefa foi executada.

## Evidência nativa Windows — par válido

Os dois eventos provêm da **mesma execução controlada**, não da amostra histórica em que `schtasks` antecedia PowerShell em mais de uma hora.

| Campo | Processo PowerShell | Criação da tarefa |
| --- | --- | --- |
| Fonte Windows | **Sysmon Event ID 1** | **Security Event ID 4698** |
| Agente/ativo | `004` | `004` |
| RecordID nativo | `173036` | `15346` |
| UTC | **19:20:56.4921438Z** | **19:20:57.8309460Z** |
| Verificação de ator | Usuário do Sysmon e SID da auditoria confirmados como a mesma conta na VM | Mesmo operador |
| Ordem | Primeiro | Segundo |

**Intervalo real: 1,34 segundo**, dentro de 15 minutos. A validação nativa confirmou **mesmo usuário/SID e mesmo servidor**, linha do tempo positiva e presença da tarefa de teste no registro `4698`. O payload foi **programado para o futuro, jamais executado**, e o objeto foi removido antes do agendamento.

**Interpretação:** a correlação é **verdadeira como sequência de ações benignas de teste**, não prova de persistência maliciosa nem incidente de segurança. A amostra histórica de 01–02/11 continua inválida para H01 por ordem e janela.

## Indexer/Discover: uma fonte confirmada, outra não

No data view `wazuh-alerts-*` do Discover, janela móvel de 24 horas:

| Consulta autorizada (somente leitura) | Resultado |
| --- | --- |
| `agent.id: 004 and data.win.system.eventID: 4698 and data.win.system.eventRecordID: 15346` | **1 documento**, mesmo RecordID da origem — **PASS** |
| `agent.id: 004 and data.win.system.eventID: 1 and data.win.system.eventRecordID: 173036` | **0 documentos** — **não verificado** |
| `agent.id: 004 and data.win.system.eventID: 1` | **80 documentos** de outros processos, na consulta ampla; **não** comprova o evento de teste |
| `agent.id: 004 and data.win.eventdata.commandLine: *M1_H01_CONTROLLED_TEST_20261105*` | **0 documentos** — **não verificado** |

**Precisão da conclusão:** o mesmo evento `4698` foi observado no Security nativo e no Indexer/Discover. O evento **Sysmon 1 específico estava presente no log nativo da VM**, mas **não foi encontrado no índice de alertas** por RecordID ou pelo identificador do script. Isso **não prova a causa** (normalização, regra/nível, coleta, latência, ausência de alerta, ou configuração do índice). Não afirmar que a fonte Sysmon do laboratório inteiro está inativa, porque outros 80 documentos Sysmon 1 apareceram no índice.

Não houve acesso direto aos logs `alerts.json` do Manager — essa via permanece restringida e **não foi contornada**. Sem os **dois lados indexados** e uma correlação nativa→Manager comprovada, `H01_FULL_WAZUH_PIPELINE` é **INCOMPLETE**, mesmo com a origem Windows demonstrada.

## Teste do motor offline — candidato real delimitado

O arquivo **privado** `.lab/m1-h01-native-normalized-20261105.jsonl` contém duas linhas **pseudonimizadas manualmente a partir do resumo exibido pelo guest Windows**, com timestamps e RecordIDs nativos capturados. Os aliases de ator/ativo foram usados somente porque o teste confirmou o mesmo ator e servidor, **não são exportações independentes de XML bruto**.

Com o correlacionador `python scripts/hunt_correlations.py --input .lab/m1-h01-native-normalized-20261105.jsonl`:

- `H01_POWERSHELL_TASK.candidate_pairs=1`, status `triage_candidate`;
- `H02` e `H03`: `insufficient_source_coverage`;
- `verdict=not_an_incident_determination`, `sample_provenance=user_supplied_normalized_not_independently_verified`.

**Essa execução não transforma registros nativos em dois documentos comprovados do Indexer** e não equivale a um sign-off independente.

## Proveniência, riscos e decisão

O snapshot privado `.lab/m1-h01-controlled-correlation-20261105-private.json` guarda **SHA-256 de dez artefatos** (scripts, capturas, normalização), autorização, pré/pós-checks, identidade de cada evento e lacunas. Dados de usuário, SID, host, IP, paths completos e capturas brutas não são publicados.

- **PASS:** teste nativo benigno H01, origem Sysmon EID1 + Security 4698, identidade, ordem/tempo, segurança da execução, limpeza, `4698` indexado.
- **PENDENTE:** provar o documento Sysmon EID1 específico em origem indexada autorizada e sua ligação ao `4698`, investigar diferença entre evento nativo e alerta do Indexer sem alterar regras sem GO próprio.
- **NÃO EXECUTADO:** segundo teste ativo, mudança na configuração Sysmon/Wazuh, supressões, revisão independente ou leitura de logs restringidos.
- **M1 permanece 15/17 (88,2%)**: o item do roadmap exige **H01, H02 e H03 completos em eventos reais**, não apenas a preparação de H01. A revisão independente e o aceite final também continuam pendentes; o rollback da auditoria 4698 permanece pronto.

### Próximas ações autorizadas sem novo teste ativo

1. Revisar **somente configurações e metadados** do agente `004`, filtros Sysmon/EventChannel e níveis de regras para entender por que o registro `173036` não aparece no `wazuh-alerts-*`. Não inferir causa por ausência de hit.
2. Se houver um método legítimo de consulta/arquivo aprovado, conciliar a mesma identidade de evento nas fontes, **sem contornar a restrição prévia** a acesso bruto do Manager.
3. Preparar investigação H02/H03 com dados reais já existentes e controles negativos, sem gerar ações adicionais sem autorização específica.

Referências: [Mudança 4698 aprovada](m1-4698-approved-cutover-real-ingestion-20261105.md) · [Hipóteses M1](m1-three-hunting-hypotheses.md) · [Revisão de tuning/FP/ATT&CK](m1-hunting-tuning-fp-attack-review-20261105.md) · [Issue #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9) · [PR #25](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/25).
