# M1 — três estudos de caso reais: alterações FIM controladas (05/11/2026)

**Estado dos estudos:** concluídos como **investigações de testes benignos autorizados** sobre eventos reais. **Não são incidentes de segurança nem validação das hipóteses H01/H02/H03.**  
**Fonte observada:** documentos de Wazuh FIM no `wazuh-alerts-*` consultados no Discover, com três operações `added`, `modified` e `deleted` por agente.  
**Escopo da validação:** **Indexer/Discover, 9/9 documentos**; o log local do Manager **não foi inspecionado de maneira independente**.  
**Analista:** proprietário do laboratório e assistência técnica (autoavaliação, sem revisão de terceiro).  
**Evidências:** registros originais, paths completos, hashes e capturas somente em `.lab/` (não publicados).

## Metodologia e critérios aplicados

Cada caso registra o alerta esperado e o realmente observado, o período, o ativo com alias, os eventos ordenados, o contexto de mudança autorizada, as principais hipóteses alternativas, a decisão de triagem, a ação indicada, o resultado da limpeza e as lacunas. A correlação usada foi **agente + mesmo artefato de prova + tipo de ação + sequência temporal**, com apoio das capturas específicas do Dashboard; não foi deduzida apenas do número total de hits.

Os horários **BRT** abaixo são provenientes dos registros do operador quando disponíveis. Os horários **“exibidos no Discover”** são transcrições da interface; a UI apresentava uma diferença próxima de **duas horas** em relação ao Windows host, e foi observada deriva adicional de aproximadamente **22 s no Kali**. Não declarar sincronização NTP, timestamp UTC dos resultados ou precisão de milissegundos para a correlação entre sistemas sem conferência adicional.

A ação controlada foi **criar → modificar → excluir** um arquivo **inerte e descartável**, sem execução de binário de teste, persistência, modificação de regras, `auditpol`, restart ou contenção.

---

## Caso FIM-001 — Linux isolado, agente `002`

**Questão:** um alerta triplo de alteração de arquivo em um endpoint Linux indica comprometimento ou atividade de laboratório autorizada?

| Campo | Registro |
| --- | --- |
| Ativo | Linux `002` — contêiner de teste de telemetria |
| Origem | Wazuh FIM no Indexer/Discover; dados originais privados do teste |
| Artefato | Um arquivo de texto temporário exclusivo no diretório isolado monitorado (caminho completo privado) |
| Janela autorizada | 05/11/2026, **13:18:53–13:48:53 BRT** |
| Alertas | **3**: `added`, `modified`, `deleted`; mesmo `agent.id=002` e mesmo `syscheck.path` |
| Classificação | **Atividade benigna autorizada, com detecção FIM positiva** |
| Severidade/ID de regra | Não extraídos de forma independente para este caso; não estimar severidade |
| Resultado da limpeza | Arquivo ausente após o teste; verificação confirmada |

### Linha do tempo

| BRT (operação local) | Timestamp exibido no Discover (fuso da UI não confirmado) | Ocorrência | Interpretação |
| --- | --- | --- | --- |
| 13:22:29 | 11:22:50.977 | `added` | O Wazuh indexou a criação do arquivo autorizado |
| 13:22:36 | 11:22:58.379 | `modified` | O Wazuh indexou a alteração de tamanho/conteúdo do mesmo artefato |
| 13:22:43 | 11:23:05.711 | `deleted` | O Wazuh indexou a remoção e confirmou o ciclo do teste |

**Decisão de triagem:** documentar como *detecção verdadeira de alteração, mas não incidente*; não atribuir intenção maliciosa. A sequência foi prevista e aconteceu dentro da janela de autorização. O mesmo artefato e o mesmo agente foram observados nas três etapas, e houve limpeza.

**Hipóteses alternativas/controles:** uma mudança não autorizada poderia gerar a mesma sequência; o contexto de autorização e a identidade do artefato distinguem este caso. **Não houve controle negativo independente** com outro arquivo/host, nem confirmação direta do `alerts.json` no Manager. Sem execução de binário, não há prova de H03 (FIM → execução).

**Ação recomendada:** preservar evidência sanitizada, manter o diretório de prova segregado, verificar posteriormente o log local do Manager pelo meio autorizado e não abrir incidente nem realizar contenção para este teste aprovado.

**Fonte privada:** `.lab/m1-fim002-benign-test-11f5daef7e9f4628-private.json`, `.lab/m1-fim002-discover-correlation-20261105-private.json`, capturas do Discover.

---

## Caso FIM-002 — Windows Server, agente `004`

**Questão:** a alteração de arquivo em caminho Windows monitorado continuou detectável após corrigir o escopo Unix da configuração centralizada?

| Campo | Registro |
| --- | --- |
| Ativo | Windows Server `004` |
| Origem | FIM do Wazuh no Indexer/Discover; diário de teste do guest Windows |
| Artefato | Um arquivo de dados temporário e inerte no diretório Windows previamente monitorado |
| Janela autorizada | 05/11/2026, **13:55:48–14:25:48 BRT** |
| Alertas | **3**: um `added`, um `modified`, um `deleted`; mesmo agente e artefato |
| Classificação | **Mudança autorizada com FIM preservado após o cutover** |
| Severidade/ID de regra | Não independente ou integralmente confirmado para este caso |
| Resultado da limpeza | Limpeza do guest registrada como verificada; sem alteração de `auditpol` ou serviço |

### Linha do tempo

| Timestamp exibido no Discover (fuso da UI não confirmado) | Evento | Evidência e decisão |
| --- | --- | --- |
| 12:02:20.228 | `added` | Criação de arquivo inerte detectada no `004` |
| 12:02:27.248 | `modified` | Modificação do mesmo arquivo detectada |
| 12:02:34.276 | `deleted` | Exclusão do mesmo arquivo detectada e limpeza registrada |

**Nota temporal:** os horários individuais da operação no Windows não estão disponíveis no resumo público com precisão de segundo; as três linhas são os horários **exibidos na interface**, dentro da janela de teste autorizada segundo os registros do operador. Não convertê-los silenciosamente para BRT.

**Decisão de triagem:** o comportamento é esperado, está relacionado a um teste benigno explicitamente delimitado e **não é incidente**. O teste evidencia que a coleta FIM de arquivo Windows continuou funcional no Indexer/Discover após a mudança A; a ausência de diretório Unix no Dashboard já tinha sido revisada no checklist de configuração por SO.

**Hipóteses alternativas/controles:** rotinas administrativas e atualizações legítimas podem gerar eventos similares; a identidade do arquivo descartável e a janela aprovada são decisivas neste caso. A detecção funcional **não comprova** cobertura de todos os diretórios, ajuste `4698`, evento Sysmon de execução, causalidade maliciosa ou normalização de horário. **Nenhum teste negativo separado foi realizado.**

**Ação recomendada:** registrar a alteração como mudança de teste autorizada; manter documentação de escopo Windows e rollback até a aceitação do Manager. Não abrir incidente nem conter a VM.

**Fonte privada:** `.lab/m1-fim004-windows-discover-20261105-private.json`, capturas individuais `added/modified/deleted` e diário do teste guest.

---

## Caso FIM-003 — Kali Linux nativo, agente `005`

**Questão:** o FIM do Linux nativo, que utiliza diretório root-owned, funciona quando o teste benigno é executado por um operador com acesso legítimo?

| Campo | Registro |
| --- | --- |
| Ativo | Kali Linux nativo `005` |
| Origem | Wazuh FIM em Indexer/Discover e terminal autorizado do operador |
| Artefato | Um arquivo descartável exclusivo no diretório FIM de laboratório, criado com autenticação `sudo` legítima |
| Janela autorizada | 05/11/2026, **13:55:48–14:25:48 BRT** |
| Alertas | **3**: `added`, `modified`, `deleted`; correspondentes ao mesmo arquivo e agente |
| Classificação | **Atividade benigna autorizada, com FIM nativo comprovado no Indexer/Discover** |
| Severidade/ID de regra | Não atestados independentemente |
| Resultado da limpeza | Ausência do artefato confirmada em verificação posterior, sem contornar permissão remota |

### Linha do tempo

| Registro da ação do operador (UTC) | Timestamp exibido no Discover (fuso da UI não confirmado) | Ocorrência |
| --- | --- | --- |
| 17:12:22Z | 12:12:22.140 | `added` do arquivo benigno |
| 17:12:29Z | 12:12:29.145 | `modified` do mesmo arquivo |
| 17:12:36Z | 12:12:36.149 | `deleted` do mesmo arquivo |

**Nota temporal:** as ações do operador correspondem aproximadamente a **14:12:22, 14:12:29 e 14:12:36 BRT**; a apresentação do Dashboard não foi tratada como UTC. O teste começou na janela previamente autorizada e não foi repetido na autorização adicional das 14:12.

**Decisão de triagem:** alteração esperada e legítima, **não incidente**. A restrição de escrita remota foi respeitada; a execução local autenticada permitiu validar a telemetria sem enfraquecer a política de permissões do diretório monitorado.

**Hipóteses alternativas/controles:** a mesma sequência poderia ocorrer por manutenção ou manipulação indevida sem contexto de autorização. Aqui o histórico da janela, a conta autorizada do operador e a identidade do artefato explicam o comportamento. Não houve experimento negativo independente nem prova de binário executado após FIM; portanto H03 continua não confirmada.

**Ação recomendada:** preservar a evidência, manter as permissões do diretório, não executar mais testes para aumentar contagens e validar o log local do Manager posteriormente por acesso autorizado.

**Fonte privada:** `.lab/m1-fim005-discover-correlation-20261105-private.json`, prova de execução e limpeza e captura de 3 hits no Discover.

---

## Consolidação das investigações

| Verificação | FIM-001 (`002`) | FIM-002 (`004`) | FIM-003 (`005`) |
| --- | --- | --- | --- |
| Sequência `added/modified/deleted` | 3/3 | 3/3 | 3/3 |
| Agente e artefato conciliados no Discover | Sim | Sim | Sim |
| Teste autorizado com contexto registrado | Sim | Sim | Sim |
| Limpeza documentada | Sim | Sim | Sim |
| Decisão de triagem | Benigno; não incidente | Benigno; não incidente | Benigno; não incidente |
| Manager local, fonte independente | Pendente | Pendente | Pendente |
| H01/H02/H03 reais completos | Não comprovado | Não comprovado | Não comprovado |
| Revisor humano independente | Pendente | Pendente | Pendente |

**Conclusão executiva:** três investigações adicionais concluídas com timelines e decisões documentadas sobre **telemetria real** de FIM; **9 eventos reais observados e reconciliados** nas telas do Indexer/Discover. Os alertas são deteções válidas de ações de arquivos aprovadas e descartáveis; não há alegação de comprometimento. A correlação direta no Manager e as hipóteses de Threat Hunting H01/H02/H03 são **etapas separadas**.

### Aceite deste deliverable do M1

O item do `ROADMAP.md` **“Registrar estudos de caso adicionais com timelines e decisões documentadas”** fica concluído com três casos reais, seus artefatos e linhas de tempo, a interpretação e decisão de triagem, consequências operacionais e lacunas explicitadas. **Não** marca como concluídos os itens “correlacionar as três hipóteses em eventos reais”, “tuning/FP/ATT&CK por hipótese” ou “encerrar M1 com revisão independente”.

A revisão independente ainda não foi realizada; a conclusão documental desse item não libera `DEPLOYMENT_GATE` de produção, merge ou alterações ativas. O rollback da mudança A continua preservado.

**Referências:** [evidências dos três agentes](m1-change-a-three-agent-fim-evidence-20261105.md), [revisão formal](m1-change-a-formal-evidence-review-20261105.md), [Issue #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9) e [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17).
