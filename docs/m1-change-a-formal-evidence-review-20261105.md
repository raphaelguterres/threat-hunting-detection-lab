# M1 — revisão técnica formal das evidências da mudança A (05/11/2026)

**Mudança:** `M1-FIM-OS-SCOPE` (atributo `os="^Linux"` no bloco Unix central Wazuh).  
**Método:** auditoria documental, inspeção de capturas autorizadas, conciliação de registros de três testes benignos e validação de proveniência dos arquivos privados.  
**Tipo de revisão:** **autoavaliação técnica documentada — NÃO equivale a revisão humana independente**.  
**Parecer:** `TECHNICAL_EVIDENCE_REVIEWED_WITH_OPEN_GATES`. **Aceite final NO-GO** enquanto `manager_ingestion` e aprovação independente não forem atendidos.

## Matriz de evidências e decisão

| Critério | Evidência examinada | Parecer |
| --- | --- | --- |
| Escopo do cutover | Registro do único seletor Unix `os="^Linux"`, hash da candidata implantada, parser oficial e metadados | **PASS no checkpoint de implantação** |
| Agentes e distribuição | `002`, `004`, `005` ativos/sincronizados após mudança; grupos e escopo configurado revisados no Dashboard | **PASS** |
| FIM Linux `002` | Arquivo inerte criado/modificado/excluído; mesmo artefato/agent.id presente em 3 documentos reais `wazuh-alerts-*`/Discover | **PASS para Indexer/Discover** |
| FIM Windows `004` | Diário de execução, limpeza confirmada e três capturas individuais de `added`, `modified`, `deleted` do mesmo artefato | **PASS para Indexer/Discover** |
| FIM Kali nativo `005` | Teste local autenticado e limpeza; três documentos `added`, `modified`, `deleted` filtrados por agent.id e artefato específico | **PASS para Indexer/Discover** |
| Total de eventos pós-change | **9 documentos indexados**, três por agente e por ciclo `added/modified/deleted` | **PASS — 9/9 no Indexer/Discover** |
| Log local do Wazuh Manager | Ainda não há prova independente de correspondência aos nove registros diretamente no `alerts.json` do Manager | **PENDENTE; não inferir PASS apenas de `manager.name`** |
| Integridade do conjunto | **10 arquivos privados** (relatórios JSON e capturas) com tamanho, existência e **SHA-256** registrados em `.lab/m1-formal-evidence-review-20261105-private.json` | **PASS na verificação local de arquivos** |
| Backup e rollback | Cópias e hashes registrados em verificações anteriores, mantidos após a mudança; sem restauração operacional nesta revisão | **Preservados; não excluir** |
| CI | [GitHub Actions #133](https://github.com/raphaelguterres/threat-hunting-detection-lab/actions/runs/42073052645): **3/3 jobs SUCCESS** | **PASS de CI, não prova de produção** |
| Revisor independente | Nenhum review formal submetido ao PR [#25](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/25) | **PENDENTE** |

## Cadeia de evidência e limites

As capturas do Discover foram examinadas individualmente para o Windows `004`; os registros dos três agentes apresentam identidade do teste, caminho do artefato e sequência de eventos correspondentes. Cada execução usou um arquivo descartável em diretório previamente monitorado; as confirmações de limpeza estão registradas nos relatórios privados. Os horários do guest/Dashboard e do host não usam a mesma apresentação; foi observada diferença de fuso de exibição e deriva do relógio Kali de cerca de 22 segundos. O parecer **não** depende apenas de coincidência de horário.

O snapshot privado guarda os SHA-256 e os nomes dos arquivos de evidência. **Não publicar hashes completos, caminhos internos, IDs brutos dos eventos, screenshots não sanitizados, credenciais ou log inteiro no GitHub.**

A consulta direta aos alertas brutos do Manager pelo acesso remoto já foi restringida. **Não se buscou contornar essa restrição por rota alternativa.** Portanto, `manager_ingestion` permanece `pending` no manifesto. A evidência no índice comprova chegada ao Indexer e visibilidade no Discover, mas não faz uma segunda atestação independente do arquivo local do Manager. Esta revisão foi feita pelo mesmo fluxo de execução; **não concede aprovação independente para si própria**.

## Parecer formal e condições de encerramento

1. **Escopo funcional FIM no Indexer e Discover: APROVADO de forma delimitada** para os três agentes, com evidências reais 9/9.
2. **Aceite operacional completo da mudança A: PENDENTE**, em razão da ausência de inspeção direta autorizada dos nove alertas correspondentes no Manager e da revisão formal por outra pessoa.
3. `DEPLOYMENT_GATE=BLOCKED` permanece **inalterado por desenho**; o manifesto local não foi preenchido artificialmente para liberar aprovação.
4. PR #25 permanece aberto; sem merge automático nem descarte de backup/rollback; M1 permanece 11/17 porque suas entregas de hunting H01/H02/H03 continuam separadas.

### Handoff para operador/revisor autorizado

Pela **interface/console do Manager com permissão explícita**, confirmar na janela dos testes de 05/11 as ocorrências `002/004/005`, comparando **ID do agente + evento `added/modified/deleted` + identidade do artefato + timestamp** com as nove entradas do índice. O operador deve preservar a prova apenas em `.lab/` e registrar um parecer sanitizado. Se a interface aprovada não permitir acesso aos alertas locais, manter o item pendente e solicitar o método aprovado à administração do laboratório; **não contornar controles de acesso**.

Submeter a documentação e a evidência sanitizada a **outra pessoa revisora**, registrar resultado e quaisquer ressalvas na Issue #17 e PR #25. Apenas após isso avaliar o aceite da mudança A.

**Referências:** [execuções e resultados nos três agentes](m1-change-a-three-agent-fim-evidence-20261105.md) · [plano pós-cutover](m1-change-a-postresume-observability-plan-20261105.md) · [Matriz de aceitação](m1-fim-acceptance-matrix.md) · [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17).
