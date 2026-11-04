# Painel de progresso — Threat Hunting & Detection Lab

**Checklist e gate reconferidos em 04/11/2026, 13h17 BRT.** A conectividade de diagnóstico com o Kali não pôde ser renovada nesta passagem; dados de telemetria abaixo mantêm as datas originais de observação. Ver [reconciliação read-only de 04/11](m1-readonly-reconciliation-20261104.md).

> **Fonte da contagem:** caixas de seleção do [ROADMAP.md](../ROADMAP.md), não percentuais de segurança, de produtividade, de CI ou de implantação. Conferir a contagem atualizada com `python scripts/roadmap_progress.py`. Evidência de runtime, aprovação humana e change control são requisitos separados.

## Visão resumida

| Trilho | Estado | Contagem | Evidência/limite |
| --- | --- | --- | --- |
| **Fases históricas 1–6** | **Concluídas no roadmap original** | **8/8 entregas** e **6/6 fases** | [Issues #1–#8](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues?q=is%3Aissue+is%3Aclosed), todas encerradas em 26/10 ou antes |
| **M1 — Threat Hunting por hipóteses** | **Em andamento** | **11/17 marcados (64,7%); 6 pendentes** | Critérios reais de aceitação ainda incompletos |
| **CI e contratos offline M1** | **PASS local em 04/11** | 198 testes aprovados, 4 ignorados e 160 subtestes aprovados; Actions #79 SUCCESS (3/3 jobs), commit ce557d4, é histórico | A aprovação de testes sintéticos não prova evento real nem autoriza deploy |
| **Revisão/merge do código M1** | **Pendente** | PRs [#24](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/24) e [#25](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/25) abertos, sem review formal | `main` sem esses commits; proteção de `main` pendente na [Issue #26](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/26) |
| **Mudança ativa de FIM no Manager** | **NO-GO** | Grupo `default`: 4 membros conferidos no Dashboard; 3/3 ativos sincronizados, `001` histórico desconectado; gate formal ainda incompleto | Backup/rollback e revisão operacional não substituem autorização |
| **Jornada de 03/11** | Acompanhada em arquivo privado | Controle de horário separado de progresso | Tempo de sessão não mede porcentagem do roadmap |

```text
Laboratório original  ████████████████████  8/8 entregas documentadas
M1 checklist          █████████████░░░░░░░ 11/17 (64,7%)
M1 deployment FIM     BLOQUEADO — não expressar como porcentagem
```

## Fases 1–6 (baseline histórica)

| Fase | Entrega e evidência histórica | Estado |
| --- | --- | --- |
| 1. Base | Arquitetura, inventário e limites; Issue #1 | Concluída |
| 2. Telemetria | Sysmon/Windows e FIM Linux fora de container; Issues #2 e #3 | Concluída |
| 3. Detecção original | Cinco casos e cobertura ATT&CK, com controles negativos; Issues #4 e #5 | Concluída |
| 4. Investigação | Cinco estudos de caso/timelines; Issue #6 | Concluída |
| 5. Resposta segura | Playbooks com aprovação humana e rollback; Issue #7 | Concluída |
| 6. Portfólio | README, exemplos e materiais redigidos; Issue #8 | Concluída |

Essas conclusões históricas são sobre **entregas do roadmap original** e não equivalem à correlação real das **três novas hipóteses M1**. O [status operacional mais antigo](STATUS_ATUAL_LAB.md) permanece como registro datado, não uma afirmação sobre disponibilidade atual das VMs.

### Checkpoint M1 — 03/11/2026, 23h30 BRT

- O Discover autenticado do `004`, data view `wazuh-alerts-*`, exibiu **488 hits** para `agent.id:004 and syscheck.path:*` na janela móvel *Last 7 days*, e **0** para a consulta que exclui `HKEY*`. Não houve comprovação de evento de alteração de arquivo.
- O Indexer confirmou via `GET wazuh-alerts-4.x-2026.11.03/_mapping/field/syscheck.path` (**HTTP 200**) o mapeamento **`syscheck.path: keyword`** nesse índice específico.
- O Manager exibiu **nível mínimo 3 para armazenar alertas** e **12 para envio de e-mail**; níveis efetivos das regras FIM relevantes e disponibilidade de archives ainda precisam de revisão.
- A VM WindowsServer `004` tinha `WazuhSvc=Running`, seis diretivas FIM (cinco agendadas, uma realtime), frequência de 12h e duas entradas de exclusão. O `ossec.log` atual não continha menções `syscheck`/`fim` no recorte de 377 linhas; isso **não** comprova ausência de varredura.
- A questão do agente histórico `001`, as mudanças FIM e auditoria `4698`, a revisão independente dos PRs e as correlações H01/H02/H03 **permanecem abertas**. Gate de pré-mudança reexecutado: `EVIDENCE_COMPLETENESS=INCOMPLETE`, `DEPLOYMENT_GATE=BLOCKED`.
- Jornada privada de 03/11: **6h00 registradas**, controle pausado; o tempo não muda o percentual do roadmap.

Detalhes sanitizados: [auditoria FIM e política do Indexer](m1-agent004-syscheck-policy-log-readonly-20261103.md) e [consulta de sete dias](m1-agent004-fim-seven-day-discover-20261103.md).

## M1 — 11 itens marcados e seis entregas ainda abertas

| Prioridade | Pendente no checklist M1 | Dependências e critério |
| --- | --- | --- |
| **1** | Confirmar inventário/OS dos demais agentes, duplicidade Security e cobertura FIM efetiva do `004` | Quatro membros de `default` com ID, OS+versão, grupos **na ordem**, status, sync e captura autorizada; revisar precedência; [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17) |
| **2** | Aprovar, executar e validar change control Windows `4698` | Aprovação e janela separadas, retenção, ingestão Wazuh, rollback e evidências pós-mudança; [Issue #15](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15) |
| **3** | Correlacionar H01/H02/H03 em eventos reais completos | Mesmos ativos/atores/artefatos e janelas, evidência Manager → Indexer → Discover, controle negativo e interpretação humana; [Issue #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9) |
| **4** | Registrar estudos de caso adicionais com timelines e decisões | Dados realmente observados, limitação da amostra, triagem e evidência sanitizada |
| **5** | Revisar tuning, falsos positivos e cobertura ATT&CK por hipótese | Comparar com controles negativos reais; documentar detecções ausentes e ajustes aprovados |
| **6** | Encerrar M1 com revisão independente e evidência sanitizada | PRs revisados por terceiro habilitado, aprovação documentada e critérios técnicos satisfeitos; [Issue #26](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/26) |

A relação acima **reordena os seis itens pendentes por dependência operacional**; não altera o checklist do [ROADMAP.md](../ROADMAP.md).

### Telemetria nativa real — nova consulta em 03/11 (~20h25 BRT)

Na [segunda auditoria somente leitura](m1-native-telemetry-checkpoint-20261103.md), Windows Server Security retornou **4698=0, 4720=0, 4672=289, 4624=295** e Sysmon ID 1 retornou **pelo menos 2.000 registros** (teto de coleta). A correlação de H02 não teve fonte 4720 na nova janela, e H03 não foi reavaliada no Indexer porque o Dashboard mostrava **not ready yet**. Portanto, os dados reais não concluem nenhuma hipótese nem desbloqueiam FIM. A nova conferência de retenção mostrou Security circular de 20 MiB com evento mais antigo em 22/10. Reabrindo a janela histórica de 31/10–04/11, H02 encontrou **1 criação de conta `4720`**, porém **nenhum 4624/4672 do mesmo SID nos 30 minutos seguintes**. Isso confirma apenas o recorte, não a ausência de comportamento em geral. Os 11/17 itens marcados de roadmap permanecem inalterados.

### Threat Hunting H01/H02/H03 — atualização de 03/11, 20h

O [checkpoint de fontes H01/H02/H03](m1-hunting-source-readiness-20261103.md) registra que a auditoria 4698 ainda depende de mudança aprovada, a associação 4720→4672/4624 não foi provada no recorte anterior e não há par FIM→execução real validado para o mesmo artefato. O motor offline rejeita aliases de identidade indefinidos; os testes sintéticos **não** são evidências novas de ataque. A [Issue #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9) permanece em aberto.

### Atualização operacional — 03/11, 19h46 BRT

- **Concluído por observação autorizada:** grupo `default` com IDs `001`, `002`, `004`, `005`; o Dashboard exibiu `SYNCHRONIZED` para os três agentes ativos `002`, `004` e `005`. A listagem centralizada mostrava somente o grupo `default`.
- **Pendente:** `001` continua desconectado e preservado como registro histórico. O gate formal de quatro agentes `active/synced` continua **não atendido**. Ver [decisão formal](m1-legacy-agent-001-decision.md) e [Issue #27](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/27).
- **Baseline revalidada:** checkpoint de somente leitura do Manager com hash igual ao backup privado, parser PASS e `004` sync PASS. A proposta mínima `os="^Linux"` foi aprovada offline, **não implantada**.
- **Autorização pendente:** [pacote de mudança FIM](m1-fim-change-approval-package.md), rollback operacional, janela, revisão independente e posterior verificação real do pipeline. O status segue **NO-GO**.

Os 11/17 itens marcados do M1 **não mudaram**: há progresso operacional verificável, mas não conclusão dos critérios totais de aceite. O bloco histórico abaixo registra o checkpoint anterior de 16h02 e não substitui o atual.

### Gate técnico atual: NO-GO

Às 16h02 BRT, o checkpoint read-only retornou:
- `AGENT_004_SYNC=PASS`
- `ACTIVE_DEFAULT_CONFIG_PARSER=PASS`
- `MANAGER_HASH_EQUALS_PRIVATE_BASELINE=True`
- `M1_READ_ONLY_CHECKPOINT=PASS`
- `ALL_FOUR_AGENT_OS_INDIVIDUALLY_CONFIRMED=NOT_VERIFIED`
- `BACKUP_RESTORE_APPROVED=NOT_VERIFIED`
- `CHANGE_WINDOW_APPROVED=NOT_VERIFIED`
- `DEPLOYMENT_GATE=BLOCKED`

O CSV privado contém quatro placeholders `UNVERIFIED`, que não são evidência operacional. O ensaio isolado de restauração de bytes do backup real DPAPI foi aprovado, **sem** realizar rollback no Manager. A proposta FIM `os="^Linux"` foi aceita pelo parser oficial **somente em cópia isolada**, não distribuída. Nem o teste nem o CI autorizam modificar a configuração ativa.

**Existe ainda uma mudança FIM ativa potencial (Issue #17)**, com necessidade de autorização, teste e rollback. Ela não é um sétimo item de checklist independente no ROADMAP atual, de modo que o percentual **64,7% não representa o esforço total restante nem previsão de prazo**.

### Triagem de conectividade antes do aceite dos agentes

O operador forneceu uma lista contendo três endpoints Linux, um Windows e um agente desconectado, porém sem os dados de associação ao grupo e sincronização. O [roteiro de diagnóstico do agente desconectado](m1-agent-001-disconnection-triage.md) e a prévia privada de **observações parciais** mantêm esses campos desconhecidos sem confundi-los com o inventário formal. O status do milestone continua **NO-GO** até a reconciliação 4/4.

## Sequência segura para a próxima sessão

1. **Operador / responsável:** os quatro membros de `default` já foram identificados na interface. **Agora** obter decisão formal sobre `001` e, na futura janela autorizada, renovar a coleta de status/sync, OS e grupos na ordem. Não usar API/CLI para contornar bloqueios; manter capturas privadas em `.lab/`. Ver [Issue #27](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/27).
2. **Revisor técnico:** conferir ordem/precedência dos grupos, diferenças Linux/Windows, telemetria local FIM, duplicidade dos coletores Security, e finalizar parecer **GO/NO-GO**.
3. **Gestor da mudança:** aprovar separadamente a janela, restauração operacional e, se pertinente, a mudança FIM e o `4698`. **Nenhuma execução antecipada.**
4. **Após mudanças autorizadas:** coletar eventos benignos reais e investigar H01/H02/H03 até o Discover com amostras, contexto e controle negativo.
5. **Encerramento:** completar timelines, tuning, revisão de PR por terceiro e documentação redigida. Só então marcar os seis checkboxes restantes.

## Fontes e rastreabilidade

- [Roadmap de referência](../ROADMAP.md)
- [Hipóteses M1](m1-three-hunting-hypotheses.md)
- [Matriz de aceitação FIM por OS](m1-fim-acceptance-matrix.md)
- [Gate de evidências](m1-evidence-gate.md)
- [Issue #9 — Hipóteses de hunting](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9)
- [Issue #15 — Change control 4698](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15)
- [Issue #17 — FIM por OS](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17)
- [Issue #26 — Proteção de main e revisão](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/26)

*Documentação pública apresenta apenas estados e contagens; não inclui dados de endpoints, hashes privados, credenciais ou capturas reais.*
