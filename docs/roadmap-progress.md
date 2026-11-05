# Painel de progresso — Threat Hunting & Detection Lab

**Progresso confirmado em 05/11/2026: M1 15/17 (88,2%), duas entregas pendentes.** [Mudança Windows Security 4698 aprovada, aplicada e validada por evento nativo + documento idêntico no Indexer/Discover](m1-4698-approved-cutover-real-ingestion-20261105.md). No agente `004`, auditoria **Success** ativada, um `4698` real de tarefa benigna, **RecordID 15301** igual na origem e no índice, limpeza confirmada, retenção Security 20 MiB/circular observada e rollback local pronto. O risco de sobreposição de **dois** coletores Security **não foi mitigado**, e o log local do Manager não foi revisado independentemente. Restam a correlação real completa H01/H02/H03 e o encerramento independente do M1. **O aceite global de implantação continua bloqueado**, e o percentual é apenas do checklist. Checkpoints abaixo são históricos.

**Progresso verificado em 05/11/2026: M1 14/17 (82,4%), três entregas pendentes.** Concluída a [revisão por hipótese de tuning, possíveis falsos candidatos de correlação e cobertura MITRE ATT&CK](m1-hunting-tuning-fp-attack-review-20261105.md), com registros complementares em [FP](false-positive-register.md) e [ATT&CK](mitre-coverage.md). **H01** tem amostra real em ordem temporal inválida e `4698` ausente; **H02** tem um `4720` real sem `4624/4672` do mesmo SID nos 30 min; **H03** tem 9 FIM benignos reais sem execução do mesmo arquivo comprovada e sem controle negativo independente. **A revisão está concluída, mas nenhuma das três correlações foi validada operacionalmente**, não houve tuning implantado nem alteração de gate de produção. Os checkpoints abaixo são históricos.

**Progresso verificado em 05/11/2026: M1 13/17 (76,5%), quatro entregas pendentes.** Concluída a [revisão de inventário 3/3, possível sobreposição Security e cobertura FIM Windows 004](m1-inventory-security-overlap-fim004-closure-20261105.md). Os três agentes permanecem ativos/sincronizados e o Windows 004 teve eventos benignos `added/modified/deleted` realmente indexados. **O risco de coleta Security sobreposta foi identificado, não eliminado**; correção, auditoria 4698, prova direta do Manager e revisão independente continuam separadas. Os checkpoints históricos abaixo preservam suas datas originais.

**Progresso atualizado de 05/11/2026: M1 12/17 (70,6%), cinco pendências.** Foi concluído o item de [três estudos de caso reais de FIM com timelines e decisões](m1-three-real-fim-investigation-case-studies-20261105.md), baseados nos **9 eventos observados em Indexer/Discover** nos agentes `002`, `004` e `005`. Cada caso registra contexto de autorização, classificação benigna, triagem, evidências, limpeza e limitações. **Esse aceite é documental, não conclui H01/H02/H03, Manager local, revisão independente nem implantação.** A contagem é calculada exclusivamente das caixas do [ROADMAP.md](../ROADMAP.md). Os checkpoints antigos abaixo preservam suas contagens históricas.

**Entrega offline adicional em 05/11:** [comparação determinística e privada Manager × Indexer](m1-fim-offline-manager-indexer-compare-20261105.md), executável por `scripts/M1_COMPARAR_EXPORTS_FIM.bat` após disponibilização de exportações legítimas; checa o mesmo ID/regra/artefato/evento/agente e tolerância de horário para **9 eventos / 3 agentes**. 11 testes novos de contrato; nenhuma exportação de Manager foi feita, portanto `manager_ingestion=pending`, aceitação global bloqueada e revisão independente exigida. Checklist M1 permanece **11/17**.

**GO limitado para continuidade de M1 — 05/11:** [regra, testes e registro da autorização](m1-owner-scoped-continuation-go-20261105.md). O script original sempre imprimia `DEPLOYMENT_GATE=BLOCKED`; novo modo `--owner-continuation` agora retorna `PROJECT_CONTINUATION_GATE=OPEN` com exceção privada validada e **somente `manager_ingestion` pendente**, sem simular prova nem aceitar deploy. O gate estrito continua bloqueado até evidência do Manager e revisão independente. Atividade liberada: documentação, CI, desenvolvimento offline e leitura autorizada. **M1 11/17**; manter backup/rollback e PR sem merge.

**Revisão técnica formal de 05/11:** [parecer e matriz detalhada](m1-change-a-formal-evidence-review-20261105.md). **9/9 alertas FIM Indexer/Discover** em `002/004/005`; 10 fontes privadas de evidência verificadas e hashes SHA-256 preservados. CI #133 **3/3 SUCCESS**. O manifesto pós-change registra como pendente apenas `manager_ingestion`; revisor independente continua ausente. **Aceite global não concedido, rollback preservado, `DEPLOYMENT_GATE=BLOCKED` e M1 11/17**.

**Consolidação de 05/11, ~14h15 BRT:** [evidência real FIM `002`, `004`, `005` no Indexer/Discover](m1-change-a-three-agent-fim-evidence-20261105.md): **9 alertas (3/3 agentes × criação, alteração e exclusão)**. O `005` foi testado localmente com autenticação autorizada e teve limpeza verificada; o `004` possui diário local, três hits no Discover e limpeza confirmada. Configuração A manteve hash esperado e três agentes ativos. **Ainda falta conferência direta do log Manager e revisão independente.** Nenhum replay nem teste ativo foi repetido na nova janela 14h12–14h42. M1 **11/17**, `DEPLOYMENT_GATE=BLOCKED` intencional e rollback preservado.

**Segunda janela de teste FIM aprovada — 05/11, 13h55min48s–14h25min48s BRT:** [relatório sanitizado](m1-change-a-second-authorized-fim-window-20261105.md). Windows `004`: teste com arquivo de dados inerte, CREATE/MODIFY/DELETE e limpeza **PASS**; Discover confirmou **3 eventos reais com mesmo agente e artefato, `added=1`, `modified=1`, `deleted=1`**. Agente Linux `002` já comprovado no Indexer/Discover. Linux `005` exige `sudo` local e está aguardando autenticação legítima; **nenhum bypass realizado**. Manager direto e revisão independente pendentes, `DEPLOYMENT_GATE=BLOCKED` e **M1 11/17**; janela com término definido às 14h25min48s.

**Conferência adicional pós-change (05/11, leitura):** [agente `004` com 35 documentos de FIM de Registro do Windows, mas 0 arquivos após excluir `HKEY*`; agente `005` com 0 FIM nas últimas 24h e sem teste ativo](m1-change-a-benign-fim-test-20261105.md). A ausência não comprova falha; `002` confirmou 3 eventos FIM reais no Indexer/Discover. **Manager direto e cobertura real de arquivos no `004/005` continuam pendentes**. M1 **11/17**, gate **BLOCKED**, rollback preservado.

**Descoberta de telemetria FIM pós-cutover (05/11, ~13h49 BRT):** [três registros reais `added`/`modified`/`deleted` do teste benigno `002` no `wazuh-alerts-*`/Discover](m1-change-a-benign-fim-test-20261105.md), com mesmo agente/caminho do artefato. **Indexer e Discover do 002 comprovados**; conferência direta do log de alertas no Manager, teste Linux 005 e evento Windows 004 **pendentes**. Janela de teste encerrada às 13h48min53s (sem novos testes ativos). Rollback preservado; **M1 11/17, gate BLOCKED**.

**Teste pós-cutover autorizado — 05/11, 13h22 BRT:** [relatório de execução FIM benigna](m1-change-a-benign-fim-test-20261105.md). No agente Linux `002`, as operações de criação/modificação/exclusão de arquivo descartável no diretório isolado **passaram**, e a limpeza/ausência do arquivo foi confirmada. Agentes 3/3 ativos e hash da mudança A intacto após o teste. Agente `005` **não testado** (diretório root-owned e escrita não autorizada para a conta remota); sessão gráfica Kali bloqueada, sem autenticação indevida. **Não há ainda verificação de alerta end-to-end no Manager → Indexer → Discover. M1 11/17; gate BLOCKED; rollback preservado.**

**Retomada 05/11/2026, ~13h BRT:** [checklist pós-mudança A](m1-change-a-postresume-observability-plan-20261105.md). VMs Kali/Wazuh e Windows Server saíram de `saved` para execução; Manager/Indexer/Dashboard ativos; agentes `002/004/005` **3/3 synchronized**; hash/parser da mudança A íntegros, rollback preservado. Clock Kali ~22s adiantado, sem ajuste. **224 testes offline OK (4 skipped)**. Não foi obtida prova de mesmo evento FIM pós-cutover no Manager/Indexer/Discover; acesso remoto aos alertas brutos bloqueado e não contornado. M1 **11/17**, gate de implantação **BLOCKED**; nenhuma alteração operacional adicional.

**Checkpoint de encerramento — 05/11/2026, 01h22 BRT:** [handoff completo da mudança A](m1-change-a-cutover-postcheck-handoff-20261105.md). **Cutover executado às 00h42** após GO explícito e janela antecipada autorizada; hash, parser, metadados e backup preservados; **3/3 agentes ativos/sincronizados**. Dashboard verificado por agente: Windows `004` 6 diretórios sem caminho Unix; Linux `002/005` 7 diretórios cada com FIM realtime Unix; `005` ainda exibe fonte `localfile` syslog. **Somente aceite do escopo exibido**, não de novos eventos Manager → Indexer → Discover. `DEPLOYMENT_GATE=BLOCKED` (proteção do gate), **M1 11/17**, PR #25 aberto, rollback retido. Jornada de 04/11 (13h11) até 05/11 (01h22), **12h11 decorridas com pausas desconhecidas**, atribuída ao dia contábil 05/11 sem duplicar em 04/11. Work paused.

**Checkpoint FIM 005 (04/11, ~22h52–22h55 BRT):** [Dashboard General/Monitored/Ignored do agente `005` verificado, sete diretórios, FIM realtime em `/opt/wazuh-lab/monitorado`, nenhuma exclusão para essa pasta; existência física confirmada em `002` e `005`](m1-agent005-fim-ignored-and-path-checkpoint-20261104.md). Consulta delimitada indica possível desvio de relógio Kali ~+22 s em relação ao host; investigar antes de validar correlação temporal. **Configuração e caminho confirmados, telemetria real ainda pendente; M1 11/17, gate BLOCKED.**

**Pré-gate A (04/11, ~22h35 BRT):** [parser oficial Wazuh da candidata PASS, hash ativo preservado e arquivos temporários removidos; GitHub Actions 3/3 SUCCESS para SHA `73d50b3`](m1-change-a-parser-ci-20261104.md). O Manager exibe três agentes ativos no grupo `default`. A reconfirmação individual da sincronização foi bloqueada na sessão atual; a evidência anterior continua datada. **FIM local do `005` exige conferência autorizada; GO operacional não recebido, `DEPLOYMENT_GATE=BLOCKED`.**

**Governança de autoavaliação (04/11, ~22h26 BRT):** [exceção individual da mudança A ratificada pelo proprietário](m1-change-a-solo-owner-review-exception-20261104.md), [Issue #31 e declaração expressa](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/31#issuecomment-6647042764). Cinco riscos específicos aceitos, **sem revisão de terceiro nem autorização de implantação**. Controles técnicos e gate preservados: `DEPLOYMENT_GATE=BLOCKED`, **M1 11/17**.

**Checkpoint adicional — 04/11/2026, ~22h17 BRT:** [staging privado da mudança A com arquivo real do Manager, diff mínimo byte a byte, testes de recusa e checklist manual](m1-change-a-staging-and-manual-gates-20261104.md). Original 221 bytes, candidata 233 bytes, `os="^Linux"` como única diferença; FIM realtime e `localfile` Linux preservados. Hash do Manager inalterado. **O parser oficial da candidata ainda não foi validado** (entrada `/dev/stdin` recusada, sem modificar o container). Janela de 05/11 18h–19h aprovada condicionalmente; **gate operacional BLOCKED**. Os checkpoints anteriores mantêm seus resultados e datas.

**Checkpoint mais recente — 04/11/2026, ~22h03 BRT:** [revisão 3/3, precedência por OS, baseline, recuperação isolada e janela de 05/11 aprovada condicionalmente pelo proprietário](m1-fim-three-agent-prechange-approval-proposal-20261104.md) ([registro da aprovação](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17#issuecomment-6646704047)); **sem GO operacional**, gate continua BLOCKED. A [retomada pós-Codex](m1-codex-continuation-20261104.md) permanece registrada. O grupo `default` foi reconfirmado com `002`, `004` e `005` **ativos e sincronizados**; `001` não consta e `003` está fora do grupo. O contrato de três agentes passou na validação estrutural, o manifesto `.lab/` foi atualizado com backup prévio (evidência ainda **não atestada independentemente**), e o parser central retornou `OK`. **210 testes passaram, 4 pulados, 160 subtestes passaram; GitHub Actions #104: success, commit `a137c51`. M1 11/17; `DEPLOYMENT_GATE=BLOCKED`.** Os checkpoints antigos abaixo mantêm a data original e não representam o estado atual.

**Checklist e gate reconferidos em 04/11/2026, 13h17 BRT.** A conectividade de diagnóstico com o Kali não pôde ser renovada nesta passagem; dados de telemetria abaixo mantêm as datas originais de observação. Ver [reconciliação read-only de 04/11](m1-readonly-reconciliation-20261104.md).

**Leitura adicional (relógio do Kali 11h23, ainda não normalizado):** o Dashboard Wazuh voltou a carregar o Ruleset (4.523 regras). As regras FIM de arquivo `550`/`553`/`554` foram verificadas nos níveis 7/7/5; as regras de Registro `594`/`597`/`598` e `750`/`751`/`752`, todas no nível 5. Isso não comprova um evento do `004` nem altera o gate. O SSH pelo host continua indisponível; os metadados locais de archives foram verificados depois, no checkpoint abaixo.

**Checkpoint do Manager em 16:32 UTC:** `alerts.json` estava atualizado, com `jsonout_output=yes` e `log_alert_level=3`. `logall_json=no`; `archives.json` existia, mas sua última modificação era de 01/11 e `archives.log` estava vazio. Portanto archives não é fonte atual de evidência nesta janela; nenhuma configuração foi alterada.

**Agregação local ativa:** `archives.json` e `alerts.json` retornaram zero `syscheck.path` do `004`, separadamente para Registro e arquivos, sem linhas JSON inválidas. A conclusão limita-se aos arquivos locais ativos, que podem ter rotacionado; não contradiz a consulta histórica do Indexer nem conclui ausência de FIM.

**Inventário de rotação:** os padrões dos três logs retornaram somente os arquivos ativos; não havia cópias rotacionadas ou comprimidas acessíveis no Manager. O recorte histórico de sete dias permanece verificável somente no Indexer observado, sem alteração de retenção ou logs.

**Checkpoint renovado do `004`:** o Manager retornou agente sincronizado e `verify-agent-conf` aprovou o `default/agent.conf`. Isso é uma validação sintática e de sync, não confirma hash, distribuição efetiva ou cobertura FIM em runtime.

**Grupo central atual:** após autorização explícita do operador, o cadastro legado `001` foi removido. A verificação sanitizada posterior confirmou `AGENT_001_REGISTERED=False`; `default` contém `002`, `004` e `005`, todos ativos e sincronizados. O `003` continua `never_connected`, fora do `default`. A mudança real de três membros não altera silenciosamente o contrato original 4/4: faltam OS/versão e ordem dos grupos, além da revisão independente da emenda de escopo; o gate segue bloqueado.

> **Fonte da contagem:** caixas de seleção do [ROADMAP.md](../ROADMAP.md), não percentuais de segurança, de produtividade, de CI ou de implantação. Conferir a contagem atualizada com `python scripts/roadmap_progress.py`. Evidência de runtime, aprovação humana e change control são requisitos separados.

## Visão resumida

| Trilho | Estado | Contagem | Evidência/limite |
| --- | --- | --- | --- |
| **Fases históricas 1–6** | **Concluídas no roadmap original** | **8/8 entregas** e **6/6 fases** | [Issues #1–#8](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues?q=is%3Aissue+is%3Aclosed), todas encerradas em 26/10 ou antes |
| **M1 — Threat Hunting por hipóteses** | **Em andamento** | **15/17 marcados (88,2%); 2 pendentes** | Mudança 4698 comprovada no Windows/Indexer/Discover; correlação real completa e revisão independente ainda abertas |
| **CI e contratos offline M1** | **PASS local em 04/11** | **210 testes aprovados, 4 pulados, 160 subtestes aprovados; Actions #104 SUCCESS, commit `a137c51`** | A aprovação de testes sintéticos não prova evento real nem autoriza deploy |
| **Revisão/merge do código M1** | **Pendente** | PRs [#24](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/24) e [#25](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/25) abertos, sem review formal | `main` sem esses commits; proteção de `main` pendente na [Issue #26](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/26) |
| **Mudança A — FIM por OS no Manager** | **Cutover aplicado; validação pós-change incompleta** | `002/004/005` 3/3 sincronizados; FIM configurado por OS exibido conforme esperado no Dashboard | [Handoff 05/11](m1-change-a-cutover-postcheck-handoff-20261105.md): não há ainda mesma identidade de evento novo no Manager, Indexer e Discover; rollback preservado; gate automático continua BLOCKED |
| **Jornadas de 03 e 05/11** | Registro particular de tempo | 03/11: 6h00 conforme checkpoint anterior. 05/11: janela 04/11 13h11 → 05/11 01h22, total decorrido 12h11, com pausas não apuradas | Horas corridas ≠ horas líquidas; transferência contábil para 05/11 sem duplicação do dia 04 |

```text
Laboratório original  ████████████████████  8/8 entregas documentadas
M1 checklist          ██████████████████░░ 15/17 (88,2%)
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

## M1 — 15 itens marcados e duas entregas ainda abertas

| Prioridade | Pendente no checklist M1 | Dependências e critério |
| --- | --- | --- |
| **1** | Correlacionar H01/H02/H03 em eventos reais completos | Mesmos ativos/atores/artefatos e janelas, evidência Manager → Indexer → Discover, controle negativo e interpretação humana; [Issue #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9) |
| **2** | Encerrar M1 com revisão independente e evidência sanitizada | PRs revisados por terceiro habilitado, aprovação documentada e critérios técnicos satisfeitos; [Issue #26](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/26) |

A relação acima **reordena os dois itens pendentes por dependência operacional**; não altera o checklist do [ROADMAP.md](../ROADMAP.md).

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

1. **Revisor independente / responsável:** registrar a remoção autorizada de `001` e aprovar ou rejeitar uma emenda explícita ao contrato 4/4 para o novo escopo de três agentes. Depois, renovar a coleta de status/sync, OS e grupos na ordem dos três membros atuais. Manter capturas privadas em `.lab/`; a aprovação da emenda não autoriza a mudança FIM. Ver [Issue #27](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/27).
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
