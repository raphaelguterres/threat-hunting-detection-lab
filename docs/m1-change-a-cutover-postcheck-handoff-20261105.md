# M1 — encerramento da jornada e handoff da mudança A (05/11/2026)

**Status ao encerrar:** `M1-FIM-OS-SCOPE` implantada no laboratório isolado, com revisão da configuração por agente no Dashboard **3/3 conforme esperado**; **aceite operacional end-to-end ainda PENDENTE**. `EVIDENCE_COMPLETENESS=INCOMPLETE`, `DEPLOYMENT_GATE=BLOCKED` (bloqueio intencional do validador). **M1: 11/17**, sem mudança no checklist. O laboratório não foi reiniciado nem desligado pelo fechamento desta jornada.

## Mudança A — fatos observados

- O proprietário ratificou os riscos da autoavaliação para laboratório individual; **não houve revisão independente**. Autorizou a janela antecipada de **05/11, 00h21–01h21 BRT** e o **GO operacional explícito**. Janela original de 18h–19h substituída para esta execução.
- **Cutover registrado às 00h42 BRT:** somente `os="^Linux"` foi adicionado à tag de abertura de `agent_config` no grupo `default`. O seletor abrange **FIM realtime e `localfile` Unix**; fonte original de 221 bytes e candidata aprovada de 233 bytes.
- Hash do arquivo ativo conferido contra a candidata, proprietário/permissões/tamanho preservados, parser oficial **PASS**. Backup original DPAPI e cópia temporária de rollback no Manager preservados, com hash original conferido. **Sem restart**, sem alterações B/4698 e C/H03.
- Após a implantação, `002`, `004` e `005` foram observados **Active e synchronized (3/3)** no Manager; Manager/Indexer/Dashboard em execução.
- O CI do commit `79f81a4926d380492161b9bd81eb71b410cdb784`, workflow #116, teve **3/3 jobs SUCCESS** (incluindo Ubuntu e Windows). CI **não** comprova entrega operacional de alertas.

## Evidências visuais pós-cutover

- **Windows `004`:** FIM habilitado, **6 diretórios Windows** exibidos (incluindo Startup com `realtime=yes`), **sem o diretório Unix central** na lista. Não inferir ausência de todos os problemas FIM pela visualização.
- **Linux `002`:** **7 diretórios Linux** no Dashboard; diretório de laboratório presente com `realtime=yes`.
- **Linux `005`:** **7 diretórios Linux**, diretório de laboratório com `realtime=yes`; em **Log collection**, `localfile` Unix de laboratório permanece visível como `syslog`.
- Ao trocar o agente em uma aba aninhada, a interface reteve conteúdo anterior. Cada configuração foi reaberta antes de validar o conteúdo do agente selecionado. Capturas privadas mantidas em `.lab/`.

**Escopo da aprovação atual:** `UI_CONFIGURATION_SCOPE=PASS_3_OF_3`. **Não** há confirmação nova de FIM por eventos pós-mudança nem prova da mesma identidade em **Manager → Indexer → Dashboard Discover**. `POSTCHANGE_OPERATIONAL_ACCEPTANCE=PENDING`. Nenhuma simulação ou teste de evento foi executado neste fechamento.

## Controle de jornada

A pedido do proprietário, toda a sessão contínua iniciada às **13h11 de 04/11** é **atribuída administrativamente à jornada de 05/11**, preservando os horários civis reais. Marco de encerramento do apontamento: **05/11 às 01h22 BRT**.

| Horário civil | Tempo decorrido |
| --- | ---: |
| 04/11 13h11 → 05/11 00h00 | 10h49 |
| 05/11 00h00 → 05/11 01h22 | 1h22 |
| **Total de janela atribuído ao dia 05/11** | **12h11** |

Este é **tempo corrido decorrido**, **não horas líquidas comprovadamente trabalhadas**; pausas não foram quantificadas. O log privado guarda essa distinção. **Não duplicar essas 10h49 como horas atribuídas ao dia 04/11**. O histórico civil das ações mantém as datas originais.

## Handoff para a retomada após descanso

1. **Não executar novas alterações ativas fora da janela encerrada às 01h21 BRT**; revisar se será necessária nova janela e novo GO para qualquer ação operacional futura.
2. Conferir novamente a saúde dos agentes e sincronização **3/3**, parser, integridade do arquivo ativo, cópia original de rollback e backups DPAPI privados. **Não remover** rollback até aceite formal.
3. Com autorização apropriada e janela própria, validar evento FIM benigno seguro nos Linux `002/005` e ausência de regressão no Windows `004`; correlacionar registro pós-change por identidade e horário no Manager, Indexer e Discover, sem publicar IDs/logs privados. Verificar fonte `localfile` Unix sem gerar ruído.
4. Se ocorrer regressão comprovada, suspender testes e seguir o **rollback autorizado** com revalidação de hash/parser/sync; não presumir que parser/CI substituem runtime.
5. Atualizar manifesto privado apenas conforme evidências reais, executar gate novamente e registrar aceite ou pendências na [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17). O PR [#25](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/25) segue aberto, sem revisão formal independente; **não fazer merge automático**. Depois, continuar M1/H01–H03 e trilhas B/4698 e C/H03 mediante aprovações próprias.

**Referências:** [Issue #17 — cutover e verificações](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17#issuecomment-6649572755) · [Issue #31 — riscos da autoavaliação](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/31) · `.lab/m1-change-a-cutover-real-20261105-private.json` · `.lab/m1-change-a-postcutover-readonly-20261105-private.json` · `.lab/m1-change-a-ui-config-postcheck-20261105-private.json` (evidências **privadas**, não publicar).

**Regra de segurança:** sem credenciais, hashes completos privados, capturas de tela, alertas brutos, hostnames privados ou identificadores originais de evento no repositório público.
