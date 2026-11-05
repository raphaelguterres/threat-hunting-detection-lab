# M1 — pacote de aprovação para correção FIM por sistema operacional

**Mudança proposta:** restringir ao Linux um único bloco centralizado de `default/agent.conf` atualmente entregue também ao Windows. **Estado:** `NO-GO` — pacote de pré-mudança; sem implantação, sem solicitação de aprovação automática.

**Checkpoint atualizado (04/11, ~22h03 BRT):** [inventário 3/3, regex aplicada aos metadados reais dos agentes, hash e owner/mode conferidos, backup DPAPI e rollback isolado PASS, janela de 05/11 APROVADA CONDICIONALMENTE pelo proprietário](m1-fim-three-agent-prechange-approval-proposal-20261104.md). [Registro da autorização da janela — Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17#issuecomment-6646704047). **Não constitui aprovação para implantação nem revisão independente.**

**Atualização de evidências (03/11):** [checkpoint FIM 004, archives e dois gates de autorização](m1-fim-004-archives-and-approvals-checkpoint-20261103.md). O Indexer não listou índices `wazuh-archives-*` (HTTP 200, `[]`), as regras Syscheck efetivas seguem sem níveis comprovados, e o gate permanece `BLOCKED`. Este registro **não** é aprovação para modificar `default/agent.conf`.

## Por que a mudança é necessária

O Dashboard autorizado exibiu no agente Windows `004` diretivas de monitoramento de diretórios Unix (incluindo `/opt/wazuh-lab/monitorado`). Os agentes Linux nativos receberam a configuração correspondente; nos três agentes ativos a página Configuration exibia `SYNCHRONIZED`.

A correção mínima proposta é **somente** alterar a abertura do único bloco Linux existente, de `<agent_config>` para `<agent_config os="^Linux">`. O Wazuh suporta [seletores `os` no `agent.conf`](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html). A comparação contra o backup **real** protegido por DPAPI confirmou que o corpo do XML não muda; o comparador e o validador estrutural passaram. O parser oficial `verify-agent-conf` aceitou a proposta **em staging isolado, anteriormente**, mas ela **não foi implantada**.

**Limite:** validação sintática e do diff **não prova** qual string OS interna de cada agente combina com a regex, nem a preservação de alertas FIM em runtime.

## Evidências e estado pré-mudança

| Gate | Evidência verificada | Status |
| --- | --- | --- |
| A — integridade Manager | Checkpoint 03/11 19h46: parser ativo válido, hash da configuração atual igual à baseline privada; Windows `004` sincronizado | **PASS no momento da leitura** |
| B — saúde dos componentes | Kali acessível; Dashboard, Manager e Indexer com contêineres Docker **RUNNING**; HTTP sem credenciais 302/401 | Conectividade **PASS**, funcionalidade ponta a ponta não demonstrada |
| C — cópia de segurança | Backup real DPAPI com metadados SHA-256 e recuperação isolada de bytes; controle negativo de corrupção PASS | **PASS isolado**, não rollback operacional |
| D — escopo e distribuição | `001` foi removido formalmente; o contrato automatizado atual foi alterado para três membros (`002`, `004`, `005`) e o inventário recente foi coletado e importado privadamente | **PASS técnico 3/3**, mas revisão/atestado do inventário e aprovação da mudança operacional permanecem pendentes |
| E — análise de precedência | Dashboard mostra somente grupo central `default` na fotografia observada; coexistência da configuração FIM local Windows exige preservação | **Revisão independente pendente** |
| F — revisão do código | PR [#25](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/25) com testes e CI aprovados, **sem review formal de terceiro** | **PENDENTE** |
| G — controle da mudança | Janela 05/11 18h–19h BRT aprovada condicionalmente pelo proprietário; executor, revisão, rollback operacional, critérios de parada e autorização específica de execução ainda a confirmar | **PENDENTE — GO operacional não concedido** |

O [agente histórico 001](m1-legacy-agent-001-decision.md) foi removido após autorização expressa. A [emenda de escopo](m1-inventory-scope-amendment-20261104.md) foi aceita pelo próprio operador com limitação documentada de segregação e implementada no commit `a137c51`; o inventário técnico 3/3 foi renovado em 04/11. A aprovação de escopo **não substitui** a revisão do inventário, a análise de impacto, a aprovação específica para mudança FIM nem o gate. Não registrar uma revisão de terceiro inexistente.

## Pacote que o revisor deve examinar

1. **Baseline:** hash, parser, owner/group/mode da configuração real, data e evidência privada antes da janela. Revalidar imediatamente antes da aplicação, sem assumir que o checkpoint antigo continua válido.
2. **Diff:** confirmar apenas `os="^Linux"` no bloco central Unix; nenhuma mudança nos diretórios Windows, logs, auditoria `4698`, outros grupos ou XML não relacionado.
3. **Seleção:** atestar a correspondência do seletor com as informações internas de SO por mecanismo **autorizado** e a exclusão do Windows. A prévia por rótulo do Dashboard é hipotética, não resultado de execução real.
4. **Rollback operacional:** confirmar pessoa responsável, acesso, backup original recuperável, metadados owner/mode/hash e procedimento de restauração **aprovado**; o ensaio isolado não equivale a executar rollback no Manager.
5. **Janela e parada:** registrar responsável, janela em fuso local, duração de monitoramento, como perceber falha, e quem decide GO/NO-GO. Parar na primeira divergência de baseline, parser, distribuição, sync, telemetria ou autorização.
6. **Aprovação independente:** revisão formal do PR e aprovação da mudança operacional são dois controles distintos; nenhum pode ser inferido do outro.

## Critérios de aceite para uma futura execução autorizada

**Antes de aplicar** (todos obrigatórios):
- [ ] Atestado humano rastreável do inventário **3/3** e da limitação de segregação na [emenda de escopo](m1-inventory-scope-amendment-20261104.md), sem alegar revisão externa inexistente
- [ ] Inventário atual, com membros reais, sistema operacional, grupos em ordem, sync e evidência privada válida
- [ ] Baseline atual do Manager, parser oficial e checksum confrontados na mesma janela
- [ ] Escopo Linux e efeito sobre Windows revisados independentemente
- [ ] Backup e rollback **operacional** aprovados, com responsável identificado
- [ ] PR revisado por pessoa habilitada e CI no SHA aprovado
- [ ] Janela, critério de parada e autorização explícita para FIM assinados

**Após uma eventual mudança** (somente com aprovação):
- [ ] Manager continua válido e baseline da **nova** configuração registrado
- [ ] Agentes Linux ativos recebem a diretiva Linux e preservam FIM
- [ ] Windows `004` não recebe os diretórios Unix e mantém sua cobertura FIM local
- [ ] Eventos benignos autorizados de teste são verificados nos próprios agentes e, quando aplicável, pelo percurso **Manager → Indexer → Discover**
- [ ] Nenhuma regressão na ingestão, sincronização ou desempenho
- [ ] Anotações sanitizadas, revisão humana e conclusão registrada no GitHub

## Cartão de autorização (não preencher por suposição)

| Campo | Valor |
| --- | --- |
| Change ID | `M1-FIM-OS-SCOPE` |
| Owner / executor | **PENDENTE** |
| Revisor independente | **PENDENTE** |
| Janela (data, início, fim e fuso) | **05/11/2026, 18h00–19h00 BRT — APROVADA CONDICIONALMENTE PELO PROPRIETÁRIO** ([Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17#issuecomment-6646704047)); execução ainda NO-GO |
| Aprovação expressa para FIM | **NÃO RECEBIDA** |
| Plano de restauração operacional aprovado | **NÃO RECEBIDO** |
| Tratamento do agente histórico `001` | Remoção formal concluída; escopo 3/3 aprovado pelo proprietário com limitação de segregação; revisão/atestado humano de inventário pendente |
| Decisão atual | **NO-GO / NÃO IMPLANTAR** |

**Não são passos de execução:** este documento não contém credenciais nem altera o Manager. Nenhuma atualização de `agent.conf`, grupo, agente, contêiner ou política Windows foi realizada ao preparar este pacote.

Links: [matriz de aceite](m1-fim-acceptance-matrix.md), [runbook do inventário](m1-agent-inventory-operator-runbook.md), [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17), [Issue #26](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/26).
