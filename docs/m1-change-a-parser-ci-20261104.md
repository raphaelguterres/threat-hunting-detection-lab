# M1 — mudança A: parser oficial, CI e limites do gate (04/11/2026)

**Change ID:** `M1-FIM-OS-SCOPE`

**Decisão:** `NO-GO / DEPLOYMENT_GATE=BLOCKED`. **Nenhuma alteração aplicada no `default/agent.conf` ativo, agentes, grupos ou serviços.**

## Validações concluídas nesta passagem

| Evidência | Resultado | Limitação |
| --- | --- | --- |
| Candidata de `agent.conf` | 233 bytes, alteração byte a byte única na abertura do bloco: `os="^Linux"` | Preparada em pasta privada `.lab/`, não aplicada |
| Parser oficial Wazuh 4.14.9 da candidata | **`verify-agent-conf: OK`, exit 0** | Validação sintática, não distribuição nem cobertura real |
| Método do parser | Arquivo temporário exclusivo no contêiner Manager; cópia temporária no host Kali | **Não** foi escrito `/var/ossec/etc/shared/default/agent.conf` |
| Integridade do arquivo ativo | SHA-256 antes/depois igual ao backup real DPAPI registrado | Hash mantido privadamente, não publicado |
| Limpeza do staging temporário | Remoção no Manager: exit 0; remoção no Kali: exit 0 | Script privado `.lab/m1-change-prep/M1_STAGE_PARSER_TRANSIENT_20261104.ps1` |
| CI do PR #25 no commit `73d50b3` | **3/3 jobs success**, Ubuntu, Windows e validação dos artefatos Wazuh | [GitHub Actions run](https://github.com/raphaelguterres/threat-hunting-detection-lab/actions/runs/41948975719) |
| CodeRabbit no PR #25 | **SKIPPED** | Não conta como aprovação nem review |
| Status da PR #25 | **OPEN**, sem revisão independente submetida | A exceção individual da mudança A foi ratificada apenas pelo proprietário na Issue #31 |
| Agentes no Manager | `002`, `004` e `005` mostrados como **Active**; grupo `default` com **3 membros** | Consulta de sincronização individual foi bloqueada nesta rodada; sincronização permanece confirmada apenas no checkpoint anterior |
| Manager, Indexer, Dashboard e agente Linux em Docker | Contêineres **Up** | Estar em execução não demonstra ingestão ou eficácia das detecções |

### Resultado exato da validação com o parser

```text
PARSER_RESULT=verify-agent-conf: OK
PARSER_EXIT=0
OFFICIAL_PARSER_STAGED_CANDIDATE=PASS
LIVE_MANAGER_CONFIG_HASH_UNCHANGED=TRUE
CHANGE_A_DEPLOYED=FALSE
DEPLOYMENT_GATE=BLOCKED
CONTAINER_TMP_REMOVAL_EXIT=0
KALI_TMP_REMOVAL_EXIT=0
ACTIVE_CONFIGURATION_WRITE_PERFORMED=FALSE
```

O procedimento é deliberadamente **não implantador**. O parser requer arquivo real (não aceita `-f /dev/stdin` na versão atual), então a cópia foi validada em caminho temporário distinto do arquivo central ativo. Os arquivos temporários foram removidos e a baseline permaneceu idêntica.

## O que o `DEPLOYMENT_GATE=BLOCKED` significa

`scripts/m1_evidence_gate.py` é um validador **fail-closed e não autorizador**. O comando continua emitindo `DEPLOYMENT_GATE=BLOCKED` mesmo que o manifesto alcance completude documental: é necessário **GO externo e explícito** depois de revisão de evidências. Não editar o código ou marcar `checks.*.status=verified` por presunção para mudar o resultado.

A última consulta ao manifesto privado ainda apresentou `EVIDENCE_COMPLETENESS=INCOMPLETE` e nove checks sem atestado no formato exigido. O parser agora está **PASS em evidência técnica real**, mas o campo `parser_staging` não foi promovido automaticamente no manifesto, porque atestado e medição são atos distintos.

## Pendências concretas antes da execução de A

1. **Manual/autorizado:** revisar a configuração local FIM do agente Linux `005`. A conta remota atual **não** tem acesso ao arquivo `ossec.conf`; não usar elevação ou outra rota para contornar permissão. A configuração local do `002` tem dois caminhos FIM, sem realtime local; `004` permanece Windows e não é escopo de mudança de diretório.
2. **Manual:** confirmar inventário `002/004/005`, impacto de filtrar todo o bloco central (FIM **e** `localfile` Unix), preservar configuração local Windows e aceitar a revisão de precedência por SO.
3. **Técnico em janela:** repetir baseline/hash/UID/GID/mode, saúde dos componentes, sincronização, integridade DPAPI e disponibilidade real de rollback. Se esses checks não puderem ser realizados, **NO-GO**.
4. **Manual:** obter **GO operacional distinto** da autorização condicional da janela. A aceitação dos cinco riscos via [Issue #31](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/31#issuecomment-6647042764) dispensa apenas o segundo revisor organizacional na mudança A, não valida o ambiente automaticamente.
5. **Pós-mudança futura autorizada:** verificar a seleção real da diretiva Linux em `002/005`, a remoção da diretiva Unix para `004` e a cadeia **FIM → Manager → Indexer → Dashboard/Discover** com evidências atuais. Não declarar H03, alteração `4698` ou correlação real concluídos antes da prova.

**Janela condicional:** 05/11/2026, 18h–19h BRT. Lembrete dos pré-checks às 17h45. A janela não inicia implantação automaticamente.

## Referências

- [M1 — staging seguro e pendências manuais](m1-change-a-staging-and-manual-gates-20261104.md)
- [M1 — exceção individual ratificada para A](m1-change-a-solo-owner-review-exception-20261104.md)
- [M1 — inventário e baseline reais](m1-fim-three-agent-prechange-approval-proposal-20261104.md)
- [Issue #17 — alteração controlada Linux](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17)
- [PR #25 — revisão e CI](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/25)

**M1 permanece 11/17 (64,7% dos itens do checklist, não prontidão operacional).**
