# M1 — Continuação remota após Codex (04/11/2026)

**Checkpoint:** 04/11/2026, ~21h26–21h35 BRT. **Escopo:** laboratório Wazuh 4.14.9, branch \`feat/m1-readiness-gate-fail-closed\`. Estado do Manager e agentes observado por CLI **somente leitura** autorizada; configuração ativa **não modificada**. Inventário privado renovado na pasta ignorada \`.lab/\`, sem publicação de hostnames, IPs, hashes ou logs.

## 1. Onde o Codex parou

No início da retomada, o repositório local estava limpo no commit \`a137c51\`, com as VMs Kali e Windows Server executando. Três commits de 04/11 ainda não tinham sido enviados ao GitHub:

| Commit | Entrega |
| --- | --- |
| \`619c857\` | Registro de descomissionamento administrativo do agente histórico \`001\` |
| \`0a37975\` | Proposta de emenda do inventário \`default\` para três agentes |
| \`a137c51\` | Alteração do validador, importador, prévia Linux, documentos e testes para \`002\`, \`004\`, \`005\` |

Os três commits foram **publicados por fast-forward**, sem reescrever histórico. A branch remota passou de \`c73f3b5\` para **\`a137c51\`**.

### Qualidade de código

- **Suíte completa local:** \`210 passed, 4 skipped, 160 subtests passed\`.
- **Testes específicos do contrato de três agentes:** \`83 passed, 3 skipped, 102 subtests passed\`.
- **Higiene de patch:** \`git diff --check c73f3b5..a137c51\` passou.
- **GitHub Actions:** \`Validate lab configuration\` **#104 — success** para o commit \`a137c51\`.
- Nenhum teste sintético foi apresentado como prova de mudança real no endpoint.

## 2. Inventário operacional observado, somente leitura

O Manager exibiu um único grupo \`default\` com **3 membros**. As consultas \`agent_control -l\`, \`agent_control -i\`, \`agent_groups -l\`, \`agent_groups -s -i\` e \`agent_groups -S -i\` foram feitas sem editar o servidor.

| ID | Família SO | Status | Grupo declarado | Sync | Observação |
| --- | --- | --- | --- | --- | --- |
| \`002\` | Linux | \`Active\` | \`default\` | \`synchronized\` | Versão do SO registrada privadamente |
| \`004\` | Windows Server 2022 | \`Active\` | \`default\` | \`synchronized\` | Agente da hipótese H03 |
| \`005\` | Linux | \`Active\` | \`default\` | \`synchronized\` | Versão do SO registrada privadamente |
| \`003\` | Windows (cadastro) | \`Never connected\` | \`Null\` | Não se aplica | **Fora** do grupo, não integra o contrato aprovado |
| \`001\` | Histórico | Cadastro ausente | — | — | Remoção observada, **não** refazer o descomissionamento |

Todos os agentes atuais \`002\`, \`004\` e \`005\` reportaram Wazuh v4.14.9. A leitura de \`default/agent.conf\` via \`verify-agent-conf\` retornou \`OK\`, o que **não** comprova seleção do regex por runtime, cobertura FIM efetiva ou ausência de impacto em produção.

## 3. Manifesto privado renovado (sem forçar atestado)

A versão anterior do manifesto \`.lab/m1-evidence.json\` ainda continha quatro agentes. Foi preservada em uma **cópia privada com timestamp** e substituída usando o importador oficial do próprio repositório, com os três dados realmente observados.

Artefatos privados (não versionar):
- \`.lab/m1-inventory-manager-readonly-20261104.json\`: observações autorizadas, com sistema operacional/versão, fuso, status, grupo e fonte;
- \`.lab/m1-agent-inventory-manager-readonly-20261104.csv\`: 3 registros para o contrato atualizado;
- \`.lab/m1-capture-manager-readonly-inventory-20261104.ps1\`: rotina de captura por leitura, sem alterar Manager/Indexer;
- \`.lab/m1-evidence-before-three-agent-refresh-*.json\`: cópia da versão anterior do manifesto;
- \`.lab/m1-evidence.json\`: versão atualizada somente após validação estrutural.

**Resultados:**
\`\`\`text
CSV_STRUCTURE=VALID
MANIFEST_UPDATED=True
AGENTS_IN_PRIVATE_MANIFEST=3
INVENTORY_CSV_STRUCTURE=VALID
AGENTS_IN_DEFAULT=3
PROJECTED_LINUX_FAMILY_AGENTS=2
PROJECTED_NON_LINUX_FAMILY_AGENTS=1
AGENT_CONFIG_OS_REGEX_CHECKED=false
WAZUH_RUNTIME_SELECTION_CONFIRMED=false
EVIDENCE_SOURCE=PRIVATE_UNATTESTED
EVIDENCE_COMPLETENESS=INCOMPLETE
DEPLOYMENT_GATE=BLOCKED
\`\`\`

A prévia do seletor \`^Linux\` é **hipotética**, baseada em família de SO exibida no Manager, e **não equivale a teste de runtime no Wazuh**. A coleta CLI read-only permanece sujeita à revisão da evidência e às exigências do contrato humano original; nenhum \`checks.*.status\` foi promovido artificialmente para \`verified\`. O importador reverte automaticamente checks dependentes quando o inventário muda.

## 4. Progresso do roadmap e gates abertos

\`\`\`mermaid
flowchart TD
  B["Fases históricas 1–6: 8/8 entregas"] --> M["M1: 11/17 · 64,7%"]
  M --> I["Inventário atual 3/3 · observado e importado em .lab"]
  I --> R["Revisão humana do inventário + precedência/impacto OS"]
  R --> G{"Aprovação, janela e rollback da mudança A?"}
  G -->|"não: estado atual"| X["DEPLOYMENT_GATE: BLOCKED"]
  G -->|"sim, após novos checks"| D["Mudança A Linux OS-scoped · validação controlada"]
  M --> C["Mudança C / H03 Windows: aprovações próprias"]
  C --> H["FIM de arquivo + Sysmon ID 1 real"]
  M --> W["Mudança B Windows 4698: change control próprio"]
  D --> F["Manager → Indexer → Discover + evidência"]
  H --> F
  W --> F
  F --> Z["Revisão de hipóteses, controles negativos e fechamento do M1"]
\`\`\`

**Checklist:** 11/17, sem novo item marcado nesta retomada. O gate de \`M1-FIM-OS-SCOPE\` permanece incompleto para: \`inventory_review\`, \`os_impact_review\`, \`group_precedence_review\`, \`baseline_integrity\`, \`parser_staging\`, \`backup_integrity_real\`, \`rollback_rehearsal_real\`, \`change_approval\`, \`approved_window\`.

**Aprovação de escopo \`M1-INVENTORY-SCOPE-3\`:** registrada no documento de emenda pelo próprio operador/revisor do laboratório, com limitação explícita de segregação; **não constitui revisão independente estrita** e não libera \`M1-FIM-OS-SCOPE\`.

**Change C / H03:** a exceção de autoavaliação individual para C foi ratificada pelo proprietário, com controles próprios, mas a pasta isolada não foi implantada nem o par FIM+Sysmon comprovado. **A janela condicional de 04/11 18h–19h BRT já terminou**; é necessária nova janela e gate para executar qualquer mudança ativa. Não reutilizar essa aprovação como autorização da mudança A ou B.

## 5. Próxima ação técnica segura

1. Revisar privadamente os três registros observados e atestar \`inventory_review\` por uma decisão explícita e rastreável, sem atribuir revisão independente fictícia.
2. Comparar precedência e diferenças entre \`ossec.conf\`, \`default/agent.conf\` e a configuração ativa de **cada SO**, guardando evidência sanitizada. O seletor \`os="^Linux"\` não foi aplicado.
3. Verificar baseline, backup real, ensaio de rollback, plano de alteração e janela **específicos da mudança A** antes de cogitar intervenção.
4. Tratar a mudança C/H03 e a auditoria Windows \`4698\` como trilhas independentes, com seus próprios gates.
5. Atualizar Issue #17, revisão de PR e checklist somente quando as evidências correspondentes forem revisadas e verificáveis.

**Este checkpoint é documental e de inventário privado.** Não houve alterações em agentes, regras, configurações Wazuh ativas, ACLs, serviços, VMs, arquivos de log ou índices.

### Referências

- [Emenda do inventário de três agentes](m1-inventory-scope-amendment-20261104.md)
- [Contrato do gate de evidências](m1-evidence-gate.md)
- [Roadmap](roadmap-progress.md)
- [Matriz FIM por OS](m1-fim-acceptance-matrix.md)
- [Mudança C e H03](m1-change-c-approval-cutover-package-20261104.md)
- [Issue #17 — FIM Linux](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17)
- [Issue #9 — H03](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9)
