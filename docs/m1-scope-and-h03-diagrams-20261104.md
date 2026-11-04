# M1 — escopos, arquitetura de evidências e fluxos H03

**Atualização:** 04/11/2026 (BRT). **Natureza:** documentação do laboratório autorizado e plano fail-closed; **não** é autorização de mudança, execução de teste ou declaração de incidente.

## 1. Situação do roadmap

- Fases históricas: **6 fases** e checklist **8/8** concluídos.
- Marco M1 (Threat Hunting): **11/17 (64,7%)** por `scripts/roadmap_progress.py`; **6 itens pendentes**.
- `DEPLOYMENT_APPROVED=false`, `HUMAN_REVIEW_VERIFIED=false`, `EVIDENCE_COMPLETENESS=INCOMPLETE`, `DEPLOYMENT_GATE=BLOCKED`.
- CI e testes sintéticos validam contratos de código; **não substituem** cobertura efetiva nem aprovação independente.

```mermaid
flowchart TD
  A["Laboratório Wazuh / Blue Team"] --> H["Fases históricas 1–6: concluídas"]
  H --> M["M1: 11/17 — em andamento"]
  M --> F["Inventário agentes e cobertura FIM 004"]
  M --> C["H01/H02/H03: pares de eventos reais"]
  M --> R["Revisão PRs e aprovação humana"]
  F --> L["Mudança Linux OS-scoped — proposta"]
  F --> W["Auditoria 4698 — mudança independente"]
  L --> G{"Gate específico aprovado?"}
  W --> G
  C --> E["Evidência + controles negativos"]
  E --> R
  R --> G
  G -->|"não: situação atual"| B["BLOCKED / NO-GO"]
  G -->|"sim, após revisão e janela"| V["Validação operacional controlada"]
  V --> Z["Reavaliar M1"]
```

## 2. Arquitetura e limites das evidências H03

```mermaid
flowchart LR
  A["WindowsServer: Wazuh agent 004"] --> L["FIM local: 5 periódicos / 1 realtime"]
  A --> S["Sysmon: Event ID 1"]
  C["default/agent.conf: diretiva Linux UnixStyle"] -.->|"sincronizada; não cobre arquivo Windows"| A
  L --> M["Wazuh Manager: syscheck alert"]
  S --> M
  M --> I["Indexer: wazuh-alerts-*"]
  I --> D["Dashboard / Discover"]
  M -.->|"logall_json=no; archive local não atual"| X["archives.json (não é fonte completa)"]
  D --> H["H03: arquivo alterado → mesmo binário executado"]
  H --> Q{"Mesmo ativo + artefato + ordem + até 20 min?"}
  Q -->|"não ou faltam provas"| N["INCONCLUSIVE"]
  Q -->|"sim e originais revisados"| P["Candidato para revisão humana"]
```

**Limites:** o agente `004` está ativo, sincronizado e com varredura Syscheck registrada em 04/11, mas não há par operacional FIM de arquivo + Sysmon 1 verificado. O bloco central Linux é inaplicável ao Windows; isso **não prova** desativação das seis entradas locais. Eventos FIM de Registro históricos **não** são evidência de alteração de arquivo.

## 3. Gate de cobertura do artefato e teste benigno

```mermaid
flowchart TD
  A["Escolher executável benigno descartável"] --> B{"Dentro de regra FIM local, sem ignore/restrict?"}
  B -->|"não ou incerto"| N["NO-GO: reavaliar o escopo"]
  B -->|"sim"| C{"Modo de detecção?"}
  C -->|"periodic 12h"| D["Latência potencial >20min: rever plano"]
  C -->|"realtime"| E["Confirmar Sysmon ID 1 do próprio binário"]
  D --> E
  E --> F{"Aprovação específica + janela + rollback + baseline?"}
  F -->|"não"| N
  F -->|"sim"| G["Uma alteração benigna aprovada + execução"]
  G --> H["Confirmar FIM arquivo + Sysmon 1 nas origens"]
  H --> I{"Mesmo ativo/objeto; FIM anterior; até 20 min?"}
  I -->|"não"| N
  I -->|"sim"| J["Correlacionar Manager → Indexer → Discover"]
  J --> K["Controle negativo + revisão humana"]
  K --> L["Documentar evidência sanitizada, sem declarar incidente automaticamente"]
```

**Não executar agora:** nenhuma seleção de artefato específico, geração de arquivo, execução de amostra, força de varredura, alteração de `syscheck`, modificação de `auditpol`, reinício ou implantação está autorizada pelo progresso documental. Caminhos, hashes, usuários, eventos brutos e credenciais permanecem exclusivamente na área privada `.lab/`.

## 4. Delimitação dos change requests

| Trilha | Escopo permitido antes de aprovação | Pré-condições da mudança |
| --- | --- | --- |
| H03 | Revisão de cobertura local, exclusões, tempos e fontes, sem gerar eventos | Executável benigno e diretiva identificados; aprovação para alterar/executar; janela, rollback e validação de duas fontes |
| Linux FIM `os="^Linux"` | Proposta, parser em cópia isolada, revisão de agentes afetados | Inventário 4/4, decisão agente histórico `001`, revisão independente, backup, rollback, janela e aprovação específica |
| Windows Security `4698` | Baseline `auditpol /get`, revisão de coletores Security e retenção | Change request próprio; 20 MiB Security analisados, rollback, teste benigno e comprovação de ingestão |
| M1 PR/CI | Testes, revisão documental, CI e controle de evidências | Revisão independente e fonte real verificável; CI verde não é aprovação operacional |

## 5. Referências rastreáveis

- [Reconciliação efetiva FIM do agente 004](m1-agent004-effective-fim-reconciliation-20261104.md)
- [Pré-gate H03 de cobertura de artefato](m1-h03-artifact-coverage-preflight-20261104.md)
- [Contrato H01/H02/H03](m1-three-hunting-hypotheses.md)
- [Pacote FIM Linux](m1-fim-change-approval-package.md)
- [Change control Windows 4698](m1-change-control-4698-fim-agent004.md)
- [Painel do roadmap](roadmap-progress.md)
- Issues: [H03 #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9), [4698 #15](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15), [FIM Linux #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17), [agente 001 #27](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/27).

**Resultado:** artefato H03 não selecionado, cobertura do artefato não validada, teste não executado, H03 `INCONCLUSIVE`, gate `BLOCKED`. O desenho ilustra contratos e etapas, não telemetria real validada.
