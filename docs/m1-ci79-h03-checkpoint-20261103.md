# M1 — checkpoint CI #79 e validação H03 (03/11/2026)

**Escopo:** atualização documental sem alteração operacional. Os testes H03 neste checkpoint são sintéticos e não constituem evidência de incidente ou de cobertura ponta a ponta.

## CI verificado

- Commit `ce557d4` na branch `feat/m1-readiness-gate-fail-closed`.
- Workflow GitHub Actions `Validate lab configuration`, execução **#79**, concluído com **success**.
- Jobs concluídos com **success**: `Validate Wazuh lab artifacts`, `M1 synthetic hunting contracts (ubuntu-latest)` e `M1 synthetic hunting contracts (windows-latest)`.
- Suíte local após os três testes adicionais: **202 tests passed, 160 subtests passed**, sem falhas.
- Novos controles sintéticos H03: rejeitar artefatos diferentes no mesmo ativo, rejeitar execução anterior à alteração e rejeitar intervalo superior a 20 minutos.

## Limitações que não mudaram

- Descoberta autenticada de Syscheck do agente Windows `004`: **488 hits em uma janela móvel de 24h** no checkpoint anterior. Filtros adicionais apontaram registros de Registro do Windows; não foi comprovado um par de arquivo alterado e arquivo executado.
- A consulta histórica de sete dias para arquivos continua **não verificada**; a tela do Kali estava preta na captura mais recente, embora a VM permanecesse ligada.
- Inventário completo dos quatro agentes, precedência, recuperação operacional e revisão independente continuam pendentes. `M1_CHECKLIST=11/17`, `HUMAN_REVIEW_VERIFIED=false`.
- Gate prechange reexecutado: `EVIDENCE_SOURCE=PRIVATE_UNATTESTED`, `EVIDENCE_COMPLETENESS=INCOMPLETE`, `DEPLOYMENT_GATE=BLOCKED`.

## Próximo trabalho autorizado

1. Reabrir o Discover com sessão legítima, confirmar o mapeamento de `syscheck.path` e comparar a janela histórica de sete dias em modo somente leitura; registrar total e fuso.
2. Se houver caminho de arquivo verdadeiro, conferir privadamente asset, caminho/hash e linha do tempo com Sysmon 1; sem produzir evento sintético no endpoint.
3. Não alterar `agent.conf`, auditoria 4698, serviço ou grupo do Wazuh até autorização de mudança e aprovação do gate.

**Estado:** CI aprovado; detecção H03 real **INCONCLUSIVE**; deploy **BLOCKED**.
