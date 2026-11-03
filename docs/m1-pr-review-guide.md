# M1 — Guia de revisão independente do PR #25

**Estado:** solicitação de revisão, não um parecer de aprovação. **Atualizado:** 03/11/2026. **PR:** [#25 — M1 readiness / fail-closed](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/25).

> O PR é amplo: na consulta de 03/11, **26 arquivos**, cerca de **2.433 linhas adicionadas** e 52 removidas. Revisar por subsistemas ajuda a evitar um aceite apenas por CI verde. O PR [#24](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/24) é **separado e documental**, não deve ser confundido com o gate operacional.

## 1. Limite do trabalho e condições de veto

A branch contém **validações offline e documentação**, não uma implantação ativa no Manager. A aprovação de código deve verificar que nenhum script concede autorização de deploy, modifica agentes, reinicia componentes ou busca inventário individual por meios não autorizados.

- `DEPLOYMENT_GATE=BLOCKED` permanece obrigatório no gate de evidências, nos relatórios de impacto FIM e nos resumos de observação parcial.
- O inventário oficial dos **quatro membros reais do grupo `default`** não está confirmado. Uma listagem geral observou quatro IDs, mas mostrou **um endpoint desconectado** e não exibiu vínculo de grupo, ordem ou sincronização individual.
- Não aceitar `active` como sinônimo de `synced`; não converter `disconnected` em `active`; não usar dados sintéticos ou placeholders como evidência operacional.
- `os="^Linux"` do Wazuh usa **informações internas do agente**; a família Linux inferida do rótulo exibido no Dashboard é apenas um cenário hipotético.
- Manter **separadas** a revisão humana do PR, a proteção de `main` ([Issue #26](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/26)) e a autorização de mudança FIM ([Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17)) / auditoria Windows 4698 ([Issue #15](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15)).

## 2. Sequência de revisão recomendada

| Ordem | Subsistema | Código a ler | Verificações principais |
| --- | --- | --- | --- |
| A | **Confiabilidade da entrada privada** | `scripts/m1_import_authorized_inventory.py`, `scripts/m1_evidence_gate.py` | CSV 4/4, status ativo e sync separado, OS+versão, grupos sem duplicação e em ordem, timestamp com fuso/coerência, rejeição de placeholders e links simbólicos; conteúdo sempre sob `.lab/` |
| B | **Prévia FIM sem autorização** | `scripts/m1_fim_impact_preview.py`, `scripts/review_fim_scope_only.py`, `scripts/validate_fim_os_scope.py` | Apenas comparação estática, nenhuma mudança, nenhuma classificação de regex interna como comprovada; rejeitar mistura de plataformas e diff além do seletor Linux |
| C | **Observações incompletas** | `scripts/m1_observed_agents_triage.py` | Registrar `001` desconectado sem falsificar sync, timestamps ou grupo; contagens agregadas; `BLOCKED` mesmo para todos ativos na fixture |
| D | **Threat Hunting H01/H02/H03** | `scripts/hunt_correlations.py` | 4698 verdadeiro vs. comando `schtasks`; H02 exige identidade da conta; H03 usa mesmo artefato; ordem temporal, controle negativo e estado `insufficient_source_coverage` |
| E | **Contador e CI** | `scripts/roadmap_progress.py`, `.github/workflows/validate-lab.yml` | `11/17` é checklist documental, não readiness; testes e checks em Windows e Ubuntu; permissions mínimos |
| F | **Documentação e segurança operacional** | `docs/m1-agent-inventory-operator-runbook.md`, `docs/m1-agent-001-disconnection-triage.md`, `docs/m1-fim-acceptance-matrix.md`, `docs/m1-evidence-gate.md`, `docs/roadmap-progress.md` | Não publicar hosts, IPs, credenciais, evidências individuais, hashes privados ou nomes de pessoas; separar NO-GO de aprovação |

## 3. Testes offline para o revisor reproduzir

Executar em uma cópia **descartável** do repositório, sem credenciais, sem serviços Wazuh e sem VMs:

```powershell
python -m unittest discover -s tests -q
python -m unittest discover -s tests -p test_m1_inventory_end_to_end.py -v
python -m unittest discover -s tests -p test_m1_observed_agents_triage.py -v
python -m unittest discover -s tests -p test_hunt_correlations.py -v
python scripts/roadmap_progress.py
powershell -NoProfile -File scripts/validate_lab_config.ps1
git diff --check
```

Além de contar testes, inspecionar asserts e conferir **falha segura** em dados inválidos. Verificar o último GitHub Actions do PR, tanto Ubuntu quanto Windows, e confirmar que o SHA corresponde ao commit revisado. Se houver novos commits, a revisão do código desatualizada precisa ser reconsiderada.

**Não executar** scripts de ativação de `auditpol`, substituição de `agent.conf`, gerenciamento de grupos ou qualquer teste que produza eventos reais sem change control explícito.

## 4. Checklist da revisão humana

- [ ] Conferi **cada arquivo de produção** e o respectivo teste, não somente os resultados do CI
- [ ] Confirmei que dados parciais, fixtures sintéticas, arquivos ausentes e referências duplicadas **não** liberam mudança
- [ ] Confirmei ausência de chamadas remotas de inventário individual e ausência de operações de escrita no Wazuh
- [ ] Confirmei que os três cenários de hunting geram apenas **candidatos**, não atestados de incidentes
- [ ] Confirmei que saída pública/CI não reproduz IPs, hosts, agentes individualizados nem segredos
- [ ] Li os limites de precedência de grupos e a distinção família Linux versus regex OS interna Wazuh
- [ ] Reproduzi os testes no commit a ser aprovado e revisei falhas/avisos de CI
- [ ] Documentei pontos pendentes e os links das evidências sem copiar a informação privada
- [ ] Submeti **review formal** no GitHub como pessoa independente e habilitada (aprovado ou alterações solicitadas)

Um comentário comum no PR, um teste verde ou um auto-review não satisfazem a revisão formal independente.

## 5. Gate separado para a operação Wazuh

**Mesmo que o PR seja aprovado e incorporado à `main`, o FIM continua em `NO-GO`** até que um operador autorizado forneça: inventário real 4/4, sync e ordem de grupos, investigação do `001` se pertencer ao grupo, plano de rollback operacional validado pelo responsável, janela e critérios de parada definidos. O Windows `4698` tem aprovação separada.

Issues relacionadas: [#9 — Hunting](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9), [#15 — Auditoria 4698](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15), [#17 — FIM](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17), [#26 — Proteção de main](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/26).
