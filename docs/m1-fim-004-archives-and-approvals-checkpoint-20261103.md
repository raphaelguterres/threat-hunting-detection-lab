# M1 — checkpoint FIM 004, archives e aprovação das mudanças

**Data:** 03/11/2026, ~23h41–23h48 BRT. **Método:** interface autenticada do Wazuh no Kali, documentação do repositório e validações sintéticas no Windows host; **somente leitura no ambiente ativo**. Não houve `auditpol /set`, mudança de configuração, coleta adicional de archives, reinício ou teste provocando alteração no endpoint.

## Investigação FIM `004`: o que ficou comprovado

| Fonte | Evidência | Limite |
| --- | --- | --- |
| Discover (`wazuh-alerts-*`) | Checkpoint anterior: 488 Syscheck do `004` em sete dias; filtro excluindo `HKEY*` retornou 0 | Os hits observados incluíam Registro do Windows; isso não prova falta de varredura de arquivos |
| Indexer (`2026.11.03`) | `syscheck.path` confirmado como `keyword` via GET `/ _mapping/field` (sem espaço no endpoint real) e HTTP 200, na coleta anterior | Mapeamento de um índice, não de toda a série histórica |
| Manager → Settings → Alerts | Mínimo armazenado: nível 3; mínimo enviado por e-mail: 12 | Ainda não confirma níveis das regras FIM efetivamente carregadas |
| Indexer → Dev Tools, 03/11 | `GET _cat/indices/wazuh-archives-*?format=json` → **HTTP 200, `[]`** | Nenhum índice `wazuh-archives-*` listado; **não** confirma ausência de arquivos `archives.json` locais no Manager nem `logall_json` ativo/inativo |
| Manager → Rules | Lista geral de 4.523 regras. WQL `id:550` e `id=550` retornaram zero itens no recorte consultado | Pesquisa inconclusiva; ausência no filtro **não** comprova que a regra 550 inexista ou que esteja inativa. Não foram verificados níveis efetivos de 550/553/554 |
| Windows `004` | WazuhSvc Running; syscheck habilitado; 6 diretivas de diretórios, 5 agendadas e 1 realtime; varredura 12h; 2 `ignore`, conforme leitura direta anterior | Não prova uma alteração de arquivo observada/alertada |

### Explicação possível ainda NÃO comprovada

O nível de alerta mínimo do Manager é 3. Um evento de FIM pode não atingir esse limiar, estar fora do período monitorado, cair em exclusão de arquivo, não ocorrer durante a janela ou não aparecer por outra decisão da cadeia. Não atribuir causalidade sem ler **regras efetivas** e logs locais. O índice `wazuh-alerts-*` contém apenas alertas; `archives.json` e índices `wazuh-archives-*` são recursos independentes.

**Próximas verificações estritamente read-only:** inspecionar nível e conteúdo das regras FIM que o Manager efetivamente carregou; ler `logall_json`, `jsonout_output` e metadados de existência/rotação de archives existentes; comparar de maneira privada, por agente e período, contagens de `syscheck.path` de Registro versus caminhos de arquivo; confirmar tipo de eventos da mudança de arquivo antes de correlacionar H03 com Sysmon 1. Uma restrição de segurança interrompeu a etapa adicional de navegação. Não contornar.

## Mudança A — FIM central Linux (`M1-FIM-OS-SCOPE`)

**Proposta já preparada, NÃO aplicada:** incluir somente `os="^Linux"` no bloco Unix existente em `default/agent.conf`. A validação original em staging por parser oficial e backup privado são históricos; devem ser atualizados na janela autorizada. Nova validação **sintética local** do escopo: PASS; declara explicitamente `deployed=false` e `wazuh_parser_verified=false` para a fixture.

**Condições para uma futura aprovação:** (A1) decidir formalmente situação do histórico `001` (Issue #27) e reconciliar critério 4/4; (A2) coletar inventário/OS/versões/grupos em ordem, sync e status atuais; (A3) revisor independente verificar seleção Linux e ausência de regressão Windows; (A4) comparar SHA256, owner/mode e parser com baseline atual; (A5) comprovar backup real restaurável e rollback operacional com operador; (A6) janela delimitada e **autorização explícita separada**; (A7) PR revisado por humano habilitado e CI válido no SHA. Qualquer divergência = NO-GO.

**Aceite após eventual aplicação aprovada:** distribuição Linux correta nos agentes ativos, 004 sem diretiva Unix central, cobertura FIM local preservada, Manager/Indexer/Discover saudáveis e rollback disponível. Sem merge, implantação ou alteração de grupos agora.

## Mudança B — auditoria `4698` (`M1-WIN-4698`)

**Proposta já preparada, NÃO aplicada:** alterar somente *Audit Other Object Access Events → Success* no Windows Server para permitir Security 4698. Baseline anterior foi *No Auditing*; Security é circular, 20 MiB; existem duas fontes de coleta `Security` locais (uma com exclusões). `4698` não estava explicitamente negado, mas a ingestão de um 4698 verdadeiro ainda não foi demonstrada.

**Condições para uma futura aprovação:** (B1) aprovação e janela **independentes** de FIM; (B2) novo baseline `auditpol /get` e revisão de sobreposição/deduplicação das duas fontes Security; (B3) avaliação de espaço/retenção 20 MiB; (B4) plano de rollback para a mesma subcategoria com decisão humana; (B5) operador presente; (B6) cenário benigno de tarefa agendada aprovado separadamente, com limpeza prevista; (B7) medição Security local → Manager → Indexer → Discover com timestamps e campo de origem; (B8) critérios de parada imediata e documentação privada.

**Aceite após eventual aplicação aprovada:** Security 4698 autêntico gerado no cenário benigno, coleta sem duplicidade inesperada, retenção controlada e confirmação no Wazuh. Não habilitar `Failure`, aumentar log, aplicar GPO, reiniciar serviços ou criar tarefa nesta etapa de preparação.

## Gates e resultados de validação

- **202 testes e 160 subtestes PASS** na suíte local de 03/11; validador de escopo XML sintético PASS, sem deploy.
- `M1_CHECKLIST=11/17` no checkpoint atual; `DEPLOYMENT_APPROVED=false` e `HUMAN_REVIEW_VERIFIED=false`.
- `EVIDENCE_SOURCE=PRIVATE_UNATTESTED`, `EVIDENCE_COMPLETENESS=INCOMPLETE`, `DEPLOYMENT_GATE=BLOCKED`.
- Revisões independentes PR #24/#25 não registradas no último check. Sem autorização para mudança A ou B.

**Decisão:** `H03=INCONCLUSIVE`; `ARCHIVES_INDEX=NOT_PRESENT_IN_INDEXER`; `ARCHIVES_LOCAL_MANAGER=NOT_VERIFIED`; `EFFECTIVE_FIM_RULE_LEVELS=UNVERIFIED`; **`DEPLOYMENT_GATE=BLOCKED`**.

Referências: [pacote FIM](m1-fim-change-approval-package.md), [change control 4698](m1-change-control-4698-fim-agent004.md), [auditoria local FIM](m1-agent004-syscheck-policy-log-readonly-20261103.md), [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17), [Issue #15](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15), [Issue #27](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/27).
