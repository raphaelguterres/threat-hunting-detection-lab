# M1 — reconciliação read-only e estado de evidência

**Data:** 04/11/2026, 13:17–13:18 BRT (16:17–16:18 UTC).
**Escopo:** repositório local e verificações de conectividade autorizadas. Nenhuma configuração de Wazuh, política Windows, serviço, agente, contêiner, índice ou arquivo de evidência foi alterado.

## Resultado executivo

O checklist permanece em **11/17**, com seis itens pendentes. O gate local continua
`EVIDENCE_SOURCE=PRIVATE_UNATTESTED`, `EVIDENCE_COMPLETENESS=INCOMPLETE` e
`DEPLOYMENT_GATE=BLOCKED`.

O checkpoint read-only que anteriormente verificava o Manager não conseguiu renovar
as três confirmações remotas nesta execução. Isso produz `UNKNOWN`, não um resultado
de falha da configuração nem uma contradição das observações de 03/11. Não foi feita
tentativa de recuperação, reinício, troca de chave, alteração de rede ou mecanismo
alternativo de acesso.

| Evidência / verificação | Resultado desta execução | Conclusão permitida | Incerteza / próximo gate |
| --- | --- | --- | --- |
| Estado do repositório | Branch `feat/m1-readiness-gate-fail-closed`, HEAD `f51b55e`, árvore limpa | Nenhuma mudança local preexistente precisava ser reconciliada | O branch não tem upstream configurado; o SHA remoto não foi consultado nesta passagem |
| Progresso e gate | `8/8` histórico, `11/17` M1; gate retornou código 2 com `BLOCKED` | O bloqueio fail-closed está ativo e a contagem não mudou | Não é uma métrica de prontidão operacional |
| Checkpoint Manager para `004` | `AGENT_004_SYNC=UNKNOWN_OR_FAILED`; parser ativo e hash também `UNKNOWN_OR_FAILED`/`UNKNOWN` | Não há confirmação remota renovada de sync, parser ou baseline | Renovar somente pelo acesso autorizado quando a conectividade voltar |
| Conectividade Kali | SSH retornou `Permission denied` na porta 22; TCP 443, 9200 e 55000 não conectaram | A rota de diagnóstico usada pelo checkpoint não estava utilizável no instante da coleta | Não determina causa, saúde dos contêineres ou estado das VMs |
| Regras FIM efetivas | Não consultadas nesta passagem | Níveis efetivos para alteração, adição, exclusão e Registro continuam `UNVERIFIED` | Leitura autorizada do ruleset carregado, registrando apenas IDs, níveis e categorias |
| Configuração de archives no Manager | Não consultada nesta passagem | `archives.json`, `archives.log`, `alerts.json`, `logall_json` e `jsonout_output` continuam `UNVERIFIED` localmente | Inventário sanitizado de existência, datas, tamanho, rotação e permissões quando o acesso autorizado estiver disponível |
| FIM de arquivo no `004` | Nenhuma nova telemetria foi gerada ou consultada | H03 permanece `INCONCLUSIVE` | Exigir alteração de arquivo autorizada e Sysmon Event ID 1 do mesmo artefato/endpoint, em até 20 minutos, mais controle negativo |

## Evidências históricas preservadas, não renovadas

Os seguintes dados continuam referências datadas de 03/11, e não observações atuais:

- `488` alertas Syscheck do `004` em sete dias, todos os resultados observados no
  controle positivo associados a caminhos de Registro; `0` no filtro que excluía
  `HKEY*`.
- `syscheck.path` era `keyword` no índice `wazuh-alerts-4.x-2026.11.03` consultado.
- O limiar exibido para armazenamento de alertas era nível `3`; isso não informa o
  nível efetivo das regras FIM aplicáveis.
- O Indexer não listava índices `wazuh-archives-*`; isso não prova a inexistência dos
  arquivos de archives no Manager.
- O Dashboard havia mostrado `002`, `004` e `005` sincronizados e `001` desconectado.
  A evidência excedeu a janela de recência do gate e não deve ser reutilizada como
  inventário atual.

## Mudanças em preparação

| Solicitação | Estado | Pré-condições ainda ausentes |
| --- | --- | --- |
| `M1-FIM-OS-SCOPE` | **NO-GO — não aplicada** | Decisão sobre `001`, inventário atual 4/4 conforme contrato vigente, revisão independente de escopo/precedência, baseline e backup/rollback operacional renovados, PR revisado, janela e aprovação expressa |
| `M1-WIN-4698` | **NO-GO — não aplicada** | Aprovador e janela próprios, novo baseline `auditpol /get`, revisão de duplicidade Security e retenção, plano de rollback da mesma subcategoria, teste benigno aprovado e validação de ingestão |

Ambas as solicitações continuam independentes. Nenhuma delas é liberada por testes
offline, conectividade parcial ou pela existência de documentação.

## Qualidade local

Foram executados em 04/11:

```text
python scripts/roadmap_progress.py
python scripts/m1_evidence_gate.py --manifest .lab/m1-evidence.json --stage prechange
python -m pytest -q -p no:cacheprovider
```

Resultado da suíte: **198 passed, 4 skipped, 160 subtests passed**. O diretório
`.lab/` permanece ignorado pelo Git; nenhum conteúdo privado foi adicionado ao
repositório.

## Decisão

**NO-GO.** O gate efetivo permanece bloqueado e a indisponibilidade atual de
verificação remota impede renovar a baseline, não justifica flexibilizar controles.
O próximo passo seguro é restabelecer o acesso autorizado sem contornar a barreira e,
então, repetir as consultas read-only de ruleset, configuração/metadata de archives e
inventário de agentes antes de solicitar qualquer mudança.
