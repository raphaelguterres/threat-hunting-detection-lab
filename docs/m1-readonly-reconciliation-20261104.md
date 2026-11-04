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
| Checkpoint Manager para `004` | Coleta posterior no Manager: `agent_groups -S -i 004` retornou sincronizado; `verify-agent-conf -f default/agent.conf` retornou `OK` | Sync do `004` e validade sintática da configuração central foram renovados em modo read-only | O hash contra a baseline privada não foi recalculado; parser não prova distribuição, precedência ou cobertura FIM em runtime |
| Conectividade Kali | SSH retornou `Permission denied` na porta 22; TCP 443, 9200 e 55000 não conectaram | A rota de diagnóstico usada pelo checkpoint não estava utilizável no instante da coleta | Não determina causa, saúde dos contêineres ou estado das VMs |
| Regras FIM efetivas | Arquivo: `550` modificação nível 7, `553` exclusão nível 7, `554` adição nível 5. Registro: `594`/`597`/`598` e `750`/`751`/`752`, todos nível 5; regras no arquivo `0015-ossec_rules.xml` | Para eventos de arquivo ou Registro que atinjam essas regras, todos os níveis observados superam o limiar histórico de armazenamento 3 | Não prova que ocorreu alteração, que o caminho do `004` é coberto ou que a cadeia de ingestão recebeu o evento; relógio/fuso do Kali ainda não foi normalizado |
| Archives e alertas no Manager | Check UTC `2026-11-04T16:32:39Z`: `archives.json` existe (1.832.766 bytes; modificado em `2026-11-01T22:33:58Z`); `archives.log` existe, 0 bytes, modificado em `2026-11-04T00:00:02Z`; `alerts.json` existe (1.177.261 bytes; modificado em `2026-11-04T16:30:09Z`); todos `640 wazuh:wazuh` | Metadados locais de arquivos foram verificados; `alerts.json` estava atual no checkpoint, mas `archives.json` não era uma fonte atual | Tamanhos/datas não provam integridade, rotação completa ou ingestão no Indexer; nenhuma linha de log foi lida |
| Opções efetivas do Manager | `jsonout_output=yes`, `logall_json=no`, `log_alert_level=3` | O Manager produz JSON de alertas e somente alertas de nível 3 ou superior são armazenados; o arquivamento JSON completo não está ativo | Não muda a política sem autorização; ausência de archive recente não prova ausência de evento nem falha de FIM |
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

## Atualização do Ruleset — 04/11, relógio exibido pelo Kali 11:22–11:23

O Dashboard Wazuh voltou a carregar e a página **Rules** exibiu `4.523` regras. O
relógio/fuso do Kali não foi normalizado nesta leitura. A
leitura visual, sem editar regras ou arquivos, confirmou as regras FIM de arquivo a
seguir:

| ID | Evento | Nível | Categorias exibidas |
| --- | --- | ---: | --- |
| `550` | Alteração de checksum/integridade | 7 | `syscheck`, `syscheck_entry_modified`, `syscheck_file`, `ossec` |
| `553` | Arquivo excluído | 7 | `syscheck`, `syscheck_entry_deleted`, `syscheck_file`, `ossec` |
| `554` | Arquivo adicionado | 5 | `syscheck`, `syscheck_entry_added`, `syscheck_file`, `ossec` |

O limiar de armazenamento visto em 03/11 era 3. Logo, a hipótese de que uma regra
FIM de arquivo observada estava abaixo desse limiar não explica, por si só, o recorte
histórico sem caminhos de arquivo. Permanecem alternativas não verificadas: não ter
havido alteração observável, caminho fora de cobertura ou exclusão, periodicidade,
pipeline e escopo temporal.

### Regras de Registro

Uma leitura local read-only do mesmo ruleset confirmou seis regras de Registro, todas
no nível 5: `594` (checksum de chave alterado), `597` (entrada de chave excluída),
`598` (entrada de chave adicionada), `750` (checksum de valor alterado), `751`
(valor excluído) e `752` (valor adicionado). Portanto a hipótese de nível abaixo de
3 também não explica os alertas de Registro observados historicamente. A consulta
não prova que tais regras foram acionadas pelo `004` na janela atual.

## Checkpoint local de archives e alertas — 04/11, 16:32:39 UTC

O operador executou no Manager um comando exclusivamente de metadados, sem abrir ou
imprimir o conteúdo de qualquer log. O resultado sanitizado foi:

| Artefato | Existência e estado observado | Interpretação limitada |
| --- | --- | --- |
| `archives.json` | Presente, 1.832.766 bytes, última modificação `2026-11-01T22:33:58Z`, modo `640`, owner/grupo `wazuh:wazuh` | Há arquivo local legível pelo serviço, porém a data não o torna fonte atual para a janela de 04/11 |
| `archives.log` | Presente, 0 bytes, última modificação `2026-11-04T00:00:02Z`, modo `640`, owner/grupo `wazuh:wazuh` | Metadado compatível com arquivo vazio/recém-rotacionado; não permite inferir causa ou saúde de rotação |
| `alerts.json` | Presente, 1.177.261 bytes, última modificação `2026-11-04T16:30:09Z`, modo `640`, owner/grupo `wazuh:wazuh` | Confirma atualização recente do artefato local de alertas antes do checkpoint, não a entrega individual de um evento FIM |

As flags efetivas retornaram `jsonout_output=yes`, `logall_json=no` e
`log_alert_level=3`. Em conjunto com a ausência anterior de índices
`wazuh-archives-*`, essa fotografia sustenta apenas que o pipeline de alertas JSON
estava configurado e que o arquivamento JSON completo não estava ativo. Ela não
autoriza habilitar `logall_json`, alterar Filebeat/Indexer, nem declarar causa para
os zero alertas de arquivo.

## Contagem sanitizada por caminho — arquivos locais ativos

O operador executou uma agregação local read-only que percorreu `archives.json` e
`alerts.json` sem exibir nenhuma linha, caminho, hash, usuário ou outro conteúdo de
evento. Para o agente `004`, o resultado foi:

| Fonte local | Syscheck total | Caminhos de Registro | Caminhos de arquivo | JSON inválido | Faixa de timestamps |
| --- | ---: | ---: | ---: | ---: | --- |
| `archives.json` | 0 | 0 | 0 | 0 | Ausente |
| `alerts.json` | 0 | 0 | 0 | 0 | Ausente |

Essa é uma fotografia dos **arquivos locais ativos** em 04/11 e não uma consulta de
sete dias. Ela não contradiz os 488 documentos históricos observados no Indexer:
`alerts.json` é sujeito a rotação e o Manager está com `logall_json=no`, portanto
`archives.json` não é uma fonte completa nem atual para a investigação. O resultado
também não prova ausência de FIM no endpoint, ausência de alertas fora do arquivo
atual ou falha de pipeline. A inventariação read-only de rotação é o próximo gate.

## Inventário de rotação acessível

O inventário read-only com os padrões `alerts.json*`, `archives.json*` e
`archives.log*` encontrou somente os três arquivos ativos já descritos. Não havia
arquivos rotacionados nem comprimidos correspondentes no diretório do Manager no
instante da consulta. Assim, não há uma fonte local acessível para reproduzir o
recorte histórico de sete dias; o Indexer permanece a única fonte observada para
aquele período. Esta ausência não descarta retenção em outro destino, configuração
externa de rotação ou dados que já tenham sido removidos, e não autoriza qualquer
limpeza ou reconfiguração.

## Checkpoint de sync e parser do `004`

Em leitura posterior no Manager, `agent_groups -S -i 004` informou que o agente
`004` está sincronizado e `verify-agent-conf -f
/var/ossec/etc/shared/default/agent.conf` retornou `OK`. Nenhuma configuração foi
editada. Esse resultado renova apenas a sincronização do `004` e a validade do XML
central no Manager; não substitui o inventário atual 4/4, a revisão de precedência,
a comparação com o backup privado ou a validação funcional de FIM.

## Inventário central antes e depois do descomissionamento autorizado

Antes da remoção, o comando read-only `agent_groups -l` retornou um único grupo,
`default`, com quatro membros. A listagem filtrada confirmou os IDs `001`, `002`,
`004` e `005`. A verificação posterior retornou `synchronized` e `active` para
`002`, `004` e `005`; `001` estava `disconnected` e sem sincronização confirmada.
O agente `003` foi observado como `never_connected`, mas não pertencia ao `default`.

Em 04/11, após autorização explícita do operador, o cadastro legado `001` foi
removido pelo procedimento administrativo do Wazuh. A verificação posterior
sanitizada comprovou `AGENT_001_REGISTERED=False`; o `default` passou a conter
`002`, `004` e `005`, todos `active` e `synchronized`.

Essa alteração comprova o estado operacional atual, mas **não** altera
silenciosamente o contrato de aceite original de inventário 4/4. Ainda faltam
OS/versão completos e ordem dos grupos dos três membros atuais, além de uma emenda
formal revisada independentemente para definir o novo critério de aceite. Até isso
ocorrer, o gate de pré-mudança permanece bloqueado.

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
