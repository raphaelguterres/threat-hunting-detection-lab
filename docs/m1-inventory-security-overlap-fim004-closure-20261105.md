# M1 — encerramento da revisão de inventário, coletores Security e FIM do Windows 004 (05/11/2026)

**Entrega do ROADMAP:** *Confirmar inventário/OS dos agentes atuais, revisar possível duplicidade Security e demonstrar a cobertura FIM efetiva do agente 004.*  
**Resultado da revisão:** **concluída para o escopo de levantamento, classificação de risco e demonstração funcional**. Há **um risco residual de sobreposição de coletores Security**, documentado e **não corrigido**. O aceite completo da mudança A e a mudança Windows 4698 continuam separados.  
**Procedimento:** observações Wazuh autorizadas **somente leitura**, confronto de registros privados já existentes e resultados FIM benignos reais de 05/11. Nenhuma nova execução ativa.

## 1. Inventário e distribuição atualizados

A consulta read-only no Wazuh Manager, repetida em **05/11/2026 às 15h26 BRT**, retornou os três agentes do escopo ativos e sincronizados individualmente. O hash da configuração centralizada `default/agent.conf` continuou igual à candidata implantada da mudança A.

| Agente | Plataforma confirmada no inventário privado | Grupo | Estado |
| --- | --- | --- | --- |
| `002` | Linux — ambiente de laboratório em contêiner | `default` | **Active / synchronized** |
| `004` | Microsoft Windows Server 2022 | `default` | **Active / synchronized** |
| `005` | Kali Linux nativo | `default` | **Active / synchronized** |

A coleta detalhada de OS/versão e associação do grupo foi feita pelo Manager autorizado em **04/11 às 21h34 BRT** e permanece na pasta privada. Todos os três agentes têm somente um grupo conhecido, `default`; **não foi identificado conflito de precedência entre grupos** nesse escopo. O cadastro legado `001` foi removido em 04/11, sob autorização registrada, e o `003` permanece sem conexão inicial e **fora da associação `default`**. Não contar o `003` como agente sincronizado e não reutilizar o inventário antigo de quatro membros como retrato atual.

**Limites:** uma observação de status/sync não prova a saúde de cada fonte de log; a evidência privada deve ser renovada quando o gate de frescor de 24 horas expirar. Esta revisão é técnica, feita pelo mesmo fluxo de execução; não substitui a aprovação humana independente do PR.

## 2. Dois coletores locais Windows Security: avaliação de sobreposição

Os registros autorizados da configuração local Windows `004` apontaram:

| Critério | Resultado comprovado |
| --- | --- |
| Fontes `Security` em `eventchannel` | **2** |
| Fonte ampla sem cláusula `query` | **1** |
| Fonte com cláusula `query` | **1** |
| Estilo da cláusula filtrada | Exclusões de EventID (negativa), sem whitelist |
| Exclusão explícita de `4698` | **Não observada** |
| Duplicação efetiva de eventos no Manager/Indexer | **Não mensurada nem comprovada** |
| Security: retenção observada em 02/11 | **20 MiB, circular** |
| `Audit Other Object Access Events` | **No Auditing** no último pré-check |

**Conclusão do risco:** uma fonte ampla e outra com filtro apenas de exclusões podem selecionar **o mesmo evento**. Isso configura **risco potencial de sobreposição**, não autorização para afirmar duplicação efetiva dos alertas. Sem auditoria comparativa por IDs da origem e sem reconfiguração de coletores, o status correto é `POTENTIAL_OVERLAP_NOT_RESOLVED`, e **não** `NO_DUPLICATES`.

**Encaminhamento:** o risco e a decisão de manter a configuração inalterada ficam vinculados à [Issue #15 — mudança Security 4698](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15). Qualquer ajuste em `localfile`, filtragem, `auditpol` ou retenção precisa de change control separado, baseline e plano de rollback. Não habilitar `4698` por este item. A revisão de possibilidade de duplicidade foi concluída; **a mitigação não foi executada nem marcada como feita**.

## 3. Cobertura FIM efetiva do agente Windows 004

A inspeção inicial do `ossec.conf` local mostrou **seis diretórios monitorados**, dos quais **um realtime**, cinco por varredura programada (**12 horas**) e zero em `whodata`. A verificação pós-cutover no Dashboard exibiu **seis diretórios Windows, sem o diretório Unix central indevidamente herdado**.

Mais importante: o teste inerte autorizado de **05/11/2026** usou um **único arquivo descartável** em um diretório Windows já monitorado e registrou três eventos **reais** no `wazuh-alerts-*` / Discover:

| Etapa | Evento FIM observado | Evidência |
| --- | --- | --- |
| Criação | `added` | Documento do mesmo artefato e `agent.id=004` |
| Modificação | `modified` | Segundo documento do mesmo artefato |
| Exclusão | `deleted` | Terceiro documento, com limpeza local confirmada |

**Resultado:** `WINDOWS_004_FIM_REALTIME_INDEXER_DISCOVER=CONFIRMED_3_OF_3`. As três operações e o término da limpeza foram documentados. A configuração da mudança A manteve o hash esperado, e o agente permaneceu sincronizado na conferência atual.

**Limites importantes:** essa prova confirma a coleta **para o diretório testado**, não para todos os seis diretórios, nem para `whodata`, registro Windows, Sysmon Event 1 ou a correlação H03 FIM→execução. O arquivo local `alerts.json` do Manager **ainda não foi inspecionado diretamente** por meio autorizado, portanto `manager_ingestion` permanece `pending` no gate final.

## 4. Proveniência privada e decisão de aceite desta entrega

Um snapshot privado em `.lab/m1-inventory-security-fim004-review-20261105-private.json` preserva a data da revisão, os resultados de escopo, **SHA-256 de oito fontes** de inventário, filtros e FIM, e as ressalvas. Não publicar CSVs, XML de agente, nomes de host, IDs de eventos brutos, capturas de tela ou hashes do snapshot.

| Critério da entrega | Resultado |
| --- | --- |
| Inventário de OS, grupos e sincronização dos membros atuais `default` | **PASS: 3/3, com fonte e momento identificados** |
| Revisão da possível duplicidade Security | **REVISADA: risco potencial identificado e transferido à Issue #15, mitigação ainda aberta** |
| FIM Windows 004: configuração por SO e funcionamento na ingestão | **PASS delimitado: 3 eventos reais e configuração visual coerente** |
| Revisão humana independente | **NÃO REALIZADA** |
| Confirmação direta do log Manager | **PENDENTE**, separada desta entrega |
| Mudança ativa, reboot, alteração de políticas | **NÃO REALIZADOS nesta revisão** |

**Aceite do item de ROADMAP:** a **revisão de inventário/OS, sobreposição Security e cobertura funcional FIM 004** está concluída e documentada. O checklist pode avançar de **12/17 para 13/17 (76,5%)**. Esse item foi originalmente redigido *antes de solicitar alteração no grupo compartilhado*; a mudança A já foi implantada com autorização e registrada em outra trilha. O marco atual é uma **conciliação retrospectiva e pós-mudança**, não prova de que uma conferência de 05/11 ocorreu antes do cutover de 00h42.

**Não estão concluídos:** alteração da auditoria Windows `4698` (Issue #15), correlação das hipóteses H01/H02/H03 com registros completos, tuning e revisão ATT&CK por hipótese, inspeção independente do log Manager, revisão formal por terceiro ou encerramento do M1. `PROJECT_CONTINUATION_GATE` poderá permanecer aberto sob a exceção limitada do proprietário; `DEPLOYMENT_GATE` de aceite final continua bloqueado e rollback preservado.

### Fontes

- [Matriz de aceitação FIM](m1-fim-acceptance-matrix.md)
- [Controle 4698 e análise de filtros Windows](m1-change-control-4698-fim-agent004.md)
- [Evidências reais dos três agentes](m1-change-a-three-agent-fim-evidence-20261105.md)
- [Parecer técnico de evidências](m1-change-a-formal-evidence-review-20261105.md)
- [Issue #17 — segregação FIM por SO](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17)
- [Issue #15 — Security 4698 e coletores](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15)
