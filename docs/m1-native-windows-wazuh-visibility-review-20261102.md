# M1 — Auditoria defensiva somente leitura: Windows Security, Sysmon e Wazuh FIM

**Revisão:** 02/11/2026. **Ambiente:** VM autorizada WindowsServer e sessão autenticada do Wazuh/OpenSearch Console no laboratório. **Sem alterações em regras, serviços, políticas de auditoria ou configuração TLS.**

**Status:** H01, H02 e H03 **ainda não comprovadas como correlações operacionais**. A coleta desta revisão identifica *disponibilidade de fontes* e verifica **somente uma sequência delimitada de H02**, não transforma ausência de correspondência em inexistência de ameaça.

## Procedência

- Na VM WindowsServer, consulta **somente leitura** via `Get-WinEvent` aos canais Security e Microsoft-Windows-Sysmon/Operational, com janela absoluta de **31/10/2026 00:00 UTC a 03/11/2026 00:00 UTC**, usando conversão UTC→hora local da VM. **Somente contagens por ID**, status da consulta e diagnóstico de auditoria foram transferidos à pasta privada do host.
- Em seguida, o mesmo sistema executou uma correlação **em memória**, sem publicar SIDs, usuários, identificadores de logon nem registros brutos, para vincular o **TargetSid** de cada Security `4720` ao **TargetUserSid** dos `4624` e **SubjectUserSid** dos `4672` subsequentes, na janela de 30 minutos. Um vínculo forte `4624↔4672` requer ainda **TargetLogonId = SubjectLogonId** e proximidade de até dois minutos.
- Na sessão autorizada **Wazuh Dashboard → Dev Tools/OpenSearch Console**, foram executadas exclusivamente consultas `GET wazuh-alerts-*/_count`, sem retornar conteúdo de eventos. Total de shards da resposta: 27, zero falhas em todas as consultas mostradas.
- As saídas privadas permanecem exclusivamente no diretório `.lab/m1-native-bridge/` do host Windows, ignorado pelo Git. O compartilhamento temporário da VM não é fonte de evidência pública nem local de armazenamento permanente.

## 1. Disponibilidade de logs nativos — janela UTC acima

| Canal | Evento | Contagem observada | Condição |
| --- | --- | ---: | --- |
| Security | `4698` — tarefa agendada criada | **0** | Sem eventos correspondentes na consulta |
| Security | `4720` — conta criada | **1** | Contagem obtida |
| Security | `4672` — privilégios especiais atribuídos em logon | **375** | Contagem obtida |
| Security | `4624` — logon bem-sucedido | **387** | Contagem obtida |
| Sysmon/Operational | `1` — criação de processo | **≥2.000** | Limite de coleta atingido (capped at 2.000); **não é total exato** |

**Lacuna H01:** `auditpol /get /subcategory:"Other Object Access Events"` respondeu **No Auditing**. A ausência de `4698` pode decorrer dessa configuração de auditoria e não prova que não houve criação de tarefas. **Não foi habilitada auditoria** neste trabalho.

**Cuidado:** a execução de ferramentas administrativas de coleta pode gerar seus próprios eventos Sysmon/processo; os totais não permitem inferir comportamento malicioso.

## 2. H02 — vínculo entre conta criada e sessão privilegiada

A análise local, usando os eventos nativos originais na memória do Windows Server, obteve:

| Métrica observacional | Resultado |
| --- | ---: |
| Eventos `4720` encontrados | **1** |
| Eventos `4720` com TargetSid válido | **1** |
| Eventos `4672` do **mesmo SID**, nos 30 minutos após criação | **0** |
| Eventos `4624` do **mesmo SID**, nos 30 minutos após criação | **0** |
| Cadeias `4624 ↔ 4672` com mesmo LogonId nesse recorte | **0** |

**Resultado:** **H02 não corroborada nesse recorte temporal**. Os 375 eventos `4672` e 387 eventos `4624` não podem ser usados como prova da hipótese sem confirmar que pertencem à conta criada. **Não há conclusão sobre atividade da conta fora desses 30 minutos**, qualidade/continuidade da auditoria ou comprometimento.

## 3. H03 — disponibilidade de FIM no Indexer

Consultas do **mesmo Console autenticado**, com endpoint de leitura `_count`:

| Consulta | Documentos encontrados |
| --- | ---: |
| Campo `syscheck.path` presente em `wazuh-alerts-*` | **112** |
| `syscheck.path` e `agent.id:004` (todo o histórico indexado disponível) | **102** |
| Mesmas condições, entre 31/10 00:00 UTC e 03/11 00:00 UTC | **0** |

Para conferir que o filtro de data usado pelo Console retornava eventos conhecidos, uma consulta de **controle positivo** para `rule.id:110100`, `agent.id:004` e a **mesma janela temporal** encontrou **1 documento**, conforme o aceite anterior da Fase 3.

**Interpretação:** há histórico de alertas FIM indexados, porém **não se observou evento FIM recente do agente 004 nessa janela**. O Sysmon 1 estava disponível no Windows, mas sem um evento FIM relacionado ao **mesmo arquivo** não existe correlação H03 validada. O total histórico de FIM, sozinho, não comprova execução de nenhum artefato.

### Reproduzir consultas somente leitura

No OpenSearch Console autenticado, obter somente contagens (nenhum payload de evento):

~~~text
GET wazuh-alerts-*/_count?q=syscheck.path:*

GET wazuh-alerts-*/_count?q=syscheck.path:*%20AND%20agent.id:004

GET wazuh-alerts-*/_count?q=syscheck.path:*%20AND%20agent.id:004%20AND%20timestamp:%5B2026-10-31T00:00:00Z%20TO%202026-11-03T00:00:00Z%5D

GET wazuh-alerts-*/_count?q=rule.id:110100%20AND%20agent.id:004%20AND%20timestamp:%5B2026-10-31T00:00:00Z%20TO%202026-11-03T00:00:00Z%5D
~~~

Cada consulta foi executada **separadamente**. Esses números se referem aos **índices disponíveis** no laboratório, não a todos os eventos originalmente gerados; retenção, parsing, regras e lacunas de indexação afetam visibilidade.

## Próximas decisões, sem mudança automática de configuração

1. **H01:** avaliar em ambiente de teste a habilitação de **Audit Other Object Access Events** para observar `4698`; exigir aprovação e plano de rollback antes de alterar GPO/`auditpol`. Confirmar a semântica da regra Wazuh `110120` (consulta/execução não equivale necessariamente a criação).
2. **H02:** revisar eventos da conta criada **fora** dos 30 minutos, inclusive grupos atribuídos, tipo de logon e origem autorizada, mantendo o material identificável apenas em ambiente privado. Se não houver continuidade ou integridade da coleta, classificar como **inconclusivo**.
3. **H03:** verificar o escopo do monitoramento FIM em Windows, políticas de coleta, latência e retenção de alertas. Reabrir a caça quando houver evidência FIM e Sysmon 1 para **o mesmo caminho/hash e ativo**, sem criar eventos de teste desnecessários.
4. Preparar três **estudos de caso** com hipóteses benignas e controles negativos depois da validação operacional. **Não fechar [M1 Issue #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9)** só por contagens, ausência de candidatos ou CI verde.

## Limitações

- Os intervalos e números são **recortes específicos da VM**, não medições contínuas de SOC em produção.
- `0` na consulta não comprova ausência de evento real; `2.000` no Sysmon é apenas **limite inferior** devido ao teto da consulta.
- A correlação H02 não substitui uma investigação contextual sobre política, dono da conta ou incidente.
- Não houve mudança de configuração, reinício, coleta de credenciais, conteúdo bruto indexado ou publicação de IDs reais.
