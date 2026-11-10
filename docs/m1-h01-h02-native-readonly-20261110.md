# M1 — auditoria nativa read-only H01/H02 (10/11/2026)

**Fonte:** Windows Server 2022, agente Wazuh `004`, logs **Security** e **Microsoft-Windows-Sysmon/Operational**. Janela consultada: últimos sete dias no relógio do guest. Execução local elevada, **sem criar eventos de teste, usuários, tarefas, políticas ou processos de simulação**.

## Contagens obtidas

| Verificação | Contagem |
| --- | ---: |
| Security `4698` (criação de tarefa) | 3 |
| Sysmon `Event ID 1` analisados | 4.017 |
| Amostra Sysmon truncada pelo teto de 5.000 | Não |
| Sysmon ID1 PowerShell com parâmetro `-enc`/`-EncodedCommand` | 0 |
| Candidatos H01 nativos por ator e tempo (15 min) | 0 |
| Security `4720` (criação de conta) | 0 |
| Logons `4624` de mesmo SID nos 30 min após `4720` | 0 |
| Pares `4624→4672` com mesmo SID e Logon ID após `4720` | 0 |

A verificação terminou com **exit 0**, `MODE=READ_ONLY_NATIVE_WINDOWS` e `INDEXER_CORRELATIONS_VERIFIED=NO`. Os SIDs, usuários e comandos originais **não foram publicados**; somente contagens agregadas constam deste relatório.

## Interpretação e limites

- **H01:** eventos `4698` existem, mas não foi encontrada no recorte a execução Sysmon do PowerShell codificado exigida pela regra personalizada `110100`. Isso é compatível com a lacuna identificada anteriormente no teste `-File`. Ausência de candidato nativo nesta janela **não** prova ausência histórica ou falha de ingestão.
- **H02:** nenhum `4720` encontrado no recorte de sete dias, logo não há par de conta criada + logon privilegiado com SID e Logon ID comprovados. O Security log é circular, e esta auditoria não cobre janelas já sobrescritas.
- **H03:** Change C/FIM foi aplicada e teste com arquivo inerte concluído em 10/11, mas ainda não há prova Manager→Indexer→Discover do evento nem par FIM→Sysmon ID1 de mesmo executável. [Relatório da Change C](m1-h03-change-c-activated-20261110.md).
- Esta consulta não valida ingestão Wazuh, correlação de fontes indexadas ou incidentes. Não houve novos testes ativos H01/H02.

**Status:** `H01=INCONCLUSIVE` · `H02=INCONCLUSIVE` · `H03=INCONCLUSIVE` · `M1=15/17` · `DEPLOYMENT_GATE=BLOCKED`.

**Próximos passos:** observar os registros H03 já produzidos em fontes Wazuh autorizadas; planejar e aprovar ensaios benignos separadamente para H01 e H02 se não houver pares reais disponíveis; correlacionar as três hipóteses com controles negativos e rastreabilidade até Discover; obter revisão independente do M1. Não criar contas privilegiadas, executar binários H03 nem reutilizar janelas de autorização sem os gates específicos.
