# H01 — PowerShell e criação de tarefa em teste controlado (10/11/2026)

No agente Windows 004, o Sysmon registrou um processo PowerShell (Event ID 1, regra Wazuh 110100), seguido 1,089 s depois por uma criação de tarefa registrada no Windows Security (Event ID 4698). Os registros nativos confirmaram o mesmo ator e ativo. A tarefa foi criada desabilitada, sem gatilhos; sua ação não foi executada.

| Verificação | Resultado |
| --- | --- |
| Wazuh Manager e Indexer | Um alerta de processo e um de tarefa em cada fonte. Identidade nativa conferida e conteúdo dos alertas igual nas duas fontes. |
| Discover | A consulta pelos dois Record IDs, com janela absoluta e filtro do agente 004, mostrou exatamente dois resultados. A conferência visual confirmou um registro do PowerShell e um da criação da tarefa. |
| Controle positivo | O correlacionador do repositório retornou **1 par** na janela H01 de 15 minutos. |
| Controle negativo | **0 pares** entre o processo atual e um 4698 real do mesmo ator e ativo ocorrido antes do processo. O 4698 histórico foi confirmado no Indexer. |
| Limpeza | Tarefa removida e ausência confirmada; configuração do agente intacta e serviço Wazuh ativo. |

Para reproduzir a análise com autorização no próprio laboratório, comece pelo [preflight e escopo do teste](m1-h01-next-test-preparation-20261110.md). Compare os Record IDs, o canal e a hora nativa entre Windows, Manager e Indexer. Confirme o processo pelo GUID e a tarefa pelo SID do criador. Normalize os registros em [`scripts/hunt_correlations.py`](../scripts/hunt_correlations.py) usando chaves pseudonimizadas e rode o positivo e o negativo separadamente. Use a hora nativa para ordenar: a chegada ao Wazuh depende de coletores distintos.

A correspondência é um candidato para triagem; esta rodada reproduz atividade benigna autorizada. Registros brutos e identificadores da VM ficam fora do Git. O M1 segue em **15/17** até a conclusão de H02 e a revisão independente final.
