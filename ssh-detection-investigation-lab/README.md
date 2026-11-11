# SSH Detection & Investigation Lab

**Fase 2 do Threat Hunting Lab · Raphael Guterres**

Investigar falhas de autenticação SSH seguidas de sucesso e produzir um caso de triagem reproduzível com Wazuh. Esta fase acrescenta correlação temporal, controles negativos e uma linha do tempo de investigação ao [laboratório principal](../README.md).

## Fluxo da telemetria

O endpoint Linux gera eventos de autenticação. Na arquitetura prevista, o Wazuh Manager recebe os registros e aplica regras, o Indexer disponibiliza os alertas e o Discover permite consultar os documentos. O Windows Server já aparece no Discover como fonte de eventos. O Kali foi usado como estação de análise.

## Diário de execução

| Data | Verificação | Resultado |
| --- | --- | --- |
| 11/11/2026 | Inventário da VPS | Ubuntu 24.04 LTS com serviços existentes. Unidade systemd do agente Wazuh não encontrada |
| 11/11/2026 | Baseline SSH na VPS | Em 24 h, o journal da unidade SSH continha 1.840 entradas. Os padrões consultados encontraram 55 linhas de autenticação aceita e 1 rejeitada |
| 11/11/2026 | Discover no Kali | Índice `wazuh-alerts-*` acessível com alertas gerais e eventos do Windows Server. O filtro SSH não foi aplicado com sucesso |

A contagem da VPS foi obtida no journal local. A ingestão desses registros no Wazuh ainda precisa ser verificada.

## Hipótese de detecção

Sinalizar para triagem quando houver pelo menos cinco falhas em cinco minutos para a mesma origem, conta e host, seguidas de sucesso até cinco minutos após a última falha. O limiar é experimental. A triagem vai confrontar hipóteses como erro legítimo de autenticação e possível uso indevido de credenciais.

| Teste sintético | Resultado esperado |
| --- | --- |
| Cinco falhas e sucesso dentro das janelas, mesma chave | Um sinal |
| Quatro falhas ou sucesso fora da janela | Sem sinal |
| Sucesso com outra origem, conta ou host | Sem sinal |
| Duplicatas da mesma falha | Cada evento contado uma vez |

## Próxima execução

1. Aplicar `rule.groups: sshd` em `wazuh-alerts-*` no Discover para os últimos sete dias.
2. Registrar os campos observados de origem, conta, agente, timestamp e regra. Se a consulta vier vazia, verificar a coleta SSH do agente Linux e a disponibilidade de eventos brutos.
3. Executar a matriz sintética com os campos confirmados e registrar o resultado esperado e observado.
4. Documentar o Caso 001 com linha do tempo, hipóteses, evidências sanitizadas e decisão de triagem.

As evidências publicadas usarão identificadores fictícios. Os logs brutos ficam em área privada.
