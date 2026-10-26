# Estudos de caso — Linhas do tempo de investigação

Este documento encerra a parte investigativa das cinco detecções do laboratório. Horários exatos, endereços internos, hashes completos e nomes de contas temporárias permanecem fora do repositório público. Todas as ações ocorreram nas VMs isoladas do laboratório em 25/10/2026.

## 1. Autenticação — tentativa com usuário inexistente

| Sequência | Evidência | Interpretação | Ação recomendada |
| --- | --- | --- | --- |
| 1 | Uma tentativa SSH controlada para usuário inexistente no Kali. | A autenticação falhou antes de senha ou sessão. | Confirmar se é teste autorizado e preservar o evento. |
| 2 | Manager recebeu a regra nativa 5710, nível 5. | Telemetria nativa de autenticação confirmada. | Não rotular uma ocorrência isolada como brute force. |
| 3 | Não houve repetição nem sucesso posterior. | Não há evidência de comprometimento. | Encerrar como simulação autorizada. |

**Classificação:** simulação autorizada, baixa prioridade.
**Ativo/usuário:** endpoint Kali; usuário inexistente, redigido.
**Melhoria de detecção:** correlacionar volume, origem e sucesso posterior antes de elevar severidade.

## 2. Identidade — alteração de conta de serviço

| Sequência | Evidência | Interpretação | Ação recomendada |
| --- | --- | --- | --- |
| 1 | Conta de serviço sem login foi criada e removida no Kali. | Mudança controlada de identidade no endpoint. | Conferir ticket, ator e conta afetada. |
| 2 | Auditd registrou os eventos; Manager aplicou a regra 100104, nível 8. | Criação/remoção de conta foi detectada ponta a ponta. | Preservar metadados e verificar aprovação. |
| 3 | Uma consulta de identidade sem alteração não elevou a contagem. | O controle negativo reduziu risco de ruído. | Manter escopo atual da regra. |

**Classificação:** mudança autorizada, sem contenção.
**Ativo/usuário:** endpoint Kali; conta temporária sem login.
**Melhoria de detecção:** enriquecer com origem da mudança e ID de aprovação.

## 3. Execução — PowerShell benigno no Windows

| Sequência | Evidência | Interpretação | Ação recomendada |
| --- | --- | --- | --- |
| 1 | Um PowerShell filho executou o marcador inofensivo `WAZUH-LAB-PS`. | Ação explícita e controlada no Windows isolado. | Confirmar operador e finalidade administrativa. |
| 2 | Sysmon ID 1 chegou ao Manager pela regra nativa 92027. | Imagem, linha de comando, usuário e processo-pai estavam disponíveis. | Correlacionar com alertas adjacentes do mesmo endpoint. |
| 3 | Processos internos do agente Wazuh, sem o marcador, permaneceram contexto distinto. | PowerShell isolado não é sinônimo de atividade maliciosa. | Não bloquear ou conter apenas por uso de PowerShell. |

**Classificação:** simulação autorizada, baixa prioridade.
**Ativo/usuário:** Windows Server isolado; operador administrativo, redigido.
**Melhoria de detecção:** priorizar comandos incomuns combinados com processo-pai, usuário e horário fora do padrão.

## 4. Integridade — alteração FIM no endpoint Linux nativo

| Sequência | Evidência | Interpretação | Ação recomendada |
| --- | --- | --- | --- |
| 1 | Arquivo foi criado em diretório FIM monitorado no Kali nativo. | Regra 554 confirmou criação no filesystem do endpoint. | Conferir caminho e responsável pela alteração. |
| 2 | O mesmo arquivo foi alterado; regra 550 trouxe hashes antes/depois. | Mudança de conteúdo foi confirmada. | Preservar hashes e comparar com mudança aprovada. |
| 3 | Arquivo equivalente fora do escopo monitorado não gerou alerta. | O escopo evita monitoramento excessivo de todo o filesystem. | Manter monitoramento mínimo e revisá-lo periodicamente. |

**Classificação:** mudança autorizada, sem contenção.
**Ativo/usuário:** endpoint Kali nativo; arquivo de validação do laboratório.
**Melhoria de detecção:** correlacionar FIM com processo, proprietário e criticidade do caminho.

## 5. Rede — conexão HTTPS privada autorizada

| Sequência | Evidência | Interpretação | Ação recomendada |
| --- | --- | --- | --- |
| 1 | Edge recarregou o painel HTTPS privado do Wazuh. | Navegação autorizada no ambiente isolado. | Confirmar serviço de destino e janela do teste. |
| 2 | Sysmon ID 3 foi recebido para `msedge.exe`; regra 100105, nível 3. | Processo, protocolo TCP e porta HTTPS permitiram reconstruir a conexão. | Não classificar como exfiltração sem dados e destino suspeito. |
| 3 | Após a ação, uma janela ociosa de 20 segundos não gerou novos eventos 100105. | Controle negativo confirmou fim do teste. | Registrar navegadores como fonte esperada de conexões em rajada. |

**Classificação:** atividade autorizada, baixa prioridade.
**Ativo/usuário:** Windows Server isolado; Edge.
**Melhoria de detecção:** avaliar processo, destino aprovado e volume antes de elevar severidade.

## Conclusão operacional

Os cinco estudos mostram que o Wazuh consegue coletar telemetria nativa, preservar contexto e apoiar uma decisão humana. Nenhuma evidência acima prova comprometimento; as recomendações de contenção são deliberadamente condicionadas a aprovação humana e ao contexto de produção.
