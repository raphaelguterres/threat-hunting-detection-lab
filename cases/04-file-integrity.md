# Caso 04 — Alteração de integridade no Windows

## Objetivo

Demonstrar investigação de uma alteração controlada de arquivo monitorado pelo Wazuh no Windows Server.

## Evidência validada

- Ativo: agente Windows `004` em estado Active.
- Arquivo de laboratório: `wazuh-fim-lab.txt` no diretório Startup monitorado.
- Decoder: `syscheck_integrity_changed`.
- Evidência: `../evidencias/kali-alerts-agent004.png`, contendo caminho e hashes antes/depois.

## Linha do tempo de investigação

| Etapa | Evidência | Interpretação |
|---|---|---|
| Criação/alteração | Comandos de teste registrados no endpoint | Mudança autorizada no escopo do laboratório. |
| Coleta | Alerta FIM recebido no Manager | Pipeline do endpoint ao Manager confirmado. |
| Triagem | Caminho e hashes antes/depois | Alteração identificável e reproduzível. |
| Encerramento | Registro como simulação autorizada | Não requer contenção. |

## Lições

FIM informa que o arquivo mudou, mas não prova sozinho a intenção. Em produção, a decisão depende de proprietário do arquivo, ticket de mudança, conta envolvida, processo correlato e criticidade do ativo.
