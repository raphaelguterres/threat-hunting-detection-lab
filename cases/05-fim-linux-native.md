# Caso 05 — Alteração FIM em endpoint Linux nativo

## Objetivo

Validar a detecção de criação e alteração de arquivo em um endpoint Linux fora de contêiner, com evidência de hashes e um controle negativo.

## Fonte e regra

- Endpoint: `kali-native-fim` (agente Wazuh nativo).
- Diretório monitorado: `/opt/wazuh-lab/monitorado`.
- Evento positivo de criação: regra `554`, nível 5.
- Evento positivo de alteração: regra `550`, nível 7.
- Controle negativo: `/opt/wazuh-lab/fora-do-escopo/fim-negative-control.txt`.

## Evidência observada

O Manager recebeu dois eventos para `fim-native-validation.txt`: um de criação e outro de alteração. O segundo trouxe hashes MD5 e SHA-256 antes/depois diferentes, compatíveis com a modificação controlada. O arquivo criado fora do escopo FIM retornou zero alertas no Manager.

## Linha do tempo de investigação

| Etapa | Evidência | Interpretação | Próxima ação |
|---|---|---|---|
| Criação controlada | Regra 554 para o arquivo monitorado | O agente está enviando eventos FIM do filesystem nativo. | Conferir caminho e responsável pela mudança. |
| Alteração controlada | Regra 550, nível 7, hashes antes/depois | Houve mudança de conteúdo real no arquivo monitorado. | Comparar com mudança aprovada e preservar hashes. |
| Controle fora do escopo | Zero alertas | A regra não está gerando ruído para todo `/opt`. | Manter o escopo mínimo e revisar novas exceções. |

## Conclusão

O caso é uma detecção FIM válida para o laboratório. Ele não indica incidente por si só: a decisão de escalonar depende de contexto, aprovação de mudança, proprietário do arquivo e criticidade do caminho afetado.
