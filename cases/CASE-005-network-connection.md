# CASE-005 — Conexão de rede autorizada

## Situação

**Estado:** estruturado; aguarda telemetria Sysmon ID 3 no Wazuh.

## Hipótese de investigação

Uma conexão de rede pode ser esperada para o serviço do laboratório ou exigir análise. Não atribuir técnica ATT&CK apenas a partir do endereço/porta; validar processo, destino autorizado, volume e contexto.

## Evidência exigida

- Serviço de destino privado previamente autorizado.
- Sysmon ID 3 local e cópia no Wazuh.
- Processo, origem, destino, porta e horário correlacionados.

## Linha do tempo

| Horário | Evento | Fonte | Observação |
| --- | --- | --- | --- |
| Pendente | Conexão privada única e autorizada | Sysmon ID 3 | Não usar destino externo |

## Classificação e ação

Classificar como esperada quando houver correspondência com o serviço autorizado. Caso contrário, preservar contexto e abrir investigação de rede.
