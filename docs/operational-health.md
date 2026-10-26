# Saúde operacional pós-roadmap

Este procedimento confirma que o laboratório continua apto a demonstrar telemetria depois de reinicializações ou alterações controladas. Ele não coleta credenciais, endereços internos nem logs brutos.

## Estado confirmado em 26/10/2026

| Componente | Resultado |
| --- | --- |
| Wazuh Manager | `wazuh-analysisd`, `wazuh-remoted`, `wazuh-logcollector`, `wazuh-db` e `wazuh-apid` em execução. |
| Endpoint Windows | Agente ativo no Manager. |
| Endpoint Kali nativo | Agente ativo no Manager. |
| Pipeline de validação | GitHub Actions concluído com sucesso para o commit de CI. |

## Checklist de retomada

1. Confirmar que as VMs estão em execução no VirtualBox.
2. Confirmar os agentes ativos no Manager, sem publicar endereços de rede.
3. Validar os serviços centrais do Manager.
4. Executar `scripts/validate_lab_config.ps1` localmente ou aguardar o workflow do GitHub Actions.
5. Se algum componente falhar, preservar o erro redigido antes de reiniciar serviços e registrar a ação em `docs/validation-log.md`.

## Critério de pronto para demonstração

O laboratório está pronto quando o Manager está saudável, os dois agentes aparecem ativos e a validação de configuração passa. Uma falha nesse checklist não deve ser mascarada por capturas antigas ou resultados de execuções anteriores.
