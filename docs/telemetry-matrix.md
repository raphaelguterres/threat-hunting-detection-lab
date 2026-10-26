# Matriz de telemetria

| Fonte | Endpoint | Telemetria | Estado | Uso de investigação |
|---|---|---|---|---|
| `/var/log/wazuh-lab/events.log` | Linux | Eventos controlados em syslog | Validado | Exercitar regras locais e triagem. |
| FIM `/opt/wazuh-lab/monitorado` | Kali nativo | Criação e alteração de arquivos | Validado ponta a ponta: regras 554 e 550 no Manager | Investigar caminho, timestamp e checksum alterado. |
| SCA | Linux | Avaliação de postura | Executado | Identificar gaps de hardening. |
| `Security` | Windows Server | Autenticação e auditoria Windows | Configurado | Investigar logons e falhas de autenticação. |
| `System` | Windows Server | Eventos do sistema | Evento de teste confirmado localmente | Correlacionar alterações e falhas de serviço. |
| `Application` | Windows Server | Eventos de aplicações | Configurado | Contexto de aplicações e serviços. |
| `Microsoft-Windows-PowerShell/Operational` | Windows Server | Execução e metadados PowerShell | Configurado; contexto de processo validado pelo Sysmon ID 1 | Investigar atividade de scripting. |
| `Microsoft-Windows-Sysmon/Operational` | Windows Server | Criação de processo, conexão e criação de arquivo | Validado ponta a ponta: IDs 1, 3 e 11 | Correlacionar processo, rede, hashes e criação de arquivo nas investigações. |
| FIM em Startup | Windows Server | Mudança de arquivo e hashes | Validado ponta a ponta | Confirmar arquivo, horário e hashes antes/depois. |

## Lacunas e próxima validação

O Sysmon está instalado, o coletor do canal está no agente e os IDs 1, 3 e 11 foram recebidos no Manager para o agente Windows. A configuração e o procedimento seguro estão em [sysmon-deployment.md](sysmon-deployment.md). As investigações associadas estão em [case-study-timelines.md](case-study-timelines.md).

A validação FIM Linux foi transferida para o agente nativo `kali-native-fim`, fora do filesystem de contêiner. A criação do arquivo controlado gerou a regra 554 e sua alteração gerou a regra 550 no Manager. A próxima etapa independente é criar e validar as detecções locais.
