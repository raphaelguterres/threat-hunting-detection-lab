# Matriz de telemetria

| Fonte | Endpoint | Telemetria | Estado | Uso de investigação |
|---|---|---|---|---|
| `/var/log/wazuh-lab/events.log` | Linux | Eventos controlados em syslog | Validado | Exercitar regras locais e triagem. |
| FIM `/opt/wazuh-lab/monitorado` | Linux | Criação e alteração de arquivos | Configurado; sem alerta validado | Limitação de filesystem de contêiner. |
| SCA | Linux | Avaliação de postura | Executado | Identificar gaps de hardening. |
| `Security` | Windows Server | Autenticação e auditoria Windows | Configurado | Investigar logons e falhas de autenticação. |
| `System` | Windows Server | Eventos do sistema | Evento de teste confirmado localmente | Correlacionar alterações e falhas de serviço. |
| `Application` | Windows Server | Eventos de aplicações | Configurado | Contexto de aplicações e serviços. |
| `Microsoft-Windows-PowerShell/Operational` | Windows Server | Execução e metadados PowerShell | Configurado; execução de teste realizada | Investigar atividade de scripting. |
| `Microsoft-Windows-Sysmon/Operational` | Windows Server | Criação de processo, conexão e criação de arquivo | Coletor configurado; agente online; ID 11 confirmado localmente | Correlacionar IDs 1 e 11 no Manager antes de concluir a ingestão. |
| FIM em Startup | Windows Server | Mudança de arquivo e hashes | Validado ponta a ponta | Confirmar arquivo, horário e hashes antes/depois. |

## Lacunas e próxima validação

O Sysmon está instalado, o coletor do canal está no agente e o agente está online. A configuração e o procedimento seguro estão em [sysmon-deployment.md](sysmon-deployment.md), mas ainda falta comprovar no Manager a coleta de `Microsoft-Windows-Sysmon/Operational` com eventos IDs 1 e 11 correlacionados. Antes de criar detecções baseadas em árvore de processos ou conexões de rede no Windows, concluir essa validação ponta a ponta.

A próxima etapa independente é o FIM Linux fora de filesystem de contêiner; o roteiro está em [linux-fim-validation.md](../tests/linux-fim-validation.md).
