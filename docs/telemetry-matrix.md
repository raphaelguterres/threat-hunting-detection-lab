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
| FIM em Startup | Windows Server | Mudança de arquivo e hashes | Validado ponta a ponta | Confirmar arquivo, horário e hashes antes/depois. |

## Lacunas e próxima validação

Sysmon ainda não está instalado. Antes de criar detecções baseadas em árvore de processos ou conexões de rede no Windows, instalar Sysmon no endpoint do laboratório, habilitar a coleta de `Microsoft-Windows-Sysmon/Operational` e validar um evento inofensivo de cada tipo necessário.
