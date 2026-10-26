# Registro redigido de validações

Este registro resume validações feitas no laboratório sem publicar endereços privados, chaves, tokens, capturas brutas ou conteúdo integral de logs.

| Data | Componente | Ação controlada | Resultado no Manager | Classificação |
| --- | --- | --- | --- | --- |
| 24/10/2026 | Windows / Sysmon | Coleta do canal Sysmon habilitada e evento local ID 11 observado | Agente Windows ativo; 36 alertas do canal, incluindo IDs 1 e 11 | Telemetria nativa validada |
| 25/10/2026 | Kali nativo / FIM | Criar e alterar arquivo em diretório monitorado | Regras 554 e 550; hashes antes/depois na alteração | Telemetria nativa validada |
| 25/10/2026 | Kali nativo / FIM | Criar arquivo fora do escopo FIM | Zero alertas | Controle negativo validado |
| 25/10/2026 | Regras locais | Emitir os quatro marcadores `100100`–`100103` | Um alerta por regra no agente Kali nativo | Pipeline sintético validado |
| 25/10/2026 | Regras locais | Emitir linha sem assinatura de regra | Zero alertas | Controle negativo validado |
| 25/10/2026 | Kali / SSH | Uma tentativa de login com usuário inexistente | Regra nativa 5710, nível 5 | Telemetria nativa validada |
| 25/10/2026 | Kali / auditd | Criar e remover conta de serviço sem login | Regra local 100104, nível 8; 16 eventos de auditoria correlatos | Telemetria nativa validada |
| 25/10/2026 | Kali / auditd | Consultar identidade sem alterar conta | Contagem da regra 100104 permaneceu inalterada | Controle negativo validado |
| 25/10/2026 | Windows / Sysmon | Recarregar o painel HTTPS privado do Wazuh | ID 3 recebido para Edge; regra 100105, nível 3 | Telemetria nativa validada |
| 25/10/2026 | Windows / Sysmon | Período ocioso de 20 segundos após a navegação | Contagem da regra 100105 permaneceu inalterada | Controle negativo validado |
| 25/10/2026 | Windows / Sysmon | PowerShell filho com marcador benigno | Quatro eventos ID 1 pela regra nativa 92027, com comando, usuário e processo-pai | Telemetria nativa validada |
| 25/10/2026 | Windows / Sysmon | Execuções internas do agente sem marcador de laboratório | Eventos separados, sem o marcador controlado | Controle de contexto validado |
| 25/10/2026 | Saúde operacional | Consultar Manager após retomada das VMs | Agentes Windows e Kali nativo ativos | Pronto para os cenários restantes |

## Limites atuais

- Os marcadores `LAB_*` são simulações autorizadas e não comprovam a execução de técnica ATT&CK.
- PowerShell benigno foi validado como telemetria de processo; o marcador de laboratório não deve ser interpretado como atividade maliciosa.
- A validação de rede usa uma regra de baixo nível e contexto de processo; ela não classifica navegação autorizada como atividade maliciosa.
- Falhas de login e alterações de conta já possuem telemetria nativa no Kali; sua correlação com técnicas ATT&CK continua tratada como hipótese até haver contexto suficiente de produção.
