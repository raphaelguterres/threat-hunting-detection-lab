# Checklist de qualidade das detecções

Use este checklist antes de marcar qualquer um dos cinco casos como concluído. Ele complementa os casos existentes em `cases/01-login-failures.md` até `cases/05-network-anomaly.md`.

## Critérios por caso

| Caso | Fonte necessária | Teste positivo | Teste negativo | Estado atual |
| --- | --- | --- | --- | --- |
| Falhas de login | Autenticação nativa ou marcador sintético identificado | Evento com conta, origem e horário | Atividade sem repetição não deve receber a mesma classificação | Pipeline sintético validado; telemetria nativa pendente |
| Alteração de conta | Auditoria nativa de identidade | Mudança autorizada em conta de teste | Consulta sem mudança não deve gerar alerta | Pendente |
| PowerShell benigno | PowerShell Operational e/ou Sysmon ID 1 | Comando administrativo inofensivo correlacionado | Processo sem PowerShell não deve ser rotulado como PowerShell | Pendente no Wazuh |
| Integridade de arquivo | Wazuh FIM | Alteração de arquivo monitorado com hash e horário | Leitura/listagem sem escrita | FIM Windows observado; consolidar evidência redigida |
| Conexão de rede | Sysmon ID 3 ou telemetria equivalente | Conexão única para destino privado autorizado | Sem conexão não deve produzir evento | Pendente no Wazuh |

## Artefato mínimo de aprovação

Para cada caso, registrar:

- consulta, regra ou filtro reproduzível;
- ativo e agente corretos;
- horário em fuso explícito;
- campos que relacionam o evento ao teste;
- justificativa de severidade e hipótese de triagem;
- resultado do teste negativo;
- captura ou saída redigida, sem credenciais, endereços privados desnecessários ou logs brutos.

## Regra de encerramento

Marcador sintético comprova o pipeline, mas não substitui a validação de telemetria nativa quando ela é exigida pelo caso. Nenhum caso deve ser apresentado como cobertura ATT&CK validada sem a evidência correspondente.
