# Checklist de qualidade das detecções

Use este checklist antes de marcar qualquer um dos cinco casos como concluído. Ele complementa os casos existentes em `cases/01-login-failures.md` até `cases/05-network-anomaly.md`.

## Critérios por caso

| Caso | Fonte necessária | Teste positivo | Teste negativo | Estado atual |
| --- | --- | --- | --- | --- |
| Falhas de login | Autenticação nativa ou marcador sintético identificado | Tentativa única com usuário inexistente, regra 5710 | Não classificar o marcador sintético como login nativo | Telemetria nativa validada; correlação de repetição permanece pendente |
| Alteração de conta | Auditoria nativa de identidade | Criar/remover conta de serviço, regra 100104 | Consulta de identidade sem mudança não deve gerar alerta | Validado no Kali |
| PowerShell benigno | Sysmon ID 1 | Processo filho com marcador benigno, regra nativa 92027 | Execuções internas sem marcador permaneceram contexto distinto | Validado no Windows |
| Integridade de arquivo | Wazuh FIM | Alteração de arquivo monitorado com hash e horário | Arquivo fora do escopo não deve gerar alerta | FIM Kali nativo validado ponta a ponta |
| Conexão de rede | Sysmon ID 3 | Navegação autorizada do Edge para painel privado, regra 100105 | Período ocioso de 20 segundos sem novos eventos | Validado no Windows; múltiplas conexões na mesma navegação são falso positivo esperado |

## Artefato mínimo de aprovação

Para cada caso, registrar:

- consulta, regra ou filtro reproduzível;
- ativo e agente corretos;
- horário em fuso explícito;
- campos que relacionam o evento ao teste;
- justificativa de severidade e hipótese de triagem;
- resultado do teste negativo;
- captura ou saída redigida, sem credenciais, endereços privados desnecessários ou logs brutos.
- classificação explícita da evidência como `nativa` ou `marcador sintético`.
- referência ao registro de falso positivo, ou declaração explícita de que não houve falso positivo observado.

## Regra de encerramento

Marcador sintético comprova o pipeline, mas não substitui a validação de telemetria nativa quando ela é exigida pelo caso. Nenhum caso deve ser apresentado como cobertura ATT&CK validada sem a evidência correspondente.
