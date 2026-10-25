# Caso 02 — Criação ou alteração de conta

## Estado

Validado no Kali nativo em 25/10/2026. O `auditd` registrou a criação e remoção de uma conta de serviço sem login; a regra local `100104` gerou alertas de nível 8 no Manager. Uma consulta de identidade sem alteração manteve a contagem de alertas inalterada.

## Hipótese

Uma conta criada ou alterada fora do processo de mudança pode indicar abuso de privilégios ou persistência. O alerta precisa conter, no mínimo, conta afetada, ator, ativo e horário.

## Execução segura realizada

Foi criada e removida uma conta de serviço sem login, exclusivamente no Kali de laboratório. O `auditd` monitorou os arquivos de identidade e a regra usa a chave de auditoria `wazuh_lab_account_change`. Nenhuma conta existente ou serviço exposto foi alterado.

## Critério de conclusão

| Etapa | Evidência | Interpretação | Ação |
|---|---|---|---|
| Criação e remoção | Auditd registrou `useradd` e `userdel` | Mudança autorizada em conta temporária. | Conferir ator e conta afetada. |
| Alerta | Regra `100104`, nível 8, no agente Kali nativo | Mudança de identidade detectada pelo Manager. | Correlacionar com aprovação. |
| Controle negativo | Consulta de identidade sem mudança | Nenhum aumento na regra `100104`. | Não criar supressão. |

## Conclusão

O evento é uma simulação autorizada. Em produção, a mesma evidência exige confirmar o solicitante, a conta afetada e a aprovação antes de classificar como incidente.
