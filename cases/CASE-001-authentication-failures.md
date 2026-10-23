# CASE-001 — Falhas de autenticação

## Situação

**Estado:** estruturado; não concluir sem evento nativo redigido.

## Hipótese de investigação

Falhas repetidas em uma conta de teste podem representar erro operacional ou tentativa de adivinhação de senha. A classificação exige contexto de origem, janela de tempo e eventual sucesso posterior.

## Evidência exigida

- Ativo, conta de teste e fonte de log.
- Horários das falhas e de eventual login bem-sucedido.
- Regra/consulta Wazuh e campos redigidos.

## Linha do tempo

| Horário | Evento | Fonte | Observação |
| --- | --- | --- | --- |
| Pendente | Falhas controladas | Autenticação nativa | Não executar fora do laboratório |

## Classificação e ação

Classificar como teste autorizado enquanto a conta e a janela coincidirem com o plano. Fora desse contexto, preservar logs e encaminhar para triagem de autenticação.
