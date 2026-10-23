# Caso 02 — Criação ou alteração de conta

## Estado

Planejado. A fonte nativa de auditoria ainda precisa ser validada com um evento autorizado no endpoint Windows ou Linux não conteinerizado.

## Hipótese

Uma conta criada ou alterada fora do processo de mudança pode indicar abuso de privilégios ou persistência. O alerta precisa conter, no mínimo, conta afetada, ator, ativo e horário.

## Execução segura prevista

Criar e remover uma conta de teste exclusivamente na VM do laboratório, registrar o ticket/nota de mudança e confirmar a chegada do evento nativo ao Wazuh. Não usar contas existentes nem serviços expostos.

## Critério de conclusão

Registrar evidência positiva e negativa, a regra ou consulta utilizada e a linha do tempo completa: evento → alerta → triagem → encerramento.
