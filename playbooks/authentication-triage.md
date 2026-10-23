# Playbook — Triagem de falhas de autenticação

## Gatilho

Várias falhas para a mesma conta ou origem em uma janela curta.

## Triagem

1. Confirmar se a telemetria é nativa ou um marcador de laboratório.
2. Identificar conta alvo, origem, quantidade e intervalo das tentativas.
3. Procurar autenticação bem-sucedida posterior e eventos no mesmo endpoint.
4. Verificar se há manutenção, troca de senha ou teste autorizado.
5. Classificar a confiança e registrar a justificativa.

## Resposta recomendada

Em incidente confirmado, preservar eventos, aplicar controles previstos pela organização (por exemplo, bloqueio temporário ou redefinição de credencial) somente com aprovação humana e registrar o rollback.

Consulte a [governança de resposta](response-governance.md) antes de qualquer contenção.
