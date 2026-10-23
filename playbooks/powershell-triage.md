# Playbook — Triagem de PowerShell

## Gatilho

Evento PowerShell fora do padrão do ativo ou alerta relacionado a scripting.

## Triagem

1. Identificar usuário, host, horário, comando e canal de origem.
2. Confirmar se o comando corresponde a administração ou automação aprovada.
3. Correlacionar com autenticação, criação de arquivo e conexões de rede no período.
4. Usar processo-pai e linha de comando completa quando Sysmon estiver disponível.
5. Registrar limitações: ausência de processo-pai não autoriza concluir intenção maliciosa.

## Resposta recomendada

Em caso suspeito, preservar os logs e recomendar bloqueio/isolamento apenas após aprovação humana. Não apagar scripts nem eventos antes da coleta de evidências.

Consulte a [governança de resposta](response-governance.md) antes de qualquer contenção.
