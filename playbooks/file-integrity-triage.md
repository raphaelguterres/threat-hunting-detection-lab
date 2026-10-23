# Playbook — Triagem de alteração de integridade

## Gatilho

Alerta FIM com caminho, tipo de mudança e hashes antes/depois.

## Triagem

1. Preservar os detalhes do alerta: agente, horário, caminho e hashes.
2. Confirmar proprietário e finalidade do arquivo.
3. Procurar mudança aprovada para a mesma janela de tempo.
4. Correlacionar com eventos de processo, autenticação e rede do ativo, se a telemetria existir.
5. Classificar como mudança autorizada, alteração suspeita ou evidência insuficiente.

## Resposta

Não modificar ou remover o arquivo automaticamente. Para uma alteração suspeita, recomendar isolamento e coleta forense somente após aprovação humana, conforme procedimento da organização. Registrar toda decisão e o plano de rollback.

Consulte a [governança de resposta](response-governance.md) antes de qualquer contenção.
