# Playbook — Triagem de conexão de rede

## Gatilho

Evento Sysmon ID 3, alerta de firewall ou telemetria equivalente indicando conexão incomum.

## Preservação de evidências

1. Registrar agente, horário com fuso, processo, processo-pai, origem, destino, porta e protocolo.
2. Salvar uma cópia redigida do alerta e correlacionar com processos, autenticação e FIM na mesma janela.
3. Confirmar se o destino pertence a serviço aprovado, manutenção ou simulação autorizada.

## Classificação

| Sinal | Interpretação inicial | Próxima ação |
| --- | --- | --- |
| Processo conhecido para destino aprovado | Atividade esperada | Registrar justificativa e encerrar. |
| Processo incomum, mas sem transferência ou repetição | Evidência insuficiente | Enriquecer contexto antes de conter. |
| Destino não aprovado, persistência ou transferência relevante | Suspeita priorizada | Acionar responsável e preparar contenção. |

Uma porta ou endereço isolado não prova exfiltração. Navegadores podem produzir conexões em rajada durante uma única navegação autorizada.

## Resposta recomendada

Preservar primeiro as evidências e recomendar bloqueio de destino ou isolamento do ativo somente com aprovação humana explícita. A aprovação precisa definir escopo, duração, impacto e rollback, conforme a [governança de resposta](response-governance.md). Não executar bloqueio automático neste laboratório.
