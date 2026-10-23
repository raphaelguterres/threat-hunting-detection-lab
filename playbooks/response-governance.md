# Governança de resposta e preservação de evidências

Este checklist se aplica aos playbooks de autenticação, PowerShell e integridade. Ele não executa contenção automática.

## Antes da decisão

- Registrar agente, ativo, regra, severidade e horário com fuso explícito.
- Salvar uma cópia redigida do alerta e dos campos necessários à correlação.
- Confirmar se há simulação autorizada, manutenção ou mudança aprovada na mesma janela.
- Separar fatos observados de hipótese investigativa.

## Aprovação humana

As ações abaixo exigem aprovação explícita de responsável autorizado:

| Ação proposta | Informação mínima para aprovar | Rollback planejado |
| --- | --- | --- |
| Isolar endpoint | ativo, impacto esperado, janela e evidência | reconectar segundo procedimento aprovado |
| Bloquear origem | escopo, duração, evidência e risco de bloqueio indevido | remover bloqueio e registrar motivo |
| Redefinir/revogar credencial | identidade afetada, risco e responsável | restaurar acesso por processo de identidade |
| Alterar/remover arquivo | hash, proprietário, impacto e cópia preservada | restaurar backup verificado |

## Durante a resposta

1. Preservar eventos, hashes e linha do tempo antes de modificar o ativo.
2. Anotar quem aprovou, quando e qual escopo foi autorizado.
3. Executar somente a ação aprovada e observar o resultado.
4. Se o efeito divergir do esperado, interromper novas ações e reavaliar.

## Encerramento

- Registrar resultado, limitações e reversão executada ou não necessária.
- Atualizar o estudo de caso associado sem incluir segredos, dados pessoais ou endereços privados desnecessários.
- Transformar lacunas recorrentes em melhoria de telemetria, regra ou playbook.
