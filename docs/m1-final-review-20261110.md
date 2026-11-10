# M1 — evidências para a revisão final

Em 10/11/2026, o proprietário aprovou explicitamente as evidências de H01, H02 e H03 e o encerramento do M1 no laboratório individual. As três hipóteses foram validadas em testes autorizados com eventos reais. O checklist foi concluído em **17/17**.

| Hipótese | Evidência | Controles |
| --- | --- | --- |
| H01 — PowerShell e criação de tarefa | O mesmo ator executou o PowerShell e criou uma tarefa desabilitada no mesmo ativo. A tarefa foi removida. [Relatório H01](m1-h01-controlled-correlation-20261110.md) | Um par positivo e zero pares com o evento anterior usado como negativo. |
| H02 — criação de conta e logon privilegiado | O Windows e o Wazuh confirmaram cinco registros, com SID comum e Logon ID verificado em cada sessão. [Relatório H02](m1-h02-controlled-correlation-20261110.md) | Dois pares positivos e zero correspondências em dois cruzamentos com Logon IDs diferentes. |
| H03 — alteração e execução de arquivo | A alteração e a execução do mesmo binário benigno foram confirmadas no Wazuh. [Relatório H03](m1-h03-controlled-binary-validation-20261110.md) | Um par positivo e zero no controle negativo. |

O registro é um aceite do proprietário para o encerramento do M1. O [guia de revisão independente](m1-pr-review-guide.md) continua aplicável ao PR que ele descreve. A remoção da conta temporária do H02 segue sem confirmação.
