# M1 — proposta de emenda do escopo de inventário após descomissionamento

**Estado:** RASCUNHO — aguarda aprovação independente. Este documento não altera
scripts, manifestos, regras FIM, grupos, agentes, serviços ou o `DEPLOYMENT_GATE`.

## Fato operacional confirmado

Em 04/11/2026, após autorização explícita do operador, o cadastro legado `001` foi
removido pelo procedimento administrativo do Wazuh. A verificação sanitizada
posterior confirmou:

- `AGENT_001_REGISTERED=False`;
- `default` contém os IDs `002`, `004` e `005`;
- os três membros atuais estavam `active` e `synchronized` no checkpoint posterior.

O agente `003` permanece fora de `default` e não integra esta proposta. Não incluir
hosts, IPs, usuários, credenciais, hashes privados, capturas ou logs brutos neste
arquivo.

## Alteração proposta

Substituir o critério de inventário do contrato M1 de **quatro membros de
`default`** para **três membros atuais de `default`**. A alteração somente poderá
vigorar após aprovação independente e atualização revisada de documentação, testes
e manifesto privado. Até lá, o contrato 4/4 e o bloqueio fail-closed continuam
vigentes.

| Item | Contrato original | Proposta condicionada à aprovação |
| --- | --- | --- |
| Escopo | Quatro membros de `default` | Três membros atuais: `002`, `004`, `005` |
| Estado exigido | Todos `active` e `synced` | Todos `active` e `synced` |
| Dados exigidos | ID, SO+versão, grupos ordenados, horário/fuso e referência privada | Os mesmos campos, renovados para os três membros |
| Precedência | Revisão individual de grupos | Mantida; não inferir ordem a partir da contagem |
| Autoriza mudança FIM | Não | Não; continua exigindo os gates de baseline, rollback, janela e aprovação FIM |

## Condições para aprovação independente

O revisor deve confirmar, por evidência privada autorizada e recente:

- [ ] a remoção de `001` e a composição atual de `default`;
- [ ] ID, sistema operacional completo com versão, grupos na ordem, status, sync e
  horário com fuso dos três membros atuais;
- [ ] a ausência de outro agente no `default` ou de uma associação relevante não
  reconciliada;
- [ ] o impacto da redução do escopo sobre a precedência de grupos e a proposta
  `os="^Linux"`;
- [ ] a revisão do diff que atualizaria testes, importador e gate sem reduzir as
  exigências de evidência, backup, rollback, janela e autorização;
- [ ] que esta aprovação de escopo é distinta da aprovação operacional de FIM.

## Cartão de decisão

| Campo | Valor |
| --- | --- |
| Change ID | `M1-INVENTORY-SCOPE-3` |
| Proponente | Operador do laboratório |
| Revisor independente | **PENDENTE** |
| Data/hora e fuso da revisão | **PENDENTE** |
| Evidência privada examinada | **PENDENTE** |
| Decisão | **PENDENTE — contrato 4/4 permanece vigente** |
| Efeito no deployment FIM | **Nenhum; `DEPLOYMENT_GATE=BLOCKED`** |

## Próximo passo após aprovação

Somente após o cartão acima estar concluído por revisor independente: criar um diff
separado que atualize o contrato automatizado para três agentes, executar as
regressões completas e reenviar o manifesto privado com os dados renovados. Uma
saída estruturalmente válida continuará não autorizando deployment; a mudança FIM
precisa de aprovação, janela e rollback próprios.

Referências: [decisão do agente 001](m1-legacy-agent-001-decision.md),
[matriz de aceite FIM](m1-fim-acceptance-matrix.md), [pacote de aprovação FIM](m1-fim-change-approval-package.md) e [gate de evidências](m1-evidence-gate.md).
