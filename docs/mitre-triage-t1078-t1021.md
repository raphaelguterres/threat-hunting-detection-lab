# Triagem MITRE: credenciais válidas e serviços remotos

## Evidência observada no laboratório

Em 26/10/2026, a visão **MITRE ATT&CK > Events** do Dashboard exibiu eventos do agente Linux nativo mapeados para `T1078` e `T1021`. Eles correspondiam a sessões SSH administrativas no ambiente isolado do laboratório.

Esse é um exemplo útil porque o mesmo conjunto de registros pode ter **duas classificações ATT&CK**:

| Elemento | O que significa | O que não significa sozinho |
| --- | --- | --- |
| [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Uma conta válida foi usada para autenticação. | Que a conta foi comprometida ou que houve elevação de privilégio. |
| [T1021 — Remote Services](https://attack.mitre.org/techniques/T1021/) | O acesso ocorreu por um serviço remoto, como SSH. | Que toda sessão SSH é movimento lateral malicioso. |

MITRE ATT&CK é uma linguagem para descrever o comportamento observado; não é um veredito de incidente. Uma técnica, isoladamente, não determina a intenção nem a severidade.

## Raciocínio de triagem

Para decidir se um alerta de `T1078`/`T1021` é relevante, o analista deve responder:

1. **Conta:** é uma conta esperada para essa administração? Houve mudança recente de senha, grupo ou privilégio?
2. **Origem e destino:** o acesso veio da rede host-only prevista e atingiu um ativo autorizado?
3. **Tempo:** o horário coincide com uma janela de manutenção ou atividade documentada?
4. **Volume:** quantidade, duração e falhas anteriores diferem do padrão da conta?
5. **Sequência:** há sinais posteriores de persistência, elevação de privilégio, transferência de arquivos ou execução suspeita?

No recorte observado, as sessões foram autorizadas para operar o próprio laboratório. A decisão correta é **benigno esperado com evidência preservada**, e não a supressão ampla de SSH, `T1078` ou `T1021`.

## Como registrar a decisão

Se for necessária uma exceção futura, ela deve ser estreita e ter:

- conta e origem específicas;
- janela temporal e motivo de mudança;
- proprietário/aprovador;
- data de expiração e reteste.

Não use somente o ID MITRE, o nome do processo ou a porta 22 como base para silenciar alertas. Isso apagaria também o sinal de uso indevido de credenciais reais.

## Relação com a telemetria do lab

O Dashboard mantém esses eventos pesquisáveis por técnica e agente. A análise deve abrir o evento original e correlacionar campos de autenticação, usuário, origem e histórico de alertas antes de qualquer conclusão ou resposta.

## Triagem remota executada em 26/10/2026

Foi feita uma triagem somente leitura no Manager para um alerta SSH `5715` mapeado para `T1078` e `T1021`.

| Critério | Evidência verificada | Resultado |
| --- | --- | --- |
| Conta | `root` autenticado por chave pública. | Conta de administração do lab; exige acompanhamento reforçado, mas não indica comprometimento por si só. |
| Origem | Conexão vinda da rede host-only de gerenciamento. | Origem esperada para o orquestrador das VMs. |
| Autenticidade | A impressão digital registrada no `sshd` coincidiu com a chave `wazuh-lab-orchestrator`. | Acesso atribuído à automação administrativa autorizada. |
| Horário | Alertas foram gerados durante esta sessão de manutenção documentada. | Compatível com a atividade aprovada. |
| Volume | 36 autenticações com esse padrão estavam no arquivo atual de alertas. | Volume explicável pelas verificações e automações; manter baseline para detectar desvios. |
| Eventos seguintes | Sequência observada: autenticação bem-sucedida, abertura PAM e encerramento de sessão. | Nenhuma evidência correlata de persistência, transferência de dados ou mudança de privilégio foi encontrada nesta sequência revisada. |

**Decisão:** benigno esperado / atividade administrativa autorizada. Os alertas permanecem pesquisáveis; não foi criada supressão por técnica, porta, usuário ou IP. Uma nova triagem é necessária se a conta, a origem, a chave, a janela de mudança ou a sequência de ações mudar.
