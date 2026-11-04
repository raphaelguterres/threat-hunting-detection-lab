# M1 — decisão formal sobre o agente histórico 001

**Atualização operacional em 04/11/2026:** a rota B foi autorizada expressamente pelo operador e executada. A verificação posterior sanitizada confirmou `AGENT_001_REGISTERED=False`; o grupo `default` agora contém `002`, `004` e `005`, todos `active` e `synchronized`. A remoção não libera mudança FIM e não reescreve o contrato de inventário 4/4 sem revisão independente.

**Registro histórico de 03/11/2026:** este documento era uma proposta de decisão, quando nenhuma desativação ou exclusão havia sido executada.

## Evidência observada

Na interface autorizada do Wazuh Dashboard, o grupo `default` exibiu **4 membros**: IDs `001`, `002`, `004`, `005`. Os agentes `002` (Linux), `004` (Windows) e `005` (Linux) estavam **active** e suas páginas **Configuration** exibiam **SYNCHRONIZED**. O `001` permaneceu **disconnected**; seu último *keep-alive* visível era de **21/10/2026**, com fuso não exibido.

Naquele checkpoint, o operador escolheu **manter o antigo `001` desligado e preservar o histórico**, sem autorização para exclusão do cadastro. Essa decisão foi posteriormente revisada de modo explícito para a rota B em 04/11.

O estado de conexão não substitui validação de sync. **A fotografia de 03/11 não deve ser usada como evidência atual após a janela de recência do gate.**

## Limite técnico importante do Wazuh

Segundo a [documentação oficial do `agent_groups`](https://documentation.wazuh.com/current/user-manual/reference/tools/agent-groups.html), remover um agente de **todos os grupos** faz com que ele **retorne ao `default`**. Logo, retirar `001` das associações sem um procedimento de descomissionamento **não o exclui do alcance da configuração central `default`**. Não utilizar alteração de grupo como forma de contornar o gate.

O [Wazuh documenta a remoção de agentes](https://documentation.wazuh.com/current/user-manual/agent/agent-management/remove-agents/index.html) como operação administrativa própria, diferente de parar um serviço ou conservar um cadastro desconectado. Essa operação foi autorizada e concluída em 04/11; não autoriza outras mudanças no Manager.

## Rotas possíveis — escolha explícita do responsável

| Rota | Ação | Consequência para o M1 |
| --- | --- | --- |
| **A — preservar como histórico** | Manter `001` desconectado, cadastro e evidências intactos; **nenhuma ação operacional** | O gate atual, que exige **quatro membros ativos e sincronizados**, **permanece BLOCKED**. Não forçar `active` nem `synced` em CSV |
| **B — descomissionar formalmente** | Após aprovação expressa, remover o cadastro antigo, preservando referências e evidências necessárias | **Executada em 04/11.** O estado posterior foi reconciliado no Manager; submeter alteração **revisada** do contrato de inventário/gate para o novo escopo. Não alterar de 4 para 3 silenciosamente |
| **C — restaurar endpoint, se necessário** | Investigar o endpoint real e recuperar agente/comunicação sob change control próprio | Gate só avança depois de `active`, `synced`, grupo e tempo de observação confirmados; nunca assumir a recuperação |

**Decisão vigente:** B, concluída em 04/11 após autorização expressa do operador. O aceite do novo escopo continua pendente de revisão independente.

## Pré-requisitos e registro da rota B

- [ ] Confirmar quem é o proprietário do endpoint antigo e se ainda existe carga, dependência, tarefa, alerta ou processo exigindo `001`
- [ ] Verificar implicações na retenção histórica, inventário, referências, relatórios e capacidade de re-enrollment; **não prometer que todos os registros sobreviverão à exclusão**
- [ ] Preservar capturas privadas, documentação de baseline e evidências com acesso restrito; não inserir chaves, credenciais, hosts ou IPs no repositório
- [ ] Designar executor autorizado, revisor independente, janela, passos e critério de parada
- [x] Obter **aprovação expressa para a remoção do cadastro**, separada da aprovação da mudança FIM Linux
- [x] Após a mudança autorizada, confirmar a ausência do cadastro `001` e a composição/status/sync atuais de `default` por verificação sanitizada no Manager
- [ ] Revisar em PR os testes/contratos que hoje exigem 4/4; executar regressões Windows/Ubuntu e obter revisão independente antes de qualquer aplicação FIM

## Estado dos gates

- **Manager / baseline atual:** parser e hash contra backup **PASS no checkpoint read-only de 03/11, 19h46**
- **Membros `default`:** três IDs atuais (`002`, `004`, `005`), todos ativos e sincronizados; `001` não está mais registrado
- **Critério original `4/4 active + synced`:** **NÃO ATENDIDO** até revisão formal de escopo
- **Descomissionamento de `001`:** autorizado e executado em 04/11
- **Revisão independente / janela / rollback operacional:** pendentes
- **Implantação FIM:** **NO-GO / DEPLOYMENT_GATE=BLOCKED**

Acompanhar esta decisão na [Issue #27](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/27) e a correção FIM na [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17).
