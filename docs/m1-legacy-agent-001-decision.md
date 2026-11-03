# M1 — decisão formal sobre o agente histórico 001

**Situação em 03/11/2026:** proposta de decisão, **nenhuma desativação nova ou exclusão executada**. Responsável pela decisão, aprovação e janela: **PENDENTES**.

## Evidência observada

Na interface autorizada do Wazuh Dashboard, o grupo `default` exibiu **4 membros**: IDs `001`, `002`, `004`, `005`. Os agentes `002` (Linux), `004` (Windows) e `005` (Linux) estavam **active** e suas páginas **Configuration** exibiam **SYNCHRONIZED**. O `001` permaneceu **disconnected**; seu último *keep-alive* visível era de **21/10/2026**, com fuso não exibido.

O operador escolheu **manter o antigo `001` desligado e preservar o histórico**, sem autorização para exclusão do cadastro. A listagem dos contêineres enviada anteriormente não incluía o contêiner legado; isso não autentica a situação de toda instalação possível.

O estado de conexão não substitui validação de sync. **A fotografia de 03/11 não deve ser usada como evidência atual após a janela de recência do gate.**

## Limite técnico importante do Wazuh

Segundo a [documentação oficial do `agent_groups`](https://documentation.wazuh.com/current/user-manual/reference/tools/agent-groups.html), remover um agente de **todos os grupos** faz com que ele **retorne ao `default`**. Logo, retirar `001` das associações sem um procedimento de descomissionamento **não o exclui do alcance da configuração central `default`**. Não utilizar alteração de grupo como forma de contornar o gate.

O [Wazuh documenta a remoção de agentes](https://documentation.wazuh.com/current/user-manual/agent/agent-management/remove-agents/index.html) como operação administrativa própria, diferente de parar um serviço ou conservar um cadastro desconectado. Nenhuma ação de remoção está autorizada nesta etapa.

## Rotas possíveis — escolha explícita do responsável

| Rota | Ação | Consequência para o M1 |
| --- | --- | --- |
| **A — preservar como histórico** | Manter `001` desconectado, cadastro e evidências intactos; **nenhuma ação operacional** | O gate atual, que exige **quatro membros ativos e sincronizados**, **permanece BLOCKED**. Não forçar `active` nem `synced` em CSV |
| **B — descomissionar formalmente** | Após aprovação separada e verificação de impacto, remover o cadastro antigo, preservando referências e evidências necessárias | **Não executar ainda.** Depois da operação autorizada, reconciliar de novo o grupo no Dashboard e submeter alteração **revisada** do contrato de inventário/gate para o novo escopo. Não alterar de 4 para 3 silenciosamente |
| **C — restaurar endpoint, se necessário** | Investigar o endpoint real e recuperar agente/comunicação sob change control próprio | Gate só avança depois de `active`, `synced`, grupo e tempo de observação confirmados; nunca assumir a recuperação |

**Decisão vigente:** A, **por ora**. A preferência do operador de não manter o agente ligado **não equivale a aprovar B**. O responsável pode revisar essa decisão expressamente.

## Pré-requisitos da rota B (somente preparação)

- [ ] Confirmar quem é o proprietário do endpoint antigo e se ainda existe carga, dependência, tarefa, alerta ou processo exigindo `001`
- [ ] Verificar implicações na retenção histórica, inventário, referências, relatórios e capacidade de re-enrollment; **não prometer que todos os registros sobreviverão à exclusão**
- [ ] Preservar capturas privadas, documentação de baseline e evidências com acesso restrito; não inserir chaves, credenciais, hosts ou IPs no repositório
- [ ] Designar executor autorizado, revisor independente, janela, passos e critério de parada
- [ ] Obter **aprovação expressa para a remoção do cadastro**, separada da aprovação da mudança FIM Linux
- [ ] Só após mudança autorizada, confirmar a contagem real do grupo e todos os agentes pela interface de administração
- [ ] Revisar em PR os testes/contratos que hoje exigem 4/4; executar regressões Windows/Ubuntu e obter revisão independente antes de qualquer aplicação FIM

## Estado dos gates

- **Manager / baseline atual:** parser e hash contra backup **PASS no checkpoint read-only de 03/11, 19h46**
- **Membros `default`:** 4/4 IDs confirmados pelo Dashboard; 3 agentes ativos sincronizados, 1 histórico desconectado
- **Critério atual `4/4 active + synced`:** **NÃO ATENDIDO**
- **Descomissionamento de `001`:** não aprovado, não executado
- **Revisão independente / janela / rollback operacional:** pendentes
- **Implantação FIM:** **NO-GO / DEPLOYMENT_GATE=BLOCKED**

Acompanhar esta decisão na [Issue #27](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/27) e a correção FIM na [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17).
