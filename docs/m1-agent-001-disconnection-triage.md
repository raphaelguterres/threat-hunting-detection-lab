# M1 — triagem somente leitura do agente desconectado e inventário preliminar

**Checkpoint: 03/11/2026. Status: NO-GO.** Este roteiro não altera agentes, grupos, configuração, redes, Docker, Windows, Wazuh ou autorizações.

O inventário preliminar recebido do operador mostra **4 agentes listados**, com **3 ativos e 1 desconectado**, mas não prova que todos estejam no grupo `default`. A outra captura incluía uma linha adicional `never connected` sem ID; **não atribuir identidade a essa linha por suposição**. O relatório público usa contagens, sem hostnames ou endereços.

## Por que o agente desconectado não deve ser reiniciado automaticamente

Segundo [Wazuh — Agent life cycle](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/agent-life-cycle.html), o Manager considera um agente **disconnected** se não receber mensagens *keep alive* dentro do tempo configurado (15 minutos por padrão). Isso **não determina a causa**: pode ser endpoint desligado, agente parado, conectividade interrompida, endereço/registro antigo ou outras condições. Exigir o horário de último contato e observações do responsável antes de concluir.

O [status de sincronização de grupo](https://documentation.wazuh.com/current/user-manual/agent/agent-management/agent-connection.html) é uma checagem **diferente** do status de conexão; a interface pode não mostrar todos os campos. **Nunca inferir `synced` de `active` ou de uma configuração idêntica num checkpoint anterior**.

## Primeiro: conferência no Dashboard autorizado (sem ação de escrita)

1. **Agents management → Groups → default:** abrir a listagem **dos membros desse grupo** e registrar os IDs. Confirmar se o agente `001` pertence ao grupo; não deduzir isso a partir de uma lista geral.
2. **Agents management → Summary → ID 001 (ícone de visualização):** conferir status atual, último *keep alive*/contato (horário com fuso, se visível) e detalhes de SO. Registrar apenas o que estiver na interface. Se persistir desconectado, verificar com o responsável se o endpoint correspondente deveria estar ligado — sem reiniciar serviços automaticamente.
3. **Demais membros:** conferir grupos atribuídos em **ordem de precedência**; o último grupo atribuído tem prioridade quando há conflito de configurações ([Wazuh — Grouping agents](https://documentation.wazuh.com/current/user-manual/agent/agent-management/grouping-agents.html)). Se a ordem ou o status de sincronização não aparecer, manter **NOT_VERIFIED** e solicitar comprovação por meio autorizado.
4. **Data da captura:** anotar horário real da observação, com fuso. Não usar o horário de envio no chat como se fosse o timestamp do Wazuh. Preservar capturas em `.lab/`; remover IPs/hostnames antes de divulgar resultados.

## Diagnóstico diferencial — não presumir a causa

| Evidência observada | Significado possível | Próxima ação **sem alteração** |
| --- | --- | --- |
| `001` fora de `default` | Não é um dos quatro membros do escopo proposto | Encontrar os quatro IDs reais desse grupo, sem tratar a lista geral como inventário formal |
| `001` em `default` e desconectado | Configuração recente pode não ter sido recebida | Documentar último contato, responsável e condição do endpoint; gate continua NO-GO |
| `001` ativo, mas sync desconhecido | Conexão não comprova distribuição de configuração | Solicitar status de sincronização/merged config pela via autorizada; não marcar `synced` |
| Quatro membros ativos e grupo confirmado | Ainda podem existir conflitos de precedência e outros riscos | Completar ordem de grupos, referências e revisão independente antes do gate |
| Console não exibe membros, última conexão ou precedência | Evidência insuficiente | Registrar campo **NOT_VERIFIED**; não tentar contornar permissão por API/CLI/arquivos |

## Etapa separada para observações parciais

O operador pode registrar **somente** a lista já observada, mesmo contendo desconectados e campos desconhecidos, no arquivo ignorado pelo Git `.lab/m1-dashboard-observations-20261103.json`. Os campos `groups_ordered`, `group_sync`, `last_keepalive` e `observed_at` permanecem `null` / `unverified` enquanto não houver evidência. O arquivo é um **rascunho de triagem**, **não substitui** `.lab/m1-agent-inventory.csv` nem o manifesto do gate.

Para obter um relatório **agregado, sem escrever em nenhum arquivo**:

```powershell
python scripts/m1_observed_agents_triage.py --snapshot .lab/m1-dashboard-observations-20261103.json
```

A execução exibe quantidades por família de SO, status e lacunas, mas **não imprime IDs, endereços, nomes, referências de captura ou horários individuais**. Qualquer combinação dos dados resulta em `DEPLOYMENT_GATE=BLOCKED` e `GROUP_MEMBERSHIP_ATTESTED=false`, inclusive um exemplo com quatro agentes ativos e grupos preenchidos. A autenticidade só pode ser aferida na revisão humana.

**Não executar `m1_import_authorized_inventory.py --apply` com esse rascunho.** Aquele importador exige os **quatro membros reais** de `default`, todos `active/synced`, com observações e ordem de grupos comprovadas. Mesmo após o importador, autorização de mudança FIM e aprovação independente seguem obrigatórias.

## Estado atual / saída de controle

- Observado: três Linux, um Windows; três ativos, um desconectado
- `default` membros confirmados **por captura de grupo**: pendente
- `001` último *keep alive*: não exibido nas capturas disponíveis
- Sync individual e ordem de grupos: pendentes
- Aprovação do FIM, janela, rollback operacional e PR independente: pendentes
- **Decisão:** `NO-GO / DEPLOYMENT_GATE=BLOCKED`; não implantar, não reiniciar preventivamente e não simular evidências

Relacionado: [roadmap](roadmap-progress.md), [matriz FIM](m1-fim-acceptance-matrix.md), [roteiro de inventário](m1-agent-inventory-operator-runbook.md), [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17).
