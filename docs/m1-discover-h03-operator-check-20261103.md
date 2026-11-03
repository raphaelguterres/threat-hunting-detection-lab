# M1 — roteiro e checkpoint do Discover / FIM H03

**Data:** 03/11/2026. **Escopo:** laboratório autorizado, verificações somente leitura.

## Evidência visual observada nesta retomada

- Dashboard Wazuh `Overview` carregado numa sessão já autenticada. Visão mostrou **3 agentes ativos, 1 desconectado**; contagens da interface para as últimas 24h: **114 críticos**, **0 altos**, **17.223 médios** e **6.214 baixos**. Níveis de alerta, não incidentes confirmados.
- A navegação para `/app/discover` na mesma sessão carregou a página funcional **Discover**, com data view `wazuh-alerts-*`, filtro padrão **Last 24 hours** e **23.549 hits** na tela naquele instante.
- Registros do agente Windows `004` estavam visíveis na tabela de Discover, confirmando apenas dados indexados desse agente nessa janela; a tela mostrava dados de eventos Windows, não FIM comprovado.
- Evidências de tela privadas mantidas em `.lab/`; nenhum evento bruto, hostname ou IP publicado neste relatório.

## Próximo filtro de investigação (pendente)

No campo DQL do Discover, pesquisar `agent.id:"004" and syscheck.path:*`, aplicar a pesquisa, registrar a contagem e a janela UTC. Comparar somente após conferência da semântica do filtro com um controle positivo `agent.id:"004"`. Repetir na janela histórica 31/10 00:00Z a 03/11 00:00Z e na janela atual, registrando ambos os resultados separadamente. Se a interface não reconhecer `syscheck.path`, revisar o mapeamento do campo na sessão, sem inventar ausência de FIM.

Uma contagem FIM não confirma H03: exige evento Sysmon ID 1 de execução do **mesmo artefato e ativo**, em ordem temporal até 20 minutos, com revisão humana de evidência privada. Nenhum evento de teste deve ser gerado sem autorização.

**Resultado:** `DISCOVER_UI=AVAILABLE_AUTHENTICATED`; `AGENT_004_EVENTS=VISIBLE`; `FIM_004_CURRENT_COUNT=NOT_CHECKED`; `H03=INCONCLUSIVE`; `DEPLOYMENT_GATE=BLOCKED`. Sem alteração de serviços, regras, política de auditoria ou configuração ativa.
