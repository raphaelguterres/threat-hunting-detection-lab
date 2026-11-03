# M1 — diagnóstico de conectividade Wazuh (03/11/2026)

**Método:** sondagens passivas de conexão TCP e requisições HTTPS sem credenciais a endpoints do laboratório autorizado. Sem alterações em VMs, serviços, Wazuh, Docker, agentes, regras ou auditoria.

## Resultados observados

- VirtualBox: VMs `WindowsServer` e Kali ativas no momento da verificação.
- Kali: rede host-only conectada e alcançável pelo host Windows. Endereço preciso mantido fora da documentação publicada.
- Dashboard HTTPS (443): porta TCP acessível; GET `/` retornou `302`.
- GET `/app/discover`: `302` com redirecionamento para `/app/login?nextUrl=%2Fapp%2Fdiscover`.
- GET `/api/status`: `401` sem credenciais; **não** é prova de falha do serviço.
- Indexer HTTPS (9200): TCP acessível; GET `/` retornou `401` sem credenciais.
- Wazuh Manager (1514/1515) e API (55000): portas TCP acessíveis; GET da API em `/` retornou `401` sem credenciais.

## Limites e decisão

Conectividade e proteção por autenticação foram observadas. **Não foi comprovada disponibilidade funcional do Discover após login**, nem foram consultadas novas contagens FIM no Indexer. `401` e `302` não provam saúde de backend, integridade de pipeline ou ausência de alertas. O aviso anterior `Wazuh dashboard server is not ready yet` continua como pendência operacional até revisão autenticada, sem registrar credenciais ou exportar eventos.

Próximo passo autorizado: operador acessar normalmente o Dashboard e conferir visualização Discover, janelas UTC e contagens sanitizadas de `syscheck.path` para agente `004`; em caso de falha, diagnosticar serviços e logs no Kali apenas em modo leitura, sem reinícios automáticos.

**H03:** `INCONCLUSIVE`; **DEPLOYMENT_GATE:** `BLOCKED`. Nenhuma detecção real validada por estas sondagens.
