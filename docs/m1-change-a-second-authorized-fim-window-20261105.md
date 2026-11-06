# M1 — segunda janela autorizada para validação FIM (05/11/2026)

**Mudança:** `M1-FIM-OS-SCOPE`. **Autorização:** proprietário do laboratório, expressa na conversa, para prosseguir com validação FIM benigna por 30 minutos. **Janela:** 05/11, **13h55min48s a 14h25min48s BRT** (UTC 16h55min48s–17h25min48s). Não constitui autorização para mudanças de regras, alteração de auditoria 4698, H03, reinstalação de agente, restart de VM/serviço, uso de credenciais por terceiros ou merge.

## Resultado técnico — Windows 004

- VM Windows Server encontrada em execução; terminal administrativo já existente no ambiente autorizado. **WazuhSvc Running**, configuração local com exatamente **uma diretiva FIM realtime**, direcionada à pasta Startup de todos os usuários.
- Como a pasta Startup não é adequada para testes de executáveis, foi utilizado **exclusivamente arquivo de dados com extensão inerte, sem vínculo de execução**, criado, alterado e removido na própria janela. **Nenhum executável, atalho, script ou tarefa de inicialização foi criado.** A limpeza foi verificada no Windows após cada operação e documentada em evidência privada.
- Operações de arquivo: **CREATE PASS, MODIFY PASS, DELETE PASS**; arquivo final ausente. Script Windows possui bloqueios para diretório inesperado, reparse point, serviço Wazuh inativo, alvo preexistente e extensão não permitida.
- A consulta no **Wazuh Discover, `wazuh-alerts-*`**, com filtro para `agent.id=004` e marcador único do mesmo artefato confirmou **3 hits do mesmo caminho**. Filtros adicionais `syscheck.event` confirmaram **`added=1`, `modified=1`, `deleted=1`**, em sequência de horários compatível com a execução. Capturas privadas guardadas em `.lab/`.
- A evidência comprova **telemetria FIM real do Windows 004 até o Indexer e Discover**, após a mudança A; não comprova leitura independente do log local `alerts.json` no Manager.
- Pós-teste, agentes `002`, `004`, `005` continuaram **Active**, hash da configuração ativa igual ao hash aprovado da mudança A e parser Wazuh oficial **PASS**. Nenhuma política/configuração/serviço foi modificado ou reiniciado.

## Linux 005 — restrição de permissão legítima

- O diretório FIM realtime do Kali pertence a `root:root`, modo `0755`; a conta operacional `kali` **não tem permissão de escrita**. `sudo -n` requer senha.
- O script benigno de criação/modificação/exclusão foi **preparado, verificado sintaticamente e instalado no diretório do próprio usuário Kali**, sem privilégio root. A execução foi iniciada no terminal gráfico, mas permanece **condicionada a autenticação `sudo` local pelo proprietário**.
- **Enquanto o terminal aguarda senha, nenhuma alteração ao diretório FIM do `005` foi executada.** A senha não foi solicitada pelo chat nem conhecida pelo operador remoto. O script exige root legítimo, janela UTC válida e diretório correto, usa extensão inerte e `trap` de limpeza; ao expirar a janela, recusa ações ativas.
- Classificação atual: `005_FIM_TEST=AWAITING_LOCAL_OWNER_AUTHENTICATION`. Caso não exista autenticação antes do prazo, registrar `NOT_EXECUTED`; não utilizar contêiner ou outra via para contornar permissão.

## Matriz de aceite da mudança A — status desta janela

| Critério | Estado |
| --- | --- |
| Linux `002`: FIM real no Indexer e Discover | **PASS** — três eventos do teste anterior (added/modified/deleted) |
| Windows `004`: FIM real no Indexer e Discover | **PASS** — três eventos novos (added/modified/deleted) |
| Linux nativo `005`: evento benigno real e visibilidade | **PENDING** — autenticação root local legítima |
| Manager `alerts.json` diretamente observado com mesmos eventos | **PENDING** — acesso bruto remoto restringido; não contornado |
| Rollback da mudança A | **Preservado**; sem alteração de configuração |
| `DEPLOYMENT_GATE` | **BLOCKED** intencional; jamais forçar PASS por documentação |
| M1 | **11/17** (contagem baseada no checklist, sem aprovação parcial de milestone) |
| PR #25 | Aberto; revisão independente pendente, sem merge |

**Limites:** o campo `manager.name` nos documentos indexados identifica origem de processamento, mas não substitui auditoria direta do Manager. Os três alertas do Windows, embora suficientes para provar a indexação e a visualização do FIM no `004`, não alteram o contrato de revisão independente. A janela encerra pontualmente às **14h25min48s BRT**; novos testes ativos exigem outra autorização.

**Referências:** [Primeiro teste Linux 002](m1-change-a-benign-fim-test-20261105.md), [handoff pós-cutover](m1-change-a-cutover-postcheck-handoff-20261105.md), [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17), [PR #25](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/25). Nenhum identificador, screenshot, caminho privado completo ou evento bruto foi publicado.
