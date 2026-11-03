# M1 — roteiro de confirmação autenticada Discover / FIM H03

**Data:** 03/11/2026. **Escopo:** operador autorizado, somente leitura. **Estado:** pendente de execução no Dashboard autenticado; não declarar êxito apenas por conectividade HTTPS.

## Pré-condições já verificadas

- VMs Kali e WindowsServer em execução no VirtualBox.
- Portas 443, 9200, 55000, 1514 e 1515 acessíveis na rede host-only; `GET /app/discover` sem sessão redireciona para login.
- A consulta remota ao Docker via canal disponível encontrou restrição de segurança; **não tentar contornar** nem tratar esta falha como indisponibilidade do Wazuh.
- Suíte completa offline: **199 testes e 160 subtestes PASS** nesta retomada.
- O gate continua `EVIDENCE_COMPLETENESS=INCOMPLETE` e `DEPLOYMENT_GATE=BLOCKED`.

## Operação manual permitida — somente leitura

1. Na VM Kali, abrir o Dashboard Wazuh pelo navegador e autenticar-se normalmente com a conta autorizada; não copiar senha, token nem cookies para chat, Git ou scripts.
2. Conferir se a interface principal e **Discover** carregam corretamente. Registrar em `.lab/` o horário local e UTC, a tela de sucesso/erro e a versão, sem divulgar ativos privados.
3. No Discover, conferir índice `wazuh-alerts-*` e o filtro temporal em UTC; testar uma janela atual e depois a janela histórica **31/10 00:00Z até 03/11 00:00Z** sem misturar interpretações.
4. No Console autenticado, se liberado pela política local, usar exclusivamente consultas `_count` em `wazuh-alerts-*`, para `syscheck.path:*`, depois `syscheck.path:* AND agent.id:004`, e por último com filtro temporal. Não exportar documentos, SID, hostname, path, hash ou payload de eventos.
5. O histórico anterior registrou 112 alertas com `syscheck.path`, dos quais 102 do `004` e zero na janela histórica citada. **São referências antigas, não resultados desta rodada.**
6. Se não carregar, registrar mensagem exata do erro e interromper consultas dependentes; solicitar diagnóstico autorizado de logs/saúde de Manager, Indexer e Dashboard. Não reiniciar contêineres nem alterar TLS automaticamente.

## Gate de H03

Um novo resultado de contagem FIM do `004` **não** confirma H03. Para validar candidato real, o operador deve confirmar em evidência privada um alerta FIM e Sysmon ID 1 para o **mesmo arquivo, mesmo ativo e ordem temporal de até 20 minutos**, com possíveis explicações benignas e verificação humana. Não simular execução sem autorização.

**Resultado desta rodada:** apenas conectividade / suíte offline verificadas. **Discover autenticado: NOT_CHECKED**; **H03: INCONCLUSIVE**; **DEPLOYMENT_GATE: BLOCKED**.
