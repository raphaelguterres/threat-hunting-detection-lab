# M1 — Plano de segregação de FIM por sistema operacional

**Estado em 02/11/2026:** proposta offline; não foi implantada nem validada no Manager. **Aprovação específica pendente.**

## Evidência que fundamenta a proposta

O agente Windows 004 recebeu do grupo compartilhado **default** uma diretiva FIM em tempo real com caminho no formato Unix/Linux, inexistente nesse host. O Manager possui somente esse grupo, com quatro agentes. O hash e tamanho do arquivo **agent.conf** no Manager e no Windows são idênticos, e a sincronização do 004 foi confirmada. Os seis caminhos FIM locais no Windows continuam existentes. **O achado não demonstra falha dos seis caminhos locais.**

Este plano acompanha a [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17) e o [runbook de change control](m1-change-control-4698-fim-agent004.md).

## Alternativas, ainda não executadas

**Alternativa A — preferencial para avaliação inicial:** manter os agentes no grupo default e **restringir as diretivas Linux existentes** usando o atributo do Wazuh agent_config com expressão regular de sistema operacional **os="^Linux"**. O atributo é suportado pela [documentação oficial](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html). Evita rematrícula de agentes e exige uma mudança menor, mas afeta arquivo compartilhado por quatro agentes; exige inventário e aprovação antes de aplicar.

**Alternativa B — grupos Windows/Linux:** criar grupos separados, com configuração própria. Aumenta a organização, mas traz custos de operação e precedência, porque os agentes podem pertencer a múltiplos grupos, e o grupo atribuído por último prevalece quando há configurações conflitantes. Requer aprovação e revisão de todos os agentes envolvidos. [Fonte oficial](https://documentation.wazuh.com/current/user-manual/agent/agent-management/grouping-agents.html).

**Não inventar um caminho FIM Windows no Manager.** O agente 004 já possui seis caminhos locais. Qualquer nova diretiva Windows deve refletir um artefato H03 realmente relevante e uma análise de custo, cobertura e precedência.

## Fixture sintética e guarda offline

O exemplo [m1-agent-conf-os-scope-synthetic.xml](../tests/fixtures/m1-agent-conf-os-scope-synthetic.xml) é **inteiramente inventado e não implantável**, com caminhos literalmente nomeados **M1_EXAMPLE_NOT_DEPLOYABLE**. Não é cópia nem patch do arquivo real distribuído.

O [validador Python offline](../scripts/validate_fim_os_scope.py) aceita propostas em fragmentos XML do formato agent.conf e:
- exige escopo explícito de sistema operacional, restrito neste exemplo aos valores **^Linux** ou **^Windows**;
- rejeita diretórios Unix em blocos Windows, diretórios Windows em blocos Linux, fontes de log de outro sistema e UNC;
- rejeita XML inválido, DTD e declarações ENTITY;
- imprime somente contagens agregadas, sempre com **wazuh_parser_verified=false** e **deployed=false**.

Comandos de laboratório, executáveis sem conexão de rede nem credenciais:

    python scripts/validate_fim_os_scope.py --input tests/fixtures/m1-agent-conf-os-scope-synthetic.xml
    python -m unittest discover -s tests -p test_fim_os_scope.py -v

**Importante:** esse verificador estrutural não substitui o Wazuh verify-agent-conf, não demonstra seleção correta dos sistemas e não confere caminhos reais.

## Plano de mudança real — somente após autorização explícita

1. **Inventariar os agentes:** somente o OS do agente 004 foi confirmado. Os outros três integrantes do default **ainda não tiveram os sistemas operacionais comprovados por inventário completo**. A tentativa de obter esse inventário programaticamente foi bloqueada por proteção de segurança; **não contornar**. Uma revisão autorizada deve confirmar OS/versões/impacto dos quatro membros antes de mudar o grupo.
2. **Preparar backup privado:** registrar o conteúdo atual e hashes do arquivo default/agent.conf, permissões, grupos atribuídos, sincronização e dependências em caminhos Linux. Nunca publicar arquivos originais no GitHub.
3. **Criar proposta mínima:** preservar as diretivas reais de syscheck e localfile; adicionar escopo específico Linux somente aos blocos existentes que de fato são destinados a Linux. Preparar diff fora da árvore ativa do Manager e revisar sem expor nomes de ativos, credenciais ou caminhos privados.
4. **Validar com o Wazuh:** em janela aprovada, criar temporariamente agent.conf.tmp sob o diretório do grupo e executar o verificador oficial:

       /var/ossec/bin/verify-agent-conf -f /var/ossec/etc/shared/default/agent.conf.tmp

   Confirmar usuário, permissões e semântica com a [documentação oficial](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html). **Nenhum arquivo de configuração foi criado no Manager até agora.**
5. **Publicar após aprovação:** aplicar somente configuração revisada e validada, com critério de parada, snapshot de baseline, backup e método de rollback. O Manager distribui automaticamente as configurações e os agentes podem recarregá-las sem restart manual; validar efeitos antes de qualquer reinício desnecessário.
6. **Validar OS e telemetria:** confirmar sincronização no 004, verificar que o caminho Unix deixou de ser aplicado ao Windows e que os seis caminhos FIM locais seguem operantes. Verificar também os agentes Linux para não causar regressão no monitoramento. Um teste FIM benigno deve ser aprovado separadamente.
7. **Rollback:** restaurar apenas o backup do default/agent.conf no Manager se houver falha, com registro de aprovação/horário e nova verificação dos quatro agentes. Não apagar dados FIM, trocar grupos por adivinhação ou fazer alterações de TLS.
8. **Documentar o resultado:** evidência sanitizada, impacto e limites, sem dados brutos. Encerrar a Issue #17 somente após validação efetiva.

## Independência da auditoria 4698

A [Issue #15](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15) é um change request distinto. Security tem retenção Circular de 20 MB e duas fontes eventchannel locais, sendo uma filtrada por exclusões e outra sem filtro; o 4698 não aparece explicitamente bloqueado. Isso **não prova ingestão**; o auditpol continua sem habilitação de Other Object Access Events, aguardando autorização.

## Referências

- [Wazuh: Centralized configuration, OS selectors e verify-agent-conf](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html)
- [Wazuh: grupos e precedência](https://documentation.wazuh.com/current/user-manual/agent/agent-management/grouping-agents.html)
- [Wazuh: configuração FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/how-to-configure-fim.html)

## Segundo gate offline: revisar somente a inclusão de escopo por SO

O validador de caminhos anterior não detecta mudanças acidentais no resto da configuração. O novo [review_fim_scope_only.py](../scripts/review_fim_scope_only.py) compara uma configuração original e uma proposta, ambas em arquivos privados, sem acessar Wazuh.

A comparação:
- exige os mesmos blocos, elementos e valores XML, sem inclusão/remoção de fontes de log, diretórios ou atributos FIM;
- permite unicamente adicionar o atributo **os="^Linux"** a um bloco agent_config antes sem seletor, com somente caminhos Unix de FIM/log;
- preserva comentários e rejeita alterações de conteúdo, ignorando exclusivamente alterações de indentação;
- rejeita mudanças em blocos Windows e filtros preexistentes, declarações DTD/ENTITY e entradas fora da pasta privada .lab (com exceção de fixtures marcadas);
- nunca modifica os arquivos e nunca imprime conteúdo sensível. Sua saída indica **deployment_performed=false** e **wazuh_parser_verified=false**.

### Teste sintético no CI (sem rede nem VM)

    python scripts/review_fim_scope_only.py --original tests/fixtures/m1-original-unscoped-synthetic.xml --proposed tests/fixtures/m1-proposed-scoped-synthetic.xml --fixture
    python -m unittest discover -s tests -p test_review_fim_scope_only.py -v

### Uso em staging privado, somente após autorização para manusear os arquivos

Com cópias previamente coletadas e autorizadas do original e da proposta dentro da pasta .lab:

    python scripts/review_fim_scope_only.py --original .lab/m1-change/original-agent.conf --proposed .lab/m1-change/proposed-agent.conf

A aprovação desse comparador **não autoriza deploy**. Ainda são exigidos inventário dos agentes afetados, revisão humana do diff, backup/rollback e verificação pelo **verify-agent-conf oficial** sobre cópia temporária autorizada antes da mudança agendada.

**Limite:** verifica apenas estrutura XML, não a seleção efetiva de OS, prioridade entre grupos, funcionamento da FIM ou aceitação de regras pelo Wazuh. Não foram usadas configurações originais do Manager nos testes públicos.
