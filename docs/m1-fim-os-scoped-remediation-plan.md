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

## Verificação oficial da baseline ATUAL — 02/11/2026

Antes de modificar qualquer arquivo, foi executado pelo Windows Remote e SSH autorizado, **somente leitura**, o verificador oficial Wazuh 4.x sobre a **configuração original ativa** no Manager:

    docker exec single-node-wazuh.manager-1 /var/ossec/bin/verify-agent-conf -f /var/ossec/etc/shared/default/agent.conf

**Resultado observado:** `verify-agent-conf: OK` com **exit code 0**.

**Escopo exato desse resultado:** confirma sintaxe aceita para o `agent.conf` **que já está em uso** no grupo `default`. **Não prova** que a diretiva Unix de FIM funcione no Windows Server 004, que os caminhos locais tenham deixado de funcionar, que a proposta com seletor de OS esteja correta ou que o sistema esteja isento de erros de detecção.

**Naquele checkpoint inicial**, a proposta OS-scoped ainda não havia sido submetida ao verificador oficial. Posteriormente, **com autorização específica para uma cópia temporária isolada**, a proposta foi validada no Manager sem implantação (resultado documentado na seção de atualização abaixo). A baseline original não foi alterada.

[Verificador oficial Wazuh](https://documentation.wazuh.com/current/user-manual/reference/tools/verify-agent-conf.html) · [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17)

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

## Atualização: proposta validada oficialmente em cópia temporária isolada — 02/11/2026

**Autorização recebida:** o operador autorizou expressamente preparar uma cópia temporária da configuração no Manager, executar o `verify-agent-conf` sobre essa cópia e apagá-la ao terminar. **Não houve autorização de implantação, reinício de serviços, alteração de grupos ou ativação de auditoria 4698.**

Procedimento executado no Manager via Windows Remote/SSH autorizado:

1. Confirmar que o SHA-256 do `/var/ossec/etc/shared/default/agent.conf` ativo corresponde à baseline privada já coletada do Windows; rejeitar diferenças antes de qualquer escrita.
2. Confirmar um único bloco `agent_config` originalmente sem atributo `os`, com caminhos Unix de FIM/log, sem entradas de caminho Windows; verificar tamanho de baseline de 221 bytes.
3. Produzir em memória cópia que **somente** muda a abertura `<agent_config>` para `<agent_config os="^Linux">`; confirmar substituição inversa idêntica ao original e XML parseável, sem alterar caminhos, fontes de log nem atributos internos.
4. Gravar a cópia em **`/tmp` dentro do container**, com permissões restritas. `/tmp` está fora de `/var/ossec/etc/shared`, o diretório de distribuição de configurações aos agentes.
5. Executar **`/var/ossec/bin/verify-agent-conf -f <arquivo_temporario_isolado>`** e conferir retorno do verificador oficial.
6. Excluir a cópia em bloco de limpeza garantida (`finally`) mesmo se a verificação falhar; comparar novamente o SHA-256 do **arquivo ativo original** com a baseline.

| Critério de aceite desse gate | Resultado observado |
| --- | --- |
| SHA-256 do original corresponde à baseline privada | **PASS** |
| Proposta altera apenas o seletor do bloco Linux | **PASS** |
| Verificador **oficial** da cópia temporária | **PASS** |
| Original ativo preservado | **True** |
| Cópia temporária removida | **True** |
| Implantação em agentes | **False** |
| Código de saída do teste controlado | **0** |

**Conclusão permitida:** a proposta mínima de adicionar `os="^Linux"` é **sintaticamente aceita pelo Wazuh**, quando validada em uma cópia temporária isolada da configuração original. **Não** prova que a proposta foi distribuída, que o agente Windows 004 deixou de receber a diretiva Linux, que a telemetria FIM funciona ou que os outros membros do grupo serão preservados após uma alteração real.

**Próximo gate não concluído:** inventário autorizado dos demais agentes no `default`, análise do impacto por sistema operacional, backup/restauração da configuração ativa, aprovação explícita para **aplicar** a mudança, publicação em janela controlada e validação efetiva de Windows/Linux. A [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17) permanece aberta.

**Fonte oficial sobre o uso de `-f` em arquivo temporário:** [Wazuh centralized configuration](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html). Evidência operacional detalhada permanece apenas no diretório privado `.lab/`; sem publicação de caminhos reais, arquivo integral, credenciais ou hash.

## Reforço de revisão FIM — 03/11/2026 (somente offline)

O comparador [review_fim_scope_only.py](../scripts/review_fim_scope_only.py) passou a rejeitar **blocos mistos Unix/Windows**, inclusive quando as referências Windows aparecem fora de `syscheck/directories` ou `localfile/location`. A análise conservadora percorre todos os elementos e atributos XML do bloco proposto para reconhecer caminhos de unidade (exemplo sintético `C:\\Windows`), UNC, variáveis como `%PROGRAMDATA%\\`, elementos de registro Windows e formatos de log `eventlog`/`eventchannel`. A normalização XML também impede ocultar um prefixo de drive por entidade numérica.

O resultado de uma identificação suspeita é **rejeitar o escopo automático Linux** e exigir revisão humana de toda a configuração. Uma exclusão Unix legítima em um bloco Unix continua permitida, desde que nenhuma outra alteração XML além de `os="^Linux"` tenha ocorrido. São controles conservadores para reduzir classificação incorreta; **não comprovam detecção de toda configuração específica de Windows nem substituem o parser oficial do Wazuh**.

Testes sintéticos incluem diretório Unix com exclusão Windows, atributo Windows, referência UNC, registro Windows, formato `eventchannel`, caminho XML codificado e um caso exclusivamente Unix permitido. Nenhum arquivo ativo do Manager foi lido, gravado ou implantado nessa revisão.

## Alinhamento dos dois validadores estruturais — 03/11/2026

O [validador OS-scope](../scripts/validate_fim_os_scope.py) também examina referências cruzadas fora dos campos de diretório e fonte de log. Ele rejeita no escopo Linux referências Windows de unidade, UNC, variável de ambiente, registro e formatos `eventchannel/eventlog`; no escopo Windows, rejeita exclusão FIM com caminho Unix absoluto. Controles negativos sintéticos exercitam essas possibilidades e um exemplo Unix válido.

Os dois verificadores têm funções diferentes: `validate_fim_os_scope.py` confere padrões estruturais de um fragmento já marcado por SO, enquanto `review_fim_scope_only.py` compara original/proposta e permite **somente** a inclusão mínima do seletor Linux. A aprovação de ambos **não** equivale a `verify-agent-conf` oficial, não valida a precedência efetiva dos grupos e **não** permite implantação sem inventário e autorização.
