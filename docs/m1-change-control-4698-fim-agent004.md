# M1 — Change control: auditoria Windows 4698 e cobertura FIM do agente 004

**Estado em 02/11/2026:** **pré-verificações e scripts de mudança/rollback preparados**, sem execução de mudanças de política. **Aprovação do operador pendente.** A revisão da configuração FIM é somente leitura.

**Escopo:** VM WindowsServer do laboratório autorizado, agente Wazuh identificado como `004` durante os testes anteriores. **Não se aplica automaticamente a ambientes de produção.** [Controle da mudança — Issue #15](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15).

**Atualização de preparação (03/11):** [checkpoint FIM 004, archives e condições independentes de aprovação](m1-fim-004-archives-and-approvals-checkpoint-20261103.md). O Manager armazena alertas a partir do nível 3, e o Indexer não listou `wazuh-archives-*`; isso não prova a recepção de 4698 nem de eventos FIM sem alerta. A aprovação, janela e validação de ingestão desta mudança continuam **PENDENTES**; nenhuma política de auditoria foi alterada.

## 1. Baseline observado remotamente (somente leitura)

| Área | Estado confirmado | Implicação |
| --- | --- | --- |
| Domínio | Servidor não associado a domínio | Reduz probabilidade de uma GPO de domínio sobrescrever política, mas não exclui políticas locais |
| `Audit Other Object Access Events` | **No Auditing** | Security `4698` (tarefa criada) não está sendo coletado por essa subcategoria |
| Canal Security | **Enabled**; limite **20 MB** | Risco de rotação prematura dos eventos se o volume aumentar; avaliar retenção **antes** de habilitar |
| `WazuhSvc` | **Running** | Serviço ativo, mas não comprova que cada evento Security está sendo encaminhado ao Manager |
| FIM `<syscheck>` local | `disabled=no` | Monitoramento FIM habilitado na configuração local |
| Varredura FIM | `frequency=43200` segundos (**12 horas**) | Alterações fora do realtime podem aparecer somente na próxima varredura |
| Diretórios FIM | **6 locais e existentes**: 5 WindowsSystem / 1 OtherLocal | Escopo majoritariamente de áreas do sistema; exige verificação de inclusão do arquivo-alvo da hipótese H03 |
| Modos | **5 programados**, **1 realtime**, **0 whodata** | Apenas um diretório configurado para alterações em tempo real; sem atribuição de quem alterou por whodata |
| Registro Windows | **23 configurações** de `windows_registry` | Não equivalem a 23 chaves individuais; podem abranger escopos |
| Caminhos de rede | **0 UNC** | Compatível com a limitação de suporte UNC do Wazuh moderno |
| Diagnóstico do `ossec.log` | 2.088 linhas do final do log; **5 menções** de FIM/varredura e **0 menções de erro FIM** no filtro aplicado | Evidência apenas da amostra do log, **não** certificação de saúde completa |

**Proveniência:** os dados acima foram extraídos por comandos read-only executados **dentro da VM autorizada**, armazenando apenas contagens e estados em arquivos privados no host: `.lab/m1-change-prep/M1_PRECHECK_PRIVATE.txt`, `.lab/m1-change-prep/M1_FIM_LOCAL_PRIVATE.txt` e `.lab/m1-change-prep/M1_FIM_COVERAGE_PRIVATE.txt`. Arquivos XML, registros e caminhos concretos não foram publicados.

**Evidência complementar:** o [levantamento anterior de visibilidade](m1-native-windows-wazuh-visibility-review-20261102.md) encontrou **102 documentos FIM históricos** do agente 004 no Indexer e **0 documentos FIM na janela 31/10 00:00–03/11 00:00 UTC**, com consulta de controle positiva para regra 110100 nesse mesmo período. Nenhum alerta recente não prova, por si só, falha do FIM: varreduras sem alteração observável podem não gerar alertas.

## 2. Decisão de mudança: habilitar auditoria 4698

**Objetivo defensivo:** coletar Security Event ID **4698**, que registra que uma tarefa agendada foi efetivamente criada, para enriquecer **H01**. A detecção Wazuh `110120` sinaliza a execução de `schtasks.exe /create`, **não** sucesso da criação; o motor M1 mantém esses conceitos separados.

A Microsoft recomenda auditar **Success** na subcategoria **Other Object Access Events** para operações de tarefas agendadas. Isso também produz eventos de criação/remoção/atualização conforme as ações realizadas, de modo que o impacto no canal Security deve ser monitorado. [Referência de auditoria](https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-other-object-access-events), [comando auditpol](https://learn.microsoft.com/pt-br/windows-server/administration/windows-commands/auditpol-set).

### Gate obrigatório antes da aplicação

1. Solicitar **aprovação explícita** para a alteração e definir janela curta com operador disponível, inclusive acesso de rollback.
2. Capturar novo baseline de `auditpol /get /subcategory:"Other Object Access Events"` **imediatamente antes** da mudança; comparar com **No Auditing** observado. Caso tenha divergido, **não aplicar** automaticamente.
3. Verificar privilégios administrativos, políticas locais e eventos `4698` históricos; decidir como garantir retenção com o log Security limitado atualmente a **20 MB**. **Não aumentar o log automaticamente** no mesmo change request sem aprovação.
4. Confirmar que o canal Security é ingerido pelo agente Wazuh (logcollector/canais configurados local ou centralmente). Habilitar auditoria Windows **não implica** indexação automática.
5. Manter somente `Success`; não habilitar `Failure` por padrão e não modificar outros subitens `auditpol`.
6. Usar os arquivos locais privados **somente após a aprovação**. Os scripts estão desenhados para **dry-run por padrão** e requerem argumento reservado mais uma frase de confirmação.

**Comando previsto, não executado nesta revisão:**

```bat
auditpol /set /subcategory:"Other Object Access Events" /success:enable
```

### Aceite técnico após a mudança — ainda pendente

- Conferir `auditpol /get` indicando `Success`; registrar a hora UTC da ativação e o baseline anterior.
- Executar **apenas um teste benigno aprovado** de criação de tarefa descartável, com limpeza validada, em janela de laboratório; **não executar sem aprovação explícita**.
- Confirmar Security `4698` na VM, timestamp e referência ao teste; verificar a chegada do evento ao Wazuh Manager, Indexer e Discover **somente se a regra de coleta e pipeline correspondente suportarem esse evento**.
- Registrar contagem de eventos da subcategoria, crescimento do log Security, possíveis perdas e critérios de parada; **não** publicar dados brutos, nomes de contas, SIDs nem conteúdo de tarefas.
- Tratar falha de `4698` ou ausência de ingestão como **gate não satisfeito**, não produzir evidência alternativa artificial.

### Rollback preparado — não executado

O baseline da subcategoria era **No Auditing**, portanto, **se a mudança ocorrer e o baseline continuar aplicável**, o rollback mais restrito é desabilitar apenas `Success` da **mesma subcategoria**:

```bat
auditpol /set /subcategory:"Other Object Access Events" /success:disable
auditpol /get /subcategory:"Other Object Access Events"
```

Não usar `auditpol /clear`, `auditpol /restore` geral ou alterações de GPO como rollback improvisado. Se a política mudar por outra fonte durante a janela, interromper e reavaliar antes de aplicar o rollback. Os scripts privados exigem confirmação explícita e a presença do baseline `No Auditing`.

**Gatilhos de rollback:** crescimento inesperado do Security, comportamento não previsto da auditoria, falha em confirmar `4698`, conflito com política vigente ou perda de visibilidade devido à retenção.

## 3. Revisão FIM 004: decisão de cobertura antes de H03

A leitura do arquivo local `C:\Program Files (x86)\ossec-agent\ossec.conf` é **preliminar**, não uma prova da configuração **efetiva**, pois configurações centralizadas em `agent.conf` podem ter precedência. [Documentação Wazuh](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/how-to-configure-fim.html).

Ações read-only para completar a revisão:

- Comparar configuração local e distribuição centralizada efetiva do agente **004** no Manager (acesso autorizado, sem leitura/publicação de segredos).
- Validar **dentro da VM** se o artefato-alvo de H03 é coberto por um dos diretórios monitorados e se o caminho é real, acessível e local; não inferir cobertura a partir de seis entradas genéricas.
- Conferir se o diretório relevante está em `realtime=yes` ou somente em varredura de 12h. **Não mudar frequência, realtime ou whodata** sem nova avaliação de carga/impacto.
- Em futuros testes aprovados, registrar baseline, varredura/mudança e, se houver alteração, ID e UTC no FIM do Manager e Indexer antes de relacionar com Sysmon Event ID 1 do **mesmo artefato**.
- Manter sem mudança o agente Wazuh se a cobertura for suficiente; casos sem correspondência permanecem **inconclusivos**.

### Checkpoint e responsabilidade

**Pronto:** inventário read-only, verificação de paths existentes, riscos levantados, script de ativação com proteção e script de rollback preparados **somente no host**. **Pendente:** aprovação humana, aplicação da auditoria, teste de criação real de tarefa, confirmação de ingestão Wazuh, inspeção de `agent.conf` efetivo e eventual validação de H03.

**Status:** a [Issue #15](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15) permanece aberta até essas decisões; M1 [Issue #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9) não está concluído.


## 4. Segundo pré-check: retenção e recebimento de configuração centralizada (02/11/2026)

**Verificações executadas no WindowsServer, exclusivamente read-only, após o inventário inicial:**

| Verificação | Resultado | Limite da interpretação |
| --- | --- | --- |
| Modo do log `Security` | **Circular** | Há sobrescrita quando chega ao limite; não assumir retenção futura constante |
| Capacidade / quantidade de registros | **20 MB / 11.378 registros** | Fotografia de um instante, sem medição de crescimento após ativar auditoria |
| Evento Security mais antigo / mais recente disponíveis | **2026-10-22 00:27:59Z / 2026-11-02 20:54:00Z** | Cobertura observada do arquivo atual; **não** constitui garantia de onze dias de retenção |
| `localfile` no `ossec.conf` | **9 entradas**, incluindo **2 Security** em `eventchannel` e **1 Sysmon** em `eventchannel` | Confirmar sobreposição de Security e compatibilidade dos filtros antes de considerar ingestão 4698 comprovada |
| Security com cláusula `query` local | **1 de 2** entradas | O scanner não detectou menção explícita a `4698`, mas não provou equivalência semântica do filtro |
| Configuração distribuída ao agente | `shared/agent.conf` e `shared/merged.mg` **presentes** | Presença não atesta que cada parâmetro central foi aplicado como esperado |
| `agent.conf` central | **1 `agent_config`**, com **1 `syscheck`**, **1 diretiva de diretório realtime**, **1 `localfile` syslog** | A fonte syslog central não equivale a um novo coletor Security; não foram publicados paths brutos |

### Achado relevante: diretiva central FIM com formato Unix no agente Windows

A diretiva **`<directories realtime="yes">`** no `shared/agent.conf` usa **caminho de estilo Unix/Linux**. Após expansão de variáveis de ambiente no WindowsServer, esse caminho **não existe** e **não coincide** com nenhum dos seis caminhos locais que foram comprovados existentes. A comparação de paths foi feita no próprio endpoint **sem exportar os nomes ou conteúdo integral do arquivo**. Não havia `whodata` nem diretivas centralizadas de registry.

**O que estava comprovado neste primeiro pré-check:** existe uma diretiva central FIM com caminho de estilo Unix inexistente na VM Windows. A fonte do grupo Manager ainda não havia sido verificada **nesta etapa inicial**. A validação adicional e sua proveniência estão registradas na seção 5. Não está comprovado que os seis diretórios locais deixaram de funcionar, nem que a diretiva explique ausência recente de alertas.

**Follow-up específico:** [Issue #17 — revisar configuração FIM central com diretiva Unix](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17). A correção central deverá ter change request **separado** e escopo por sistema/grupo; **não** editar o arquivo recebido no endpoint, não sobrescrever `agent.conf` manualmente e não reiniciar serviços sem necessidade.

### Gate de autorização permanece inalterado

A observação de dois coletores Security locais e de um caminho FIM Unix **não autoriza** a ativação da auditoria. Antes da mudança 4698, conferir a possibilidade de sobreposição dos dois coletores Security e medir retenção dos 20 MB, registrar uma janela com rollback autorizado e confirmar a ingestão real do Security 4698 após teste benigno aprovado. A seção 5 já registra a análise estrutural dos filtros, mas não prova entrega end-to-end. A ação `auditpol /set` **não foi executada**.

**Evidência privada agregada no Windows:** `.lab/m1-change-prep/M1_4698_PIPELINE_PRIVATE.txt`, `M1_CENTRAL_CONFIG_PRIVATE.txt`, `M1_CENTRAL_EFFECTIVE_PRIVATE.txt` e `M1_CENTRAL_PATH_CLASS_V2.txt`. O primeiro teste do classificador de caminho falhou por erro de sintaxe do coletor e **não foi usado como evidência**; o classificador V2 executou e validou o formato Unix com sucesso. Os hashes de configuração, nomes de caminhos, dados de agente e registros brutos não são publicados.

**Fontes oficiais:** [Microsoft: Audit Other Object Access Events](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events) · [Wazuh: `localfile` eventchannel](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html) · [Wazuh: centralized configuration](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html).

## 5. Identificação do grupo de origem e revisão dos filtros Security — 02/11/2026

Este complemento foi realizado **somente leitura**, usando SSH autorizado com chave existente do Windows host para a VM Kali e os comandos informativos do container Wazuh Manager, além de uma análise **local** sem divulgar o texto de filtros do WindowsServer.

| Checagem | Resultado observado | Critério de interpretação |
| --- | --- | --- |
| `agent_groups -l` | **1 grupo no Manager: `default`**, contendo **4 agentes** | A distribuição centralizada atual não está segmentada por SO |
| `agent_groups -s -i 004` | **Agente 004 pertence somente ao `default`** | Origem do grupo atribuída diretamente |
| `agent_groups -S -i 004` | **`Agent '004' is synchronized`** | Sincronização do grupo confirmada, mas não prova a eficácia de toda diretiva FIM |
| `sha256sum /var/ossec/etc/shared/default/agent.conf` | **Hash idêntico ao `shared/agent.conf` recebido no WindowsServer**; **221 bytes em ambas as pontas** | Confirma distribuição **desse mesmo arquivo** por parte do Manager, sem publicar seu conteúdo |
| Security local | **2 entradas `eventchannel`**, **1 sem cláusula `query`** | Uma entrada é ampla; avaliar risco de coleta sobreposta |
| Security filtrado | **1 cláusula `query` baseada somente em negações de EventID** | Um filtro de exclusões, não um whitelist de eventos conhecidos |
| Restrição a `4698` | **Nenhuma menção nem negação explícita ao EventID 4698 encontrada nos dois blocos Security locais** | Condição de configuração **favorável, mas insuficiente para comprovar ingestão real** |

**Conclusão confirmada:** o `agent.conf` com diretiva FIM de formato Unix não se originou de um grupo Windows especializado; foi recebido do único grupo `default`, e o hash corresponde exatamente ao arquivo desse grupo no Manager. A diretiva não encontra o caminho esperado neste endpoint Windows. Não está provado que os seis caminhos locais do `ossec.conf` tenham parado de ser monitorados; a revisão do FIM efetivo e os efeitos de sobreposição ainda precisam de validação apropriada.

### Estratégia de correção proposta (não executada)

1. Criar **planejamento de segregação por sistema operacional** e aprovar escopo separado da mudança 4698. Analisar quais dos quatro agentes do `default` usam Linux/Windows **sem publicar identificadores**.
2. Preparar grupo de configuração específico para Windows, com entradas FIM suportadas pelo sistema e revisão dos coletores Security. Avaliar o impacto de **múltiplos grupos**: segundo o Wazuh, o último grupo atribuído tem maior prioridade e as configurações são mescladas; uma diretiva Linux residual no `default` pode continuar sendo distribuída.
3. Para mudança futura, preparar backup do arquivo `default/agent.conf`, `merged.mg` e vínculos de grupos, revisão de configuração, testes de sintaxe e rollback por grupo; **não** modificar automaticamente um grupo compartilhado por quatro agentes.
4. Executar apenas após autorização explícita, com critérios de confirmação da distribuição, funcionamento do agente e teste FIM benigno específico. Não modificar credenciais, TLS ou serviços desnecessariamente.
5. Controlar essa correção na [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17), independente da ativação da auditoria `4698` na [Issue #15](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15).

**Referências:** [Wazuh — Grouping agents](https://documentation.wazuh.com/current/user-manual/agent/agent-management/grouping-agents.html) · [Wazuh — agent_groups](https://documentation.wazuh.com/current/user-manual/reference/tools/agent-groups.html) · [Microsoft — Audit Other Object Access Events](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events).
