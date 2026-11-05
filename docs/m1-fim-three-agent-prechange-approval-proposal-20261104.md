# M1 — inventário 3/3, precedência FIM e pré-gate da mudança A

**Data do checkpoint:** 04/11/2026, aproximadamente 21h34–21h50 BRT.
**Change ID:** `M1-FIM-OS-SCOPE`.
**Natureza:** diagnóstico read-only, ensaio isolado e proposta de janela.
**Decisão operacional:** `NO-GO / DEPLOYMENT_GATE=BLOCKED`. **Nenhuma configuração do Manager, agente, serviço ou grupo foi modificada.**

## 1. Inventário técnico atualizado — evidência real, sem assinatura inventada

Foram realizadas consultas **somente leitura** autenticadas no Manager Wazuh 4.14.9: `agent_control -l/-i`, `agent_groups -l/-s/-S`. Os dados completos (SO/versão, grupos, timestamps com fuso e referência de captura) ficaram exclusivamente em `.lab/m1-inventory-manager-readonly-20261104.json` e no CSV correspondente.

| Agente | SO/família | Grupo, na ordem observada | Estado | Sync |
| --- | --- | --- | --- | --- |
| `002` | Linux | `default` (único) | Active | synchronized |
| `004` | Windows Server 2022 | `default` (único) | Active | synchronized |
| `005` | Linux | `default` (único) | Active | synchronized |

O grupo `default` contém **exatamente três agentes**. O `001` não consta no cadastro; o `003` permanece cadastrado, `Never connected` e **fora** do grupo. A decisão do próprio proprietário de mudar o contrato 4→3 foi registrada em [emenda de escopo](m1-inventory-scope-amendment-20261104.md), com a limitação explícita de não ser uma revisão independente estrita.

**Validação realizada:** importador CSV aceitou os dados reais; o manifesto privado passou a conter três agentes depois de backup da versão anterior. A ferramenta continua declarando `EVIDENCE_SOURCE=PRIVATE_UNATTESTED` e exige `inventory_review`. **A confirmação técnica aqui não é uma assinatura independente nem autorização de deploy.** O registro foi produzido por consulta controlada read-only; nenhuma observação sintética foi usada para simular agentes ativos.

## 2. Precedência e impacto por sistema operacional

A leitura do `default/agent.conf` ativo no Manager retornou:
- **1 bloco** `agent_config`, atualmente **sem seletor `os`**;
- **1 diretiva** `syscheck/directories` com caminho **Unix/Linux**, `realtime=yes`;
- **0 caminhos Windows** na configuração central;
- pelo menos **1 fonte `localfile`** dentro do mesmo bloco;
- arquivo validado com `verify-agent-conf: OK`.

| Fonte de configuração | Linux `002` | Windows `004` | Linux `005` |
| --- | --- | --- | --- |
| Grupo `default` único | Verificado | Verificado | Verificado |
| `agent.conf` sem filtro OS atual | Recebe o bloco Linux | Recebe o bloco Linux indevidamente | Recebe o bloco Linux |
| FIM local `ossec.conf` | **Não atestado nesta consulta** | Seis caminhos locais já inventariados; um deles Startup realtime | **Não atestado nesta consulta** |
| Caminho central Linux no Windows | Não se aplica | Exibido no Dashboard como caminho normalizado, mas **inexistente no disco** | Não se aplica |
| Proposta `os="^Linux"` — metadados `agent_control` | **Regex corresponde** | **Regex não corresponde** | **Regex corresponde** |
| Resultado da distribuição real após proposta | **Não testado** | **Não testado** | **Não testado** |

**Precedência oficialmente documentada:** `ossec.conf` é lido antes do `agent.conf`; configurações compartilhadas podem sobrescrever opções conflitantes, e listas de caminhos podem coexistir. Entre múltiplos grupos, o último atribuído tem maior prioridade, mas **não há multigrupo neste escopo 3/3**. Fontes: [Wazuh — Centralized configuration](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html) e [Grouping agents](https://documentation.wazuh.com/current/user-manual/agent/agent-management/grouping-agents.html).

**Cuidado de impacto:** adicionar `os="^Linux"` à abertura do **bloco inteiro** também restringe a fonte de logs Unix `localfile`, não apenas a diretiva FIM. Revisar essa consequência antes de aprovar. O regex foi testado contra a string real `Operating system` do `agent_control` nos três agentes, mas não contra o parser/seleção de runtime após implantação.

## 3. Baseline real, backup e ensaio de recuperação

**Arquivo central ativo:** `/var/ossec/etc/shared/default/agent.conf`. No momento da checagem:

| Controle | Resultado | Limitação |
| --- | --- | --- |
| SHA-256 atual × backup DPAPI pré-existente | **MATCH** | Hash privado, não publicado |
| Tamanho do arquivo atual × metadados | **MATCH** | 221 bytes |
| UID, GID, modo do arquivo × baseline | **MATCH** | UID/GID `999/999`, modo `0660`; conferir de novo antes do cutover |
| `verify-agent-conf` atual | **OK** | Sintaxe, não semântica ou telemetria |
| Recuperação de backup real para sandbox local | **PASS** | Não é restauração no Manager ativo |
| Mutação de conteúdo no sandbox detectada | **PASS** | Controle negativo |
| Reversão no sandbox ao SHA esperado | **PASS** | Restauração operacional ainda não ensaiada |
| Sandbox descartável removido | **PASS** | Sem alteração do Manager |
| Conta/perfil DPAPI disponível na janela futura | **A revalidar** | Backups `CurrentUser` dependem do mesmo perfil Windows |

**Evidência privada:** `.lab/m1-change-prep/M1_REAL_AGENT_CONF_DPAPI_PRIVATE.bin`, `M1_REAL_AGENT_CONF_DPAPI_METADATA_PRIVATE.json`, `M1_REAL_ISOLATED_ROLLBACK_TEST.ps1`. Arquivos criptografados, metadados com hash e logs brutos **não devem ser versionados**.

## 4. Pré-gates da mudança A

| Gate | Resultado desta passagem | Pode liberar implantação? |
| --- | --- | --- |
| Escopo 3/3 aprovado pelo proprietário | Registrado com limitação de segregação | Não, isoladamente |
| Inventário técnico atual 3/3 | **PASS técnico**, CSV importado e fontes privadas | **Pendente atestado humano conforme contrato** |
| Precedência de grupos | **PASS: somente `default`** | Não prova a config FIM local Linux |
| Regex `^Linux` em `agent_control` | **2 matches, 1 exclusão** | Runtime ainda não testado |
| Parser da baseline central | **PASS** | Revalidar em janela |
| Backup/hash, owner/group/mode | **PASS** | Revalidar em janela |
| Recuperação isolada e corrupção negativa | **PASS** | Plano operacional de rollback ainda requer aceite |
| Revisão PR/código e efeito de filtrar `localfile` | **Pendente** | NO-GO |
| Autorização específica para `M1-FIM-OS-SCOPE` | **Não recebida** | NO-GO |
| Janela nova | **Somente proposta** | NO-GO |
| FIM Linux/Windows após mudança → Manager → Indexer → Discover | **Não executado** | NO-GO |

**Gate automático observado após importação:** `EVIDENCE_COMPLETENESS=INCOMPLETE`; `MISSING_OR_UNVERIFIED=inventory_review,os_impact_review,group_precedence_review,baseline_integrity,parser_staging,backup_integrity_real,rollback_rehearsal_real,change_approval,approved_window`; `DEPLOYMENT_GATE=BLOCKED`.

O status `verified` do manifesto **não foi inventado**: os checks pendentes só podem ser promovidos após uma revisão rastreável e autorização de mudança, considerando as limitações da autoavaliação do proprietário.

## 5. Nova janela proposta — NÃO APROVADA

**Mudança A — somente seletor Linux na configuração central:**
- **Proposta:** quinta-feira, **05/11/2026, 18h00–19h00 BRT** (`America/Sao_Paulo`).
- **Executor/owner proposto:** operador responsável pelo laboratório; nomeação e aceitação explícita ainda pendentes.
- **Escopo exato:** modificar somente a abertura do bloco Linux de `<agent_config>` para `<agent_config os="^Linux">`, sem alterações em logs, regras, diretivas Windows, `4698`, grupos ou agentes.
- **Observação:** aplicar o seletor no bloco existente altera a elegibilidade de **todas** as diretivas do bloco, inclusive o `localfile` Unix. O revisor deve aceitar este impacto expressamente.
- **Pré-cutover:** validar janela, inventário recente, diff mínimo, parser da proposta em staging não distribuído, baseline/metadata, backup recuperável, monitoração e plano de parada.
- **Aplicação, somente após GO formal:** staging seguro + validação oficial e publicação atômica do XML conforme instruções Wazuh. A configuração central é distribuída automaticamente aos agentes; **não reiniciar Manager por rotina**.
- **Pós-cutover:** reconferir hashes, sync dos três agentes, configuração efetiva FIM por agente, Windows sem diretiva Linux, cobertura Linux real, Manager→Indexer→Dashboard e carga/ingestão.
- **Gatilho NO-GO / rollback:** divergência de baseline; erro do parser; perda de sync; Linux sem FIM; Windows ainda recebendo caminho Unix; mudança não correspondente ao diff; fontes de logs ausentes; ausência de dados ou acesso ao backup.
- **Rollback a aprovar:** em caso de falha, verificar hash da configuração atual e da cópia protegida; restaurar **somente** `default/agent.conf` a partir do backup original validado, preservando owner `999`, grupo `999` e modo `0660` e evitando sobrescrever alterações alheias. Confirmar parser, sync, telemetria e integridade; não apagar evidências nem reiniciar serviços automaticamente.
- **Janela de rollback e recursos:** revisor/operador devem reservar tempo suficiente para validação antes e depois; se não houver tempo para rollback dentro da janela, **NO-GO**.

**Mudança C (H03 Windows)** e **mudança B (`4698`)** são independentes, **não cobertas** por essa janela. A autorização condicional anterior para a mudança C venceu em 04/11 às 19h BRT e não deve ser reaproveitada.

## Decisão técnica desta passagem

`INVENTORY_MANAGER_3_OF_3=VERIFIED_READONLY`
`INVENTORY_HUMAN_REVIEW=NOT_ATTESTED`
`GROUP_PRECEDENCE_MULTIGROUP=NONE`
`MANAGER_OS_REGEX_METADATA_TEST=2_LINUX_1_WINDOWS`
`WAZUH_RUNTIME_OS_SCOPE_TEST=NOT_PERFORMED`
`ACTIVE_BASELINE_HASH_MODE_UID_GID=PASS`
`REAL_BACKUP_ISOLATED_RESTORE=PASS`
`CHANGE_A_WINDOW=PROPOSED_NOT_APPROVED`
`CHANGE_A_DEPLOYED=NO`
`DEPLOYMENT_GATE=BLOCKED`

**Próxima decisão:** proprietário deve revisar e aprovar explicitamente o escopo e a janela da mudança A, registrar o tratamento da ausência de segundo revisor conforme o contrato do projeto e confirmar que os controles de rollback e observabilidade podem ser executados. Não registrar assinatura ou evidência como se uma segunda pessoa tivesse revisado.

### Referências

- [Roadmap M1](roadmap-progress.md)
- [Pacote de aprovação FIM Linux](m1-fim-change-approval-package.md)
- [Matriz de aceite FIM por OS](m1-fim-acceptance-matrix.md)
- [Gate de evidência](m1-evidence-gate.md)
- [Checkpoint pós-Codex](m1-codex-continuation-20261104.md)
- [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17)
