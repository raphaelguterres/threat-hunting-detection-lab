# M1/H03 — Change C aplicada no agente Windows 004 — 10/11/2026

**Modalidade:** laboratório privado autorizado pelo proprietário, com autoavaliação formal específica da Change C. **Sem revisão independente de M1.** Ativação da configuração FIM local ocorreu dentro de nova janela aprovada; os demais agentes e o `default/agent.conf` não foram alterados.

## Antes da alteração

- Pré-check do Windows `004`: volume NTFS saudável, `WazuhSvc=Running`; `C:\SecurityLab` e `C:\SecurityLab\H03` já haviam sido criados em preparação anterior. Ambas as pastas apresentaram DACL protegida, três ACEs e nenhuma regra ampla de escrita no verificador local.
- Pasta `H03` vazia, sem reparse point. Identidade de operador local e SIDs mínimos confirmados no script aprovado, sem publicar identidade privada.
- `ossec.conf` ativo idêntico ao baseline protegido, com recuperação DPAPI validada. Proposta privada existente, marcada `PREPARED_NOT_APPLIED`, mas janela anterior expirada. A nova janela foi delimitada para **10/11, 16h59–17h45 BRT** (19h59–20h45 UTC).
- Pré-check novo terminou com **exit 0**: `CHANGE_C_PREFLIGHT=PASS`, `DPAPI_RECOVERY_AND_HASH_MATCH=PASS`, `H03_DIRECTORY_SECURE_AND_EMPTY=PASS`, `PROPOSAL_ONE_REALTIME_DIRECTORY_ONLY=PASS`.
- A comparação de bytes antes da implantação exigiu somente uma diretiva `<directories realtime="yes" check_all="yes">C:\SecurityLab\H03</directories>`, preservando o restante do XML.

## Implantação e verificação local

- Executado script privado com `-Apply` no Windows Server autorizado. Resultado **exit 0**, `CUTOVER=LOCAL_APPLIED`, `SERVICE_RESTARTED=YES`, `LOCAL_TARGET_DIRECTIVE=REALTIME`. Nenhum rollback necessário.
- Um segundo verificador somente leitura, **após o restart**, confirmou `ACTIVE_SYSCHECK_TARGET_DIRECTIVES=1`, `ACTIVE_EQUALS_BASELINE=False`, `ACTIVE_EQUALS_PROPOSAL=True`, `WAZUH_SERVICE=Running`, DACLs protegidas e diretório H03 vazio.
- O manifesto de preparação anterior continua com janela expirada e estado histórico `PREPARED_NOT_APPLIED`. Não foi adulterado para simular aprovação; a autorização e a ativação novas estão registradas separadamente.
- Baseline criptografada, proposta e backup nativo anterior à troca foram preservados no ambiente privado. Não foi feita alteração de configuração centralizada, auditoria 4698, política, regras ou outros agentes.

## Smoke test benigno local (C4 parcial)

- Executado teste de **arquivo texto inerte** no diretório H03: criação **20:11:02 UTC**, modificação **20:11:07 UTC** e exclusão **20:11:12 UTC**.
- Resultado do executor: `H03_SMOKE_PREFLIGHT=PASS`, `SMOKE_WINDOWS_LOCAL_FILE_CYCLE=PASS`, `H03_DIRECTORY_EMPTY_AFTER=TRUE`, **exit 0**. Nenhum binário foi enviado/executado, nenhuma conta ou tarefa criada.
- Esses timestamps registram a ação local. A consulta posterior ao Manager encontrou um ciclo compatível, descrito abaixo, com divergência temporal ainda não explicada. Indexer/Discover permanecem **PENDENTES**.
- **Não houve teste v1→v2 e Sysmon EID1 para o mesmo executável.** H03 continua `INCONCLUSIVE` como correlação real.

## Estado e próximos controles

`CHANGE_C_LOCAL_CONFIG=APPLIED` · `BACKUP_PRESERVED=TRUE` · `WAZUH_SERVICE_RUNNING=TRUE` · `H03_LOCAL_SMOKE=PASS` · `H03_INDEXER_EVIDENCE=NOT_VERIFIED` · `H03_BINARY_EXECUTION=NOT_PERFORMED`.

**M1 ainda 15/17 (88,2%); `DEPLOYMENT_GATE=BLOCKED`.** Para 16/17 falta comprovar as três correlações H01/H02/H03 em eventos reais e controles negativos, sem confundir provas locais/sintéticas com ingestão. O encerramento 17/17 continua exigindo revisão independente, não substituída por esta exceção de Change C.

**Evidências privadas:** capturas do precheck, do cutover, do pós-check e do smoke test permanecem em `.lab/`, ignoradas pelo Git.

## Auxiliares da sessão e comparação posterior

Os launchers `VERIFICAR_BACKUP.cmd`, `VERIFICAR_H03.cmd`,
`PREPARAR_H03.cmd`, `APLICAR_H03.cmd` e `COMPARAR_H03.cmd` foram preparados
para execução manual pelo proprietário na VM Windows via pasta compartilhada.
Eles conferem uma cópia local do script antes de executá-lo com a política
PowerShell existente; não usam `ExecutionPolicy Bypass`.

O launcher de backup depende do verificador privado preexistente em `.lab/`,
que não é distribuído pelo Git. Os launchers de preparação/aplicação possuem
janelas fixas históricas e devem parar fora delas. Não são instaladores
genéricos e não autorizam nova mudança em outra máquina ou data.

A tentativa posterior de `APLICAR_H03` parou em `live_config_hash`, sem
substituição do arquivo ativo. A execução manual de `COMPARAR_H03` esclareceu
a divergência: baseline de 9725 bytes, configuração atual de 9801 bytes,
`CURRENT_EQUALS_PREPARED_PROPOSAL=True`, exatamente três campos XML novos
(diretiva de diretório e atributos `check_all`/`realtime`), uma diretiva H03,
ambos atributos `yes`, ACL do arquivo igual à baseline e serviço Running.
O comparador não alterou arquivos ativos ou serviços. Esse resultado é
coerente com a implantação documentada acima; não deve ser contado como
segunda implantação nem como comprovação da cobertura efetivamente carregada.

## Consulta posterior ao Manager, somente leitura

A leitura do arquivo ativo `alerts.json`, filtrada por agente `004` e pela
pasta H03, encontrou três alertas para um mesmo caminho:

| Horário UTC no Manager | Evento | Regra |
| --- | --- | --- |
| 20:10:27.736 | added | 554 |
| 20:10:32.753 | modified | 550 |
| 20:10:37.785 | deleted | 553 |

O evento de alteração possui os campos SHA-256 anterior e posterior; nenhum
valor de hash, nome de arquivo ou conteúdo foi publicado. Os três eventos
estão no intervalo consultado de 20:10–20:14 UTC. Isso comprova recebimento
de eventos FIM dessa pasta no Manager durante esse intervalo.

Os horários antecedem em aproximadamente 35 segundos os horários registrados
para as ações locais acima. A sequência e os intervalos são compatíveis,
mas a origem dessa diferença ainda não foi verificada; não se afirma
identidade exata com o smoke test documentado. A leitura contou também uma
linha JSON inválida no arquivo ativo, sem investigar sua causa.

Esta consulta não atesta Indexer/Discover, configuração completa em runtime
ou correlação FIM/Sysmon do mesmo executável. **M1 permanece 15/17**.
