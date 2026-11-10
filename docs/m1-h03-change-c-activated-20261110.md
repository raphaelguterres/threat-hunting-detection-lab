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
- Esses timestamps comprovam a ação local, **não** comprovam alerta recebido no Wazuh. A inspeção do Manager/Indexer/Discover para esses eventos está **PENDENTE**, com verificação remota aguardando liberação do painel de revisão.
- **Não houve teste v1→v2 e Sysmon EID1 para o mesmo executável.** H03 continua `INCONCLUSIVE` como correlação real.

## Estado e próximos controles

`CHANGE_C_LOCAL_CONFIG=APPLIED` · `BACKUP_PRESERVED=TRUE` · `WAZUH_SERVICE_RUNNING=TRUE` · `H03_LOCAL_SMOKE=PASS` · `H03_INDEXER_EVIDENCE=NOT_VERIFIED` · `H03_BINARY_EXECUTION=NOT_PERFORMED`.

**M1 ainda 15/17 (88,2%); `DEPLOYMENT_GATE=BLOCKED`.** Para 16/17 falta comprovar as três correlações H01/H02/H03 em eventos reais e controles negativos, sem confundir provas locais/sintéticas com ingestão. O encerramento 17/17 continua exigindo revisão independente, não substituída por esta exceção de Change C.

**Evidências privadas:** capturas do precheck, do cutover, do pós-check e do smoke test permanecem em `.lab/`, ignoradas pelo Git.
