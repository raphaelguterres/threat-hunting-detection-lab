# M1 — diagnóstico confirmado do Sysmon EID1 ausente em `wazuh-alerts-*` (05/11/2026)

**Verificação reproduzível adicionada:** `python scripts/m1_h01_rule_scope_audit.py --rule .lab/m1-h01-active-rule110100-20261105-private.xml`. A cópia do XML veio de leitura autorizada do arquivo de regras do Manager, permaneceu em `.lab/` e passou no validador **exit 0**: regra `110100` nível 12, dependências esperadas, condição de PowerShell codificado e **5 vetores sintéticos PASS** (incluindo `-File` negativo). [Onze testes de regressão](../tests/test_m1_h01_rule_scope_audit.py) passaram; nenhum processo novo, regra ou serviço foi alterado. O validador intencionalmente retorna `event_ingestion_verified=false` e `runtime_rule_loading_attested=false`: um snapshot não é inspeção do pipeline vivo.

**Ambiente:** Wazuh Manager 4.14.9 single-node Docker, Windows Server agente `004`.  
**Modo:** leitura autorizada de **arquivos de configuração e regras**, sem abrir `alerts.json` ou `archives.json`, sem consultar dados brutos restritos, sem reinicialização e sem mudança ativa.  
**Diagnóstico:** `EXPECTED_RULE_FILTERING_FOR_PREVIOUS_BENIGN_POWERSHELL_INVOCATION`.  
**Não confundir:** o evento estava presente **no Sysmon nativo** (RecordID `173036`), mas sua **chegada ao Manager em estado bruto não foi atestada independentemente**. Esta revisão explica por que **não esperamos um alerta** do processo com os filtros atuais; não prova, por si só, entrega de todo evento bruto pela rede.

## Regras realmente verificadas no Manager

| Componente | Resultado lido no sistema |
| --- | --- |
| Regra-base Sysmon EID 1 | `61603`, **level=0**, `if_sid=61600`, `win.system.eventID=^1$` |
| Limiar de armazenamento de alertas | `<log_alert_level>3</log_alert_level>` |
| Regra customizada de PowerShell | `110100`, **level=12**, dependência `if_sid=61603,92057` |
| Escopo da `110100` | `win.system.providerName=Microsoft-Windows-Sysmon`, Event ID 1, imagem terminada em `powershell.exe` ou `pwsh.exe` e linha de comando com `-enc` **ou** `-EncodedCommand` seguida de espaço |
| Arquivamento geral de eventos | `<logall_json>no</logall_json>` (`archives.json` não representa necessariamente todos os eventos do Manager nesta configuração) |
| Coletor do agente `004` | **Um** `Microsoft-Windows-Sysmon/Operational`, `log_format=eventchannel`, **zero** cláusulas `query` locais |
| Estado das fontes | Log Sysmon ativo e `WazuhSvc` em execução no guest, observados no pós-check |

**Condição decisiva:** o ensaio benigno anterior disparou um PowerShell por **`-File`**, sem `-enc`/`-EncodedCommand`. Logo, **não se enquadra na regra personalizada `110100`**. A regra-base `61603` tem nível zero, inferior ao limite mínimo três. A ausência de alerta para **esse** evento é, portanto, **compatível com as regras efetivamente instaladas**, e não comprova falha do agente ou do Indexer.

O índice `wazuh-alerts-*` contém outros eventos Sysmon EID 1 (80 na consulta ampla da mesma janela). Eles podem ser casos elevados por regras mais específicas; suas contagens não tornam a regra-base `61603` um alerta universal.

## Contrato offline: por que o primeiro teste não deveria alertar

Foi conferido o predicado da `110100` com quatro vetores **sintéticos**, sem executar processos ou comandos:

| Linha de comando simulada | Aciona o predicado de comando da 110100? | Resultado do teste |
| --- | --- | --- |
| `powershell.exe -NoLogo -NoProfile -NonInteractive -File ...` | **Não** | PASS — negativo esperado |
| `powershell.exe -NoProfile -EncodedCommand ...` | **Sim** | PASS — positivo de regex |
| `powershell.exe -NoProfile -enc ...` | **Sim** | PASS — positivo de regex |
| `powershell.exe -NonInteractive -Command Write-Output hello` | **Não** | PASS — negativo esperado |

**4/4 vetores PASS.** Isso é inspeção estática da condição `commandLine`, **não** um `wazuh-logtest` nem uma validação live de todos os campos/provider/pais/regras do evento.

## Situação de H01 após a investigação

- **Fonte nativa:** Sysmon EID1 `173036` → Security 4698 `15346`, mesmo usuário e servidor, **1,34 s**, tarefa benigna removida sem execução. **PASS no Windows.**
- **Wazuh/Discover:** Security 4698 `15346` presente como um documento pelo RecordID. **PASS para esse lado.**
- **Sysmon EID1 do mesmo teste:** 0 alertas no `wazuh-alerts-*` por RecordID e por identificador de comando. **Esperado sob a regra-base nível 0 e a exigência `-EncodedCommand` da 110100; não atestado no fluxo bruto do Manager.**
- **Motor de hunting offline:** 1 candidato de triagem em duas linhas pseudonimizadas do resumo nativo; **não** representa par indexado completo.
- **Status:** `H01_RULE_EXPECTATION_EXPLAINED`; `H01_WAZUH_RULE110100_END_TO_END=NOT_TESTED_WITH_MATCHING_COMMAND`. Nenhuma regra defeituosa foi identificada por esses critérios e **nenhuma regra ativa foi modificada**.

## Decisão técnica: não reduzir o limiar nem elevar todos os processos

**Não** modificar `log_alert_level` de 3 para zero, nem sobrepor indiscriminadamente a regra `61603` a nível 3. Isso pode indexar grande volume de processos e comprometer retenção, desempenho e utilidade de triagem. **Não** habilitar `logall_json` ou criar `wazuh-archives-*` só para fazer um teste parecer válido: isso precisa de change control próprio e avaliação de armazenamento/dados.

**Correção do plano de validação, sem mudança no Wazuh:** na **próxima janela ativa especificamente autorizada**, gerar **uma única execução benigna** de PowerShell usando a forma `-EncodedCommand` reconhecida pela `110100` para criar uma tarefa agendada **inerte e descartável**, sem executá-la. Pré-checks iguais aos anteriores: WazuhSvc ativo, Sysmon, auditoria 4698 Success, backup/rollback, tarefa inexistente, Security com retenção adequada, limitação de uma execução. Conferir a mesma conta/host, ordem dentro de 15 min e a ausência da tarefa ao final.

Critérios de aceite para esse ensaio **futuro** (não realizados nesta investigação):

1. No Security/Sysmon nativo, comprovar **Sysmon EID1 do PowerShell com linha de comando `-EncodedCommand`** e Security 4698 real, com mesmo ator e ativo.
2. No `wazuh-alerts-*`, comprovar **regra `110100`** para o mesmo evento de criação de processo e a ocorrência **4698** da mesma tarefa por RecordID, sem assumir correspondência apenas por horário.
3. Normalizar eventos somente após identidade real atestada, rodar correlacionador offline e documentar que é comportamento **benigno autorizado**, não incidente.
4. Se não houver dois alertas, **H01 permanece incompleto**; investigar sem repetição indiscriminada ou desabilitar controles.
5. **H02 e H03 não ficam automaticamente validadas** pelo H01: H02 precisa `4720 → 4624/4672` de mesmo SID e Logon ID; H03 requer FIM e execução **do mesmo artefato**. Retenção do Security e risco de sobreposição dos dois coletores continuam sob controle na Issue #15.

**Governança:** a janela anterior de H01 autorizou **um** teste, já executado e limpo. Este diagnóstico **não reabriu nem reutilizou** aquela autorização para gerar eventos adicionais. M1 permanece **15/17 (88,2%)**; pendem correlações completas H01/H02/H03 e sign-off independente, além da atestação do Manager para o gate de aceite final.

## Fontes

- [Relatório H01 nativo e consulta Discover](m1-h01-authorized-real-powershell-task-test-20261105.md)
- [Especificação H01/H02/H03](m1-three-hunting-hypotheses.md)
- [Revisão de tuning e falsos candidatos](m1-hunting-tuning-fp-attack-review-20261105.md)
- [Documentação Wazuh — níveis de regras](https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html)
- [Documentação Wazuh — alert level/threshold](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html)
- [Regras-base Wazuh Sysmon 61603](https://github.com/wazuh/wazuh-ruleset/blob/master/rules/0595-win-sysmon_rules.xml)

**Nota de procedência:** valores de regra e `ossec.conf` foram lidos **diretamente dos arquivos de configuração do container Wazuh Manager**, sob acesso autorizado somente leitura. Nenhum conteúdo de `alerts.json`/`archives.json` foi requisitado ou contornado.
