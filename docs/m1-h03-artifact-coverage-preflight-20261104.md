# M1/H03 — pré-gate de cobertura do artefato e teste benigno

**Data:** 04/11/2026. **Modo:** análise documental e diagnósticos read-only; sem testes de alteração ou execução de arquivo, sem alterações no Windows, Wazuh, Sysmon, índices ou auditoria.

## Contrato de correlação

H03 exige **file_change (Wazuh FIM)** anterior a **file_execution (Sysmon Event ID 1)** para o **mesmo ativo e mesmo artefato**, em **até 20 minutos**. O caminho/identidade do arquivo deve ser normalizado com base nos originais; hora e fuso precisam ser reconciliados. Um evento FIM de Registro, uma execução de outro arquivo ou proximidade temporal isolada **não comprovam** H03. Ver `docs/m1-three-hunting-hypotheses.md` e `scripts/hunt_correlations.py`.

## Evidência disponível

| Elemento | Estado | Implicação |
| --- | --- | --- |
| Windows `004` | `Active`, Windows Server 2022, Wazuh 4.14.9 (Manager, 04/11) | Agente presente, sem prova H03 |
| Syscheck local | Inventário read-only anterior: 6 diretivas (5 periódicas/12h, 1 realtime), todos caminhos existentes, 23 diretivas de Registro, 2 ignores | Os caminhos existentes não comprovam inclusão de um arquivo-alvo ainda não designado |
| Config central | Bloco UnixStyle realtime no `default`, inexistente no Windows; `agent_groups -S -i 004`: synchronized; `verify-agent-conf`: OK | Sync/parser não comprovam cobertura efetiva; bloco Unix não serve de alvo H03 Windows |
| Última varredura | Manager reportou início e término em 04/11/2026 16:58:47–17:00:47 (relógio exibido pelo Manager) | Demonstra execução registrada da varredura, não emissão de alerta de mudança |
| Ruleset | 550/553 nível 7; 554 nível 5; limiar de armazenamento 3 | Se regra acionada, nível não é a causa isolada esperada para ausência de alerta |
| Arquivos locais Manager | `alerts.json` atualizado em 04/11, `archives.json` sem atualização desde 01/11; `logall_json=no` documentado | Telemetria agregada não identifica evento H03; archive atual não é fonte completa |
| Indexer histórico | Resultados Syscheck de `004` observados como Registro; 0 arquivos no filtro não-HKEY do recorte anterior | Ausência do par arquivo+execução no recorte; não descarta FIM local |
| Artefato H03 concreto | **NÃO DESIGNADO** em evidência aprovada | Não é possível certificar cobertura por diretiva local específica |

## Gate de seleção do artefato (sem produzir evento)

1. Operador e revisor devem selecionar **um arquivo executável de teste benigno e descartável**, com origem e função verificadas, fora de caminhos críticos; usar alias privado em `.lab/`, sem publicar caminho, usuário ou hash bruto.
2. No próprio Windows `004`, confirmar que o caminho exato está **realmente dentro** de uma diretiva FIM local aplicável, que não corresponde a `ignore`, `restrict` ou outro filtro relevante e que o `agent.conf` central não invalida a cobertura. Documentar classificação **covered_realtime / covered_scheduled / excluded / not_covered / unknown**.
3. Se `covered_scheduled`, **não presumir** detecção em até 20 minutos: a frequência local é 43200s; qualquer coleta acelerada ou mudança de frequência requer change request específico. `covered_realtime` é preferível para um teste de 20 minutos, somente se cobertura e impacto comprovados.
4. Conferir que o Windows Sysmon Event ID 1 registra **a execução do próprio arquivo escolhido**. Não substituir por execução de `powershell.exe`, `cmd.exe` ou outro lançador sem identidade do arquivo binário correspondente.
5. Confirmar relógios/fusos, baseline de hash e logs, fonte e privilégios, critérios de parada, backup, rollback/limpeza, aprovação humana, janela e observabilidade endpoint → Manager → Indexer → Discover.

## Execução futura — NÃO AUTORIZADA NESTE CHECKPOINT

Somente após autorização humana **explícita e específica** para o artefato, ação, janela, consequências e cleanup, executar **uma alteração benigna controlada** do mesmo executável de teste, seguida de sua execução, verificando: (a) alerta FIM de arquivo com metadados originais; (b) Sysmon ID 1 com imagem correspondente; (c) ordem e diferença temporal até 20 min; (d) mesmo agente/ativo e objeto; (e) controle negativo com artefato distinto; (f) evento recebido no Manager, Indexer e Discover; (g) reversão/limpeza autorizada e registro de evidência privada. **Não implantar alteração de configuração, não forçar scan, nem manipular binário do sistema para fazer o teste passar.** Se qualquer precondição falhar, **NO-GO**.

## Resultado

`ARTIFACT_SELECTED=NO`; `LOCAL_COVERAGE_FOR_ARTIFACT=UNVERIFIED`; `H03_REAL_PAIR=INCONCLUSIVE`; `TEST_APPROVED=NO`; `DEPLOYMENT_GATE=BLOCKED`. A preparação não conclui nenhum item adicional do M1. As duas alterações locais preexistentes em `docs/m1-readonly-reconciliation-20261104.md` e `docs/roadmap-progress.md` são preservadas e não incluídas neste checkpoint.
