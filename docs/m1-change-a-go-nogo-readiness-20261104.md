# M1 — prontidão GO / NO-GO da mudança A (04/11/2026)

**Change ID:** `M1-FIM-OS-SCOPE` · **Janela condicional:** 05/11/2026, 18h–19h BRT.

**Último levantamento read-only:** 04/11, ~23h05 BRT.

**Decisão:** `NO-GO / DEPLOYMENT_GATE=BLOCKED`.

## Entenda o GO

**GO** = autorização operacional explícita para uma alteração controlada; não é referência à linguagem de programação Go. **NO-GO** = não executar enquanto requisitos pendentes ou divergências bloqueadoras permanecerem.

O validador atual `scripts/m1_evidence_gate.py` **sempre imprime `DEPLOYMENT_GATE=BLOCKED`, inclusive quando o manifesto está documentalmente completo**. Isso é uma barreira intencional contra deploy automático. O sucesso de um teste significa no máximo **`EVIDENCE_COMPLETENESS=REVIEW_READY`**; a mudança A ainda exige **GO operacional externo e separado**, assim como rechecks durante a janela. Não desabilitar essa proteção para acelerar o M1.

## Mapeamento dos nove checks do manifesto

| Check pendente no manifesto | Evidência técnica existente | O que falta para atestar |
| --- | --- | --- |
| `inventory_review` | Snapshot read-only 3/3 de `002`, `004`, `005`, status/sync datados e um grupo `default` | **Atestado humano do proprietário**; reconfirmar dados frescos na janela |
| `os_impact_review` | Regex Linux corresponde a `002/005`, exclui `004`; Dashboard do `005` General/Monitored/Ignored; pasta existente em `002/005` | **Atestado específico** do impacto no **FIM realtime e `localfile` Unix**; verificar efetividade depois do cutover |
| `group_precedence_review` | Apenas `default` nos três agentes; FIM local Windows inventariado; agente `002` tem duas diretivas locais sem realtime | Revisão humana dos conflitos e do FIM local `005`; Dashboard efetivo do 005 já inspecionado, mas XML nativo inacessível à conta remota |
| `baseline_integrity` | SHA, UID/GID, modo e tamanho do `default/agent.conf` correspondem ao backup real | Atestar a evidência; **revalidar imediatamente antes da execução** |
| `parser_staging` | Candidata real: `verify-agent-conf: OK`, exit 0, staging temporário removido | Atestar evidência concreta; conferir hash da candidata na janela |
| `backup_integrity_real` | Cópia DPAPI `CurrentUser` do arquivo central original; hash conferido | Atestar e confirmar recuperação pelo mesmo perfil autorizado no momento de execução |
| `rollback_rehearsal_real` | Teste isolado de restauração real e corrupção negativa: PASS | Atestar e aceitar procedimento operacional. **Rollback real do Manager ainda não executado** |
| `change_approval` | Exceção individual da mudança A e cinco riscos ratificados na [Issue #31](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/31#issuecomment-6647042764) | **GO operacional final específico** ainda não concedido; não inferir da ratificação |
| `approved_window` | Janela 05/11 18h–19h BRT aprovada **condicionalmente** na [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17#issuecomment-6646704047) | Atestar no formato contratual e **reconfirmar** que a execução está dentro da janela |

Todos os nove campos continuam sem `verified` no manifesto; isso não significa que nove tarefas técnicas precisem ser repetidas do zero. A revisão humana e a análise de impacto permanecem diferentes de um teste sintático que passou.

## Evidência operacional complementar — sem alteração de ambiente

- O Wazuh Manager reportou `default (3)`; executores principais `wazuh-analysisd`, `wazuh-remoted`, `wazuh-syscheckd`, `wazuh-db`, `wazuh-apid` e `wazuh-logcollector` **running**. Alguns componentes opcionais não estavam executando; o comando `wazuh-control status` retornou exit `1` e, por isso, **não deve ser registrado como PASS global sem análise**.
- Kali via `timedatectl`: `Timezone=America/New_York`, `NTP=yes`, `NTPSynchronized=yes`. O host Windows tem fuso Brasília, mas `w32tm /query /status` respondeu **Windows Time service not started**. Um checkpoint anterior mediu Kali aproximadamente **+22 segundos** frente ao host Windows; **não atribuir a causa a um lado sem referência de tempo independente**.
- As duas VMs estavam ligadas, e a branch Git local estava limpa em `40663fb`. Nenhuma alteração em FIM, serviço, índice ou grupos foi executada nesta revisão.
- O PR [#25](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/25) tinha os três jobs principais em SUCCESS na última verificação; CodeRabbit `SKIPPED`. O CI precisa ser conferido no SHA do commit de execução, não presumido com base em SHA antigo.

## Decisões manuais em ordem

1. **Agora:** proprietário revisar o [cartão A1/B1 de atestado do inventário e impacto](m1-change-a-owner-inventory-impact-attestation-20261104.md) e dar confirmação expressa, ou indicar divergência. Esta decisão **não** autoriza implantação.
2. **Na janela, após lembrar às 17h45:** operador reconfirma baseline/hash, XML candidato, integridade do backup recuperável, sincronização 3/3, clocks/telemetria, saúde e plano de rollback; se algum dado crítico não puder ser verificado, manter NO-GO.
3. **Somente após checks:** proprietário decide **GO operacional da mudança A** dentro da janela condicional de 05/11, 18h–19h BRT. Sem GO explícito, não implantar.
4. **Depois de eventual implantação autorizada:** provar FIM Linux nos agentes `002/005`, preservar FIM Windows `004`, validar Manager→Indexer→Dashboard e executar rollback aprovado se critérios de parada ocorrerem.

## Separação de escopo

- **Mudança A:** seletor `os="^Linux"` para bloco central inteiro (FIM e `localfile`).
- **Mudança B:** auditoria Windows `4698`, exige processo separado.
- **Mudança C:** H03 Windows, diretório isolado, binário benigno e correlação FIM + Sysmon, exige janela e aprovação próprias.
- **M1:** 11/17 (64,7%) — contagem do checklist, não prontidão ou classificação geral de segurança.

**Resultado:** `OWNER_INVENTORY_IMPACT_ATTESTATION=PENDING` · `STAGED_PARSER=PASS` · `BACKUP_ISOLATED_RESTORE=PASS` · `CI_LAST_VERIFIED=PASS` · `HOST_WINDOWS_TIME_SERVICE=NOT_RUNNING` · `MANAGER_CORE_SERVICES=OBSERVED_RUNNING` · `CHANGE_A_DEPLOYED=NO` · `DEPLOYMENT_GATE=BLOCKED`.
