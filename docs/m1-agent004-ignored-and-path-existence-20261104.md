# M1 / H03 — exclusões FIM do agente 004 e existência física dos diretórios

**Verificação:** 04/11/2026, aproximadamente 18h16–18h18 BRT. **Método:** leitura autenticada do Wazuh Dashboard na aba `Ignored` do endpoint Windows `004`; segunda verificação somente leitura `Test-Path` dentro da VM Windows Server 2022. **Nenhuma alteração ativa aplicada.**

## Fontes e resultados

| Evidência | Resultado | Observação |
| --- | --- | --- |
| Identidade da interface | Breadcrumb **Endpoints → Windows Server (004) → Configuration → Integrity monitoring → Ignored**, integridade `enabled` | É a configuração apresentada para o agente `004`, não a página isolada do grupo |
| Ignored / Path | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini` | Exclusão pontual de `desktop.ini` na Startup |
| Ignored / Sregex | `\.log$\|\.htm$\|\.jpg$\|\.png$\|\.chm$\|\.pif$\|\.evtx$` | Extensões listadas na interface; **não há uma exclusão `.exe` explícita nesta lista** |
| FIM / Monitored (leitura anterior) | `C:\opt\wazuh-lab\monitorado`, marcado `realtime=yes` | Origem: `/opt/wazuh-lab/monitorado` do `default/agent.conf` central UnixStyle, sem seletor Linux |
| Windows 004: `Test-Path -PathType Container` | `C:\opt\wazuh-lab\monitorado` → **False** | O caminho herdado, apesar de exibido em Monitored, **não existe** no endpoint Windows |
| Windows 004: `Test-Path -PathType Container` | `C:\SecurityLab\H03` → **False** | Diretório isolado proposto para a mudança C ainda **não foi criado** |
| Caminho Startup realtime local | Diretiva local existente segundo inspeção anterior, com risco de execução automática | **NO-GO** para alocar binário benigno de teste |
| Par real H03 | Nenhum FIM de alteração + Sysmon ID 1 do mesmo executável verificado | **INCONCLUSIVE** |

A presença do caminho de Linux no painel demonstra **configuração declarada**, não monitoramento efetivo nem cobertura de diretório Windows. O `Test-Path=False` fecha a dúvida de existência física para esse caminho no momento da verificação. A ausência de `.exe` nas exclusões **não prova** que um futuro `.exe` esteja coberto, pois isso também depende do diretório existir, configuração em vigor, varredura/realtime, regras e telemetria.

**Evidência bruta mantida fora do Git:** screenshots remotos da aba Ignored em `.lab/fim-agent004-ignored-20261104.png` e do PowerShell em `.lab/fim-004-guest-paths-20261104.png`. Esses arquivos são privados e não devem ser versionados por conterem identificadores de host e contexto da VM.

## Consequências para a mudança C

1. **Não utilizar o caminho central Linux** `C:\opt\wazuh-lab\monitorado` para o teste H03: é inexistente no Windows e corresponde à mudança A de segregação `os="^Linux"`, que tem aprovação independente e gate separados.
2. **Não usar Startup**: é uma pasta de autorun, inadequada para testar executáveis.
3. O diretório segregado sugerido `C:\SecurityLab\H03` ainda **não existe e não está coberto**. A implantação da mudança C exige criar a pasta com ACL restrita, confirmar propriedades, adicionar diretiva FIM realtime **exclusivamente ao agente 004**, reiniciar `WazuhSvc` somente em janela aprovada e confirmar cobertura ativa posteriormente.
4. Aceitação de riscos do responsável está ratificada apenas para **mudança C** ([Issue #29](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/29)), mas não constitui validação operacional, execução de mudança nem prova H03.
5. Antes do binário H03: confirmar change control aplicável, baseline de hashes e backup DPAPI recuperável, observabilidade Manager → Indexer → Dashboard e evidências reais. O binário preparado no host nunca foi transferido nem executado no Windows 004 nesta passagem.

**Gate no checkpoint:** `AGENT004_DASHBOARD_IGNORED=OBSERVED`, `LINUX_INHERITED_DIR_EXISTS_ON_WINDOWS=false`, `ISOLATED_H03_DIR_EXISTS=false`, `H03_FILE_DETECTION=UNVERIFIED`, `DEPLOYMENT_GATE=BLOCKED`, `M1=11/17`.

**Referências internas:** [Configuração FIM do 004 no Dashboard](m1-agent004-dashboard-active-fim-20261104.md), [mudança C / aprovação e rollback](m1-change-c-approval-cutover-package-20261104.md), [teste benigno H03](m1-h03-benign-binary-test-plan-20261104.md).
