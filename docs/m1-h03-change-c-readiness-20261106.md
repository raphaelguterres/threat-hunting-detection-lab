# M1 / H03 — preparação da mudança C, sem implantação (06/11/2026)

**Objetivo:** um diretório NTFS isolado, monitoramento FIM realtime restrito ao Windows Server agente `004` e critérios verificáveis para, futuramente, correlacionar mudança e execução benigna do **mesmo** artefato.

**Decisão atual:** `CHANGE_C=NO_GO`, `H03_ACTIVE_TEST=NOT_AUTHORIZED_IN_THIS_WINDOW`, `M1=15/17 (88.2%)`. **Nenhum diretório foi criado, nenhuma DACL aplicada e nenhum serviço/VM reiniciado nesta etapa.**

## Situação atual e validade de evidências

- Em **06/11 às ~02h39 BRT**, as VMs **WindowsServer e Kali estavam em estado VirtualBox `saved`**, não `running`. Isso impede afirmar saúde atual de `WazuhSvc`, ingestão ou FIM. Mantido o estado das VMs.
- Última inspeção read-only **05/11**: seis diretivas locais de FIM Windows, uma recebida de configuração central, diretório `C:\SecurityLab\H03` **ausente**, sem cobertura FIM local ou central registrada para esse alvo. Não reutilizar essa captura como verificação em tempo real de 06/11.
- Em **04/11**, a mudança C tinha uma **janela condicional de 18h–19h**, já expirada. A [exceção de autoavaliação](m1-change-c-solo-owner-review-exception-20261104.md) foi ratificada **somente para Change C** e não constitui revisão humana independente do M1. Backups DPAPI do `ossec.conf` foram documentados dentro da VM, **mas sua disponibilidade e integridade precisam ser reconfirmadas após retomada**, com a mesma conta de operador.
- Existem alertas FIM **reais** no Windows `004` para artefato benigno **não executável** (`.m1probe`), porém **nenhuma execução do mesmo artefato foi verificada**. H03 continua sem par real.

## Diretório selecionado como candidato

`C:\SecurityLab\H03` — **caminho proposto, não criado**. Local, separado das pastas Windows/Program Files, Wazuh e Startup, sem rotina de autostart, serviço ou tarefa associada. Artefato futuro: **um** `.exe` benigno próprio, com duas versões que diferem apenas no identificador exibido, já preparadas no host em `.lab/`. **Não transferir nem executar na VM nesta fase.**

A segurança da pasta **não pode ser inferida da DACL de `C:\`**. Antes de um GO, exigir alvo ausente, volume NTFS, ausência de links de reanálise e **criação já com DACL protegida**: `SYSTEM` e `Administrators` com controle completo, SID verdadeiro do operador autorizado com Modify, nenhuma escrita ampla para `Everyone`, `Authenticated Users`, `BUILTIN\Users` ou `INTERACTIVE`. Verificar DACL, proprietário e herança **no diretório criado**, não apenas em simulação.

**Validações offline em 06/11 (host, sem VM):**
- `scripts/M1_H03_CHANGE_C_ACL_SIMULATE.ps1` com SID **sintético**: **3 ACEs**, 0 ACEs amplas de escrita, herança protegida, exit 0. Controle negativo com SID `Everyone`: exit **2**, rejeitado.
- `scripts/m1_h03_candidate_safety_gate.py`: candidato isolado `REVIEW_REQUIRED` com cobertura ainda não atestada, não `GO`. Pasta Startup: `NO_GO`.
- `scripts/m1_h03_change_c_offline_diff_gate.py`: criado para aceitar **exclusivamente uma diretiva nova** `<directories realtime="yes" check_all="yes">C:\SecurityLab\H03</directories>` no `ossec.conf` local do **004**, com o restante idêntico (incluindo comentários, regras, Security, ignores e diretivas FIM preexistentes). **13 testes sintéticos PASS**. Não foi comparado a um novo XML efetivo da VM suspensa.

## Próxima janela de Change C: gates obrigatórios

| Fase | Ação futura sob autorização específica | Evidência para GO |
| --- | --- | --- |
| **C0 — baseline** | Retomar VMs mediante GO de operação; confirmar agente, relógios, versão, config ativa e backup DPAPI do operador | `004` íntegro; baseline/hashes recentes; rollback recuperável |
| **C1 — diretório/ACL** | Criação de diretório protegido sem intervalo permissivo; inspecionar NTFS, proprietário, DACL, herança e reparse | Somente SIDs mínimos; **nenhuma ACE pública de escrita**; target local real |
| **C2 — config FIM** | Criar proposta privada de `ossec.conf`; **adicionar só uma diretiva** FIM realtime no agente `004`, nunca no grupo compartilhado `default` | `m1_h03_change_c_offline_diff_gate.py` **exit 0**, XML/parser e demais opções inalterados |
| **C3 — ativação** | Somente após GO da janela, reiniciar **apenas** `WazuhSvc`; consultar configuração Syscheck ativa | `C:\SecurityLab\H03` presente **antes do restart**, FIM realtime observável e agente saudável |
| **C4 — smoke test** | Um arquivo inerte dentro do alvo, com teste FIM de criação/alteração/remoção **separadamente autorizado** | Evento FIM dessa pasta na origem e Indexer/Discover; sem alteração em outros agentes |
| **C5 — teste H03** | Somente depois de **nova aprovação expressa para binário**: v1→v2 no mesmo caminho, depois uma execução benigna | FIM v2 **antes** de Sysmon ID 1 do **mesmo `.exe`**, mesmo host, até 20min, horários UTC e IDs verificáveis |
| **C6 — fechamento/rollback** | Remoção segura do artefato, reversão isolada de `ossec.conf` se aprovada e nova verificação | Hash da baseline, restauração comprovada, serviço e telemetria saudáveis, evidências privadas íntegras |

**Regra decisiva:** diretórios `realtime` do Wazuh precisam **existir antes do restart** do agente. Não usar caminho UNC/mapeado no Windows. A revisão de 2026 não autorizou nenhuma etapa C1–C6 nesta conversa.

**Atenção à visibilidade da execução:** Sysmon Event ID 1 **nativo** não necessariamente gera alerta `wazuh-alerts-*`: regra-base `61603` nível 0 com limiar 3. Planejar antecipadamente a forma **autorizada** de comprovar o processo benigno, sem elevar globalmente os Sysmon nem reivindicar correlação completa apenas pelo evento nativo. Uma ausência de alerta continua `INCONCLUSIVE`, não prova de ingestão.

## Gate e critérios de parada

`CURRENT_STATUS=NO_GO_WAITING_FRESH_PREFLIGHT_AND_CHANGE_WINDOW` · `EFFECTIVE_TARGET_ACL=UNVERIFIED` · `FIM_REALTIME_TARGET=NOT_APPLIED` · `H03_REAL_CORRELATION=NOT_VERIFIED` · `DEPLOYMENT_GATE=BLOCKED`.

Abortar diante de relógios divergentes, configuração ativa desconhecida, backup DPAPI inacessível, DACL ampla, divergência do único diff permitido, pasta inexistente ao reiniciar, evento FIM/execução não observável, impacto de outros agentes ou qualquer restrição da ferramenta. Não contornar bloqueios de acesso anteriores, não reutilizar a janela de 04/11, não alterar B/4698 nem a mudança A/Linux nesta proposta.

### Fontes

[Change C e backup de 04/11](m1-change-c-approval-cutover-package-20261104.md) · [Runbook ACL/FIM](m1-h03-three-gates-acl-fim-sequence-20261104.md) · [Teste binário benigno ainda não executado](m1-h03-benign-binary-test-plan-20261104.md) · [Wazuh FIM realtime](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/basic-settings.html) · [Wazuh precedência local/central](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/how-to-configure-fim.html) · [Issue #29](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/29).
