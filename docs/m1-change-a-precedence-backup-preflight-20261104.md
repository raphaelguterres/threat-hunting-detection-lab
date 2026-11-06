# M1 — precedência, integridade do backup e preparação dos pré-checks

**Checkpoint:** 04/11/2026, ~23h28 BRT. **Mudança:** `M1-FIM-OS-SCOPE` (A).
**Decisão:** `NO-GO`. Nenhum arquivo ativo, agente, índice, serviço ou relógio alterado.

## Precedência FIM por sistema operacional

A [documentação oficial de configuração centralizada do Wazuh](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html) estabelece: primeiro o agente lê `ossec.conf`; depois, `agent.conf`, com possibilidade de sobrescrever parâmetros conflitantes e agregar caminhos diferentes. Quando há vários grupos, o último grupo da lista tem maior prioridade. **Este laboratório usa apenas `default` nos três agentes atuais.**

| Agente | Configuração local / efetiva observada | Central atual | Resultado do review |
| --- | --- | --- | --- |
| `002` Linux | `ossec.conf` lido diretamente: dois nós `<directories>` com `/etc,/usr/bin,/usr/sbin` e `/bin,/sbin,/boot`, nenhum `realtime` local | Diretório Unix `/opt/wazuh-lab/monitorado`, `realtime=yes`; `localfile` Unix | Não existe sobreposição textual entre caminhos FIM locais e o central; diretórios coexistem |
| `005` Linux | Dashboard do endpoint exibiu sete diretórios e exclusões; `/opt/wazuh-lab/monitorado` está marcado realtime e não está ignorado | Mesmo bloco central de Linux | Configuração exibida consistente; **leitura bruta do `ossec.conf` local ainda restrita** |
| `004` Windows | FIM local com seis diretivas observado em inventário anterior | Bloco Unix central aparecia normalizado no Dashboard Windows; pasta herdada inexistente | A alteração futura pretende impedir a aplicação desse bloco no Windows, sem alterar FIM local |

O único bloco central ativo contém **uma diretiva FIM Unix realtime e uma fonte `localfile` Unix**; adicionar `os="^Linux"` à sua abertura limita **ambas** aos agentes Linux. Regex em metadados observados: `002/005` correspondem e `004` não corresponde. **O comportamento runtime após mudança ainda não foi verificado.**

## Integridade real e ensaio isolado

| Controle | Rechecagem desta sessão | Restrição |
| --- | --- | --- |
| Hash do `default/agent.conf` ativo × backup DPAPI | `MATCH` | Sem divulgar hash privado |
| UID/GID/modo/tamanho | `999:999`, `0660`, 221 bytes, todos idênticos à baseline | Repetir dentro da janela |
| Candidata privada (233 bytes) | Reversão byte a byte restaura os 221 bytes originais; único acréscimo `os="^Linux"` | Não aplicada |
| Parser oficial da candidata | `verify-agent-conf: OK` em staging temporário, validado anteriormente em 04/11 | Revalidar se baseline/candidata mudar |
| Restauração de backup DPAPI real em sandbox isolado | `PASS` | Dependência de mesmo usuário Windows (DPAPI CurrentUser) |
| Controle negativo de corrupção e reversão isolada | `PASS`/`PASS`, sandbox removido | **Restauração no Manager ativo NÃO testada** |
| Pré-check privado de somente leitura | 14 verificações `PASS`, 0 falhas; grupo com 3, agentes `Active`, parser ativo e rollback isolado | Não reconfirma sync individual nem aprovação |

## Estado do manifesto `.lab/m1-evidence.json`

Após backup prévio e substituição atômica, foram registrados **sete controles com evidência de origem identificada**: `inventory_review`, `os_impact_review` (autoatestado explícito do proprietário), `group_precedence_review`, `baseline_integrity`, `parser_staging`, `backup_integrity_real` e `rollback_rehearsal_real` (revisão técnica de observações e testes). O documento privado `m1-change-a-technical-evidence-review-20261104.json` registra que **não ocorreu revisão humana independente** e que o rollback foi apenas isolado.

**Pendentes:** `approved_window` (revalidar a janela real no momento da execução) e `change_approval` (GO operacional do proprietário, ainda não concedido). **O script `m1_evidence_gate.py` sempre preserva `DEPLOYMENT_GATE=BLOCKED`, mesmo com revisão documental completa. Isso não deve ser contornado.**

## Preparação da janela (05/11/2026, 18h–19h BRT)

Foi criado e testado **somente no diretório privado** o script `.lab/m1-change-prep/M1_CHANGE_A_READONLY_PREFLIGHT_20261105.ps1`. Ele compara novamente baseline, candidato, grupos e saúde básica, executa o ensaio isolado e imprime sempre `DEPLOYMENT_GATE=BLOCKED`. **Não aplica mudanças, reinicia serviços, libera GO ou busca contornar consultas de sync bloqueadas**. A execução de 04/11 ocorreu fora da janela e não substitui a rechecagem de 05/11.

**Às 17h45:** existe lembrete de revisão. Para executar os novos pré-checks será necessário retomar a sessão autorizada. Não há execução remota automática agendada. **Depois das 18h:** somente com janela válida, revisão de diferenças, sync efetivo e **GO separado** será possível considerar alteração ativa.

Antes de provas com timestamps, revisar a diferença observada de ~22 segundos entre o Kali (NTP sincronizado) e o Windows host (serviço Windows Time não iniciado), sem modificar horários por esta mudança. Se houver dúvida sobre sincronização, manter `NO-GO`.

**Fora do escopo:** mudança B (auditoria 4698), C (H03) e testes de eventos reais dessas trilhas. M1 segue `11/17 (64,7%)` — contagem de checklist, não nota de segurança.

### Evidências relacionadas

- [Cartão de atestado do proprietário](m1-change-a-owner-inventory-impact-attestation-20261104.md)
- [Análise FIM do Linux 005](m1-agent005-fim-ignored-and-path-checkpoint-20261104.md)
- [Parser e CI da candidata](m1-change-a-parser-ci-20261104.md)
- [Exceção individual ratificada](m1-change-a-solo-owner-review-exception-20261104.md)
- [Issue #17 — mudança A](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17)
