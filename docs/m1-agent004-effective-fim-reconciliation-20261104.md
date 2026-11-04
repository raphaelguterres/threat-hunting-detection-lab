# M1 — reconciliação FIM do agente 004: local, central e telemetria

**Checkpoint:** 04/11/2026, ~15h10–15h15 BRT. Verificações no ambiente ativo estritamente **somente leitura**. Não houve alteração em `agent.conf`, `ossec.conf`, regras, `auditpol`, serviços ou índices.

## Matriz de evidências

| Dimensão | Observação sustentada | Limite técnico |
| --- | --- | --- |
| Agente e plataforma | Manager: ID `004`, status `Active`, Windows Server 2022, agente Wazuh `4.14.9` | Estado válido no instante da consulta, sem teste de alteração de arquivo |
| FIM local | Inventário privado anterior: `syscheck.disabled=no`, frequência `43200` segundos, **6 diretivas** em caminhos existentes (**5 agendadas; 1 realtime; 0 whodata**), **23 diretivas de Registro**, duas entradas `ignore` | Inspeção de paths e modos é datada de 02–03/11; não foi revalidada a configuração local dentro da VM nesta passagem; não pressupor precedência final |
| FIM central | `default/agent.conf` distribui **1 diretiva FIM realtime UnixStyle**, caminho inexistente no Windows e não coincidente com nenhum dos seis locais, além de uma fonte `syslog` (inventário privado de 02/11) | O bloco Unix não adiciona cobertura útil ao Windows `004`; não demonstra que as seis diretivas locais falharam |
| Grupo e sintaxe | Manager: `agent_groups -S -i 004` → **synchronized**; `verify-agent-conf -f /var/ossec/etc/shared/default/agent.conf` → **OK** em 04/11 | Parser e sync não provam precedência efetiva, monitoramento dos seis caminhos ou alertas gerados |
| Varredura FIM no agente | `agent_control -i 004`: `Syscheck last started` em **04/11/2026 16:58:47** e `last ended` em **17:00:47**, horários exibidos pelo Manager | **Confirma registro de início e término da varredura**, não sua abrangência completa, ausência de erro, detecção de mudança nem entrega ao Indexer; os relógios devem ser normalizados antes de correlação |
| Alertas locais Manager | `alerts.json` presente, atualizado em **04/11/2026 18:12:02 UTC** (1.798.017 bytes) | Arquivo ativo e global, não confirmação de evento de arquivo do `004` |
| Archives locais Manager | `archives.json` presente, última modificação **01/11/2026 22:33:58 UTC** (1.832.766 bytes); inventário anterior não encontrou arquivos rotacionados acessíveis | Arquivo desatualizado; `logall_json=no` observado anteriormente. Não é evidência de ausência de eventos no Manager |
| Ruleset FIM | Checagem anterior de 04/11: arquivos `550`/`553` em nível 7, `554` em nível 5; Registro `594`, `597`, `598`, `750`, `751`, `752` em nível 5; limiar de armazenamento `log_alert_level=3` | Níveis compatíveis com armazenamento de alertas se as regras forem acionadas; não atesta disparo nem conteúdo por arquivo |
| Indexer | Consulta anterior: `syscheck.path` é `keyword` no índice de 03/11, 488 hits Syscheck do agente em 7 dias associados a Registro na amostra, e 0 ao excluir `HKEY*`; nenhum `wazuh-archives-*` listado | Janela histórica e tipos de índice diferentes; não equivale a eventos atuais nem prova ausência de FIM de arquivo |

## Conclusão de cobertura

**FIM local está configurado, as seis entradas locais foram previamente verificadas como caminhos existentes, o serviço/agent foi observado ativo, houve uma varredura Syscheck registrada com início e fim no Manager, e a configuração central está sincronizada e sintaticamente válida.**

**Cobertura efetiva de detecção de arquivos ainda NÃO foi comprovada ponta a ponta.** Os dados permitem separar: (a) caminho Linux central inaplicável a Windows; (b) seis diretivas locais que podem continuar operando; (c) eventos históricos de Registro presentes no Indexer; (d) ausência de evidência verificável de alteração de arquivo do `004` correspondente a H03; (e) archive local não atual e ausência de índice archives. Não atribuir causa única à lacuna.

## Próximos gates para eventual GO

1. Reconferir, dentro do `004`, as seis entradas, seus padrões de exclusão e qual diretiva cobre **o artefato real da hipótese H03**, sem publicar paths privados.
2. Revisar configuração mesclada/precedência efetiva local+central e última varredura, incluindo erros e timestamp com fuso normalizado.
3. Com janela/ação benigna **aprovadas separadamente**, acompanhar alteração de arquivo e confirmar a cadeia endpoint → Manager → Indexer → Discover e a correlação com Sysmon 1 do mesmo artefato, mesmo host e até 20 minutos; incluir controle negativo.
4. Em mudança **independente** e apenas após autorização, aplicar proposta mínima de escopo `os="^Linux"` ao bloco central Unix. Precondições: decisão agente `001`, inventário atual conforme contrato, revisão externa, baseline, backup/rollback operacional, janela e aprovação explícita.
5. Habilitar auditoria Windows `4698` somente em change request separado após revisão de retenção Security 20 MiB, fontes `eventchannel`, rollback e teste benigno aprovado.

**Gate formal na execução:** `EVIDENCE_COMPLETENESS=INCOMPLETE`; `DEPLOYMENT_GATE=BLOCKED`. Nenhuma mudança ativa aplicada.

**Rastreabilidade:** [reconciliação anterior](m1-readonly-reconciliation-20261104.md), [pacote FIM](m1-fim-change-approval-package.md), [plano 4698](m1-change-control-4698-fim-agent004.md), [matriz de aceite](m1-fim-acceptance-matrix.md). Este documento é independente das duas alterações locais preexistentes, que não devem ser sobrescritas.
