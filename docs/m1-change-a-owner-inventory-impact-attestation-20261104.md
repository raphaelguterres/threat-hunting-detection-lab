# M1 — cartão de atestado do proprietário (pré-mudança A)

**Preparado em:** 04/11/2026, ~23h BRT.

**Change ID:** `M1-FIM-OS-SCOPE` — **somente seletor Linux no grupo `default`**.

**Status:** `OWNER_INVENTORY_AND_IMPACT_ATTESTATION=PENDING`, `CHANGE_A_EXECUTION=NO_GO`, `DEPLOYMENT_GATE=BLOCKED`.

> Este cartão **não é um atestado assinado**. O proprietário precisa revisar os itens e confirmar explicitamente. A exceção de autoavaliação ratificada na [Issue #31](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/31#issuecomment-6647042764) é **separada** da autorização operacional de implantação, que ainda não foi fornecida.

## A — Inventário observado e identificado

| ID Wazuh | Família SO | Grupo | Status da observação | Sincronização na captura |
| --- | --- | --- | --- | --- |
| `002` | Linux (contêiner de laboratório) | apenas `default` | Active | Synchronized |
| `004` | Windows Server 2022 | apenas `default` | Active | Synchronized |
| `005` | Linux (agente nativo Kali) | apenas `default` | Active | Synchronized |

**Fonte:** coleta autorizada `agent_control` + `agent_groups`, no dia **04/11 às ~21h34 BRT**, snapshots privados `.lab/m1-inventory-manager-readonly-20261104.json` e CSV. O grupo `default` tinha **3** membros, sem grupo concorrente; `001` já fora do cadastro, `003` fora do grupo e `Never connected`. Status/sync individuais foram confirmados **na hora da coleta**, mas a reconfirmação individual mais recente foi bloqueada — não deduzir sincronização atual.

**Decisão manual A1:** o proprietário revisou esses três IDs, famílias, o grupo único `default` e as limitações de atualidade? **PENDENTE**.

## B — Efeito completo da mudança A

**Arquivo único a ser alterado futuramente, somente com GO:** `/var/ossec/etc/shared/default/agent.conf`.

**Diff esperado (apenas a tag de abertura):**

```diff
-<agent_config>
+<agent_config os="^Linux">
```

O bloco contém **duas configurações Unix**: diretiva de **FIM realtime** para `/opt/wazuh-lab/monitorado` e fonte de logs `localfile` Unix. O seletor é aplicado ao **bloco inteiro**, não só à linha FIM. Nenhuma outra diretiva deve mudar.

**Impacto previsto:**

| ID | Esperado após a futura mudança A | Pré-condição / verificação |
| --- | --- | --- |
| `002` Linux | Mantém diretiva FIM realtime de grupo e `localfile` Unix | O caminho `/opt/wazuh-lab/monitorado` **existe**; FIM local com dois diretórios não realtime |
| `005` Linux | Mantém FIM realtime de grupo e `localfile` Unix | Dashboard General/Monitored/Ignored: sete diretórios, alvo realtime e sem exclusão; pasta **existe**; arquivo local bruto ainda protegido |
| `004` Windows | Deixa de receber diretiva Unix de grupo; mantém as próprias diretivas FIM locais | Antes, Dashboard mostrava caminho Linux herdado normalizado para Windows sem existência física; seis diretivas FIM locais inventariadas, inclusive Startup (não usar para testes) |

**Limite:** a previsão foi validada em regex de metadados de SO e parser oficial em staging, **não** pela distribuição real da nova configuração. A fonte `localfile` Unix **também fica limitada aos Linux**. Após eventual implantação, confirmar perda zero de fontes Linux esperadas e ausência do bloco Unix no Windows.

**Decisão manual B1:** o proprietário aceita expressamente o impacto do filtro **FIM + `localfile` Unix** e reconhece os limites de validação? **PENDENTE DE ATESTADO ESPECÍFICO**, separado da ratificação de riscos A.

## C — Verificações técnicas já demonstradas

| Controle | Resultado | Revalidação necessária |
| --- | --- | --- |
| Candidata de XML baseada no arquivo real de 221 B | 233 B; única inserção `os="^Linux"`; diff reversível | Conferir diff e hash novamente na janela |
| Parser oficial Wazuh 4.14.9 da candidata | **`verify-agent-conf: OK`** em arquivo temporário não ativo; temporários eliminados | Validar SHA da candidata no cutover e, se necessário, parser novamente |
| Backup DPAPI de `agent.conf` + baseline | SHA/bytes, owner/group e modo de arquivo coincidentes; ensaio de restauração isolada passou | Verificar perfil da conta DPAPI, SHA, UID/GID `999:999`, modo `0660`, recursos/tempo de rollback |
| CI e testes | Commit [`ff283c2`](https://github.com/raphaelguterres/threat-hunting-detection-lab/commit/ff283c2): 3/3 jobs GitHub Actions SUCCESS; local 220 passed / 4 skipped / 160 subtests | Conferir CI no SHA **específico da implantação** |
| Sincronização/telemetria | Wazuh Manager listou três agentes `Active`; grupo `default` com três membros | Sync individual no cutover; ingestão Manager → Indexer → Dashboard |
| Consistência temporal | Kali observado ~22 segundos à frente do host em consulta UTC | Conferir horários UTC antes de comparar eventos, sem alterar o relógio fora de escopo |
| Reversão real | Ensaio com conteúdo real em área isolada `PASS` | **Restauração ativa não ensaiada**, rollback operacional precisa aceite e plano de parada |

## D — Separação de decisões

| Decisão | Estado |
| --- | --- |
| Aceitação específica dos 5 riscos da exceção individual A | **RATIFICADA** na [Issue #31](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/31#issuecomment-6647042764) |
| Janela 05/11/2026, 18h–19h BRT | **APROVADA CONDICIONALMENTE**, não inicia sozinha |
| Atestado do inventário A1 | **PENDENTE** |
| Atestado do impacto completo B1 | **PENDENTE** |
| Rechecks técnicos na janela | **PENDENTES** |
| Autorização operacional final / GO | **NÃO RECEBIDA** |
| Distribuição ou produção de alertas reais pós-mudança | **NÃO EXECUTADA** |
| Gate do validador privado | **INCOMPLETE / BLOCKED**, intencional; não editar flags por suposição |

**Declaração proposta para confirmação em conversa/Issue #17 (não assinada):**

> Confirmo que revisei o inventário atual de três agentes do grupo `default` — `002` e `005` Linux, `004` Windows Server 2022 — e aceito como base de escopo, sujeito à rechecagem na janela. Reconheço que `os="^Linux"` irá restringir **todo o bloco** de `agent.conf`, incluindo a diretiva FIM realtime e a fonte `localfile` Unix, aos agentes Linux; o Windows deverá preservar seu FIM local. Concordo com a análise de impacto documentada, sem considerar parser/CI como prova de eventos reais. Esta confirmação **não autoriza a implantação**, que exigirá GO operacional separado após os pré-checks.

**Não publicar raw exports/snapshots privados** nem marcar um revisor externo inexistente. Se o proprietário discordar de qualquer item, manter **NO-GO** e reconciliar a diferença antes do atestado.

## Próximo fluxo

1. Proprietário lê A1 e B1 e confirma explicitamente (ou aponta divergência).
2. Registrar sua resposta fielmente em [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17) como **`OWNER_SELF_ATTESTATION`**, sem fingir revisão independente.
3. Preparar os controles de pré-checks de 05/11 às 17h45 BRT: baseline atual, backup/rollback, saúde e sincronização, parser e CI no SHA da implantação.
4. Somente após essas verificações, solicitar **autorização final da execução da mudança A**, distinta deste cartão e da aprovação da janela.
5. Depois de eventual mudança autorizada, comprovar FIM/telemetria real nos dois Linux e ausência de regressão no Windows via Manager → Indexer → Discover, com rollback aprovado se falhar.

Referências: [pre-gate](m1-change-a-parser-ci-20261104.md), [FIM 005](m1-agent005-fim-ignored-and-path-checkpoint-20261104.md), [exceção A](m1-change-a-solo-owner-review-exception-20261104.md), [matriz FIM](m1-fim-acceptance-matrix.md).
