# M1 — mudança controlada Windows Security 4698 (05/11/2026)

**Estado da mudança B/4698:** **APLICADA E VALIDADA no escopo nativo Windows → Wazuh Indexer/Discover**. Não equivale a aceite completo da mudança A/FIM nem ao encerramento do M1.  
**Proprietário:** autorização explícita na conversa de 05/11/2026.  
**Janela:** **15h47min22s–16h17min22s BRT**, no Windows Server de laboratório, agente Wazuh `004`.  
**Mudança aplicada:** habilitar somente **Success** em `Audit Other Object Access Events`; a auditoria Failure, fontes Wazuh, `agent.conf`, `ossec.conf`, contêineres, VMs e regras **não** foram alterados.

## 1. Preflight e controle de rollback

| Verificação antes da mudança | Evidência observada |
| --- | --- |
| Sessão do Windows Server | Administrador, agente Wazuh em execução |
| Política `Other Object Access Events` | **No Auditing**, confirmada imediatamente antes da alteração |
| Log Windows Security | Habilitado, **Circular**, **20 MiB**, aproximadamente **15.297 registros** |
| Idade do evento mais antigo | **353,4 horas (~14,7 dias)** no recorte examinado |
| Espaço disponível no volume de sistema | ~**35 GiB** |
| Coletores Security do Wazuh | **2** locais: **1 amplo**, **1 filtrado apenas por exclusões** |
| Duplicidade de coleta | **Risco potencial identificado; não mitigado nem declarado eliminado** |
| Tarefa específica do teste | **Não existia** |
| Compartilhamento dos scripts | Acessível somente para leitura na VM; não apropriado para gravar o baseline |
| Backup real da política | Exportação local `auditpol /backup`, **6.227 bytes**, no disco da VM |
| Recuperação | Script `RESTORE_4698.ps1` criado **dentro do Windows Server**, parse PowerShell **PASS**, baseline original guardado |
| Rollback executado em produção de teste? | **Não**: artefato preparado, mas restauração real não invocada porque não houve gatilho |
| Relógios | Guest Windows em Pacific Standard Time; timestamps de origem registrados em UTC. Host em BRT; diferenças de apresentação não foram confundidas com deriva de relógio |

**Decisão pré-change:** o log Security apresentava retenção observada superior a 48 horas; o caminho de restauração local foi preparado antes de aplicar a mudança. A possível sobreposição dos dois coletores foi **aceita somente como risco de observação para um teste benigno único dentro da janela**, **sem alterar ou aprovar sua permanência como configuração ideal**. A correção/deduplicação futura permanece tarefa própria da Issue #15. Não aumentar Security nem alterar filtros automaticamente nesta mudança.

## 2. Execução e prova de origem — Windows Server 004

| Etapa | Data/hora | Resultado |
| --- | --- | --- |
| Alteração `auditpol` somente na subcategoria, `Success` | **05/11, 15h52min09s BRT** | **PASS** |
| Confirmação de política após aplicação | Imediata | **Success**; Failure não habilitada |
| Criação de **uma** tarefa agendada descartável | **05/11, 15h53min07s BRT** | **PASS** |
| Windows Security EventID | `4698`, `eventRecordID=15301` | **1 evento do teste identificado no canal nativo** |
| Ação da tarefa | Comando inerte programado para o **dia seguinte**, removido antes do agendamento | **Nunca executada** |
| Exclusão da tarefa e checagem de ausência | Logo após a criação | **PASS; tarefa não permanece registrada** |

A tarefa temporária, chamada `Wazuh_M1_4698_Benign_20261105`, foi criada para provar **o evento de auditoria de criação**. Não houve execução do payload e não foi feita persistência permanente. Os detalhes originais (XML, IDs internos e capturas) permanecem apenas em `.lab/`.

## 3. Prova de ingestão no Wazuh

O Wazuh Discover, índice `wazuh-alerts-*`, apresentou **1 documento** para:

```text
agent.id: 004 and data.win.system.eventID: 4698
```

O documento foi inspecionado em modo somente leitura e continha **o mesmo nome de tarefa** e **o mesmo `data.win.system.eventRecordID=15301`** do Security nativo. A tela mostrava horário **13h53min11s** na convenção local do Kali/Wazuh, enquanto a origem Windows registrava **18h53min07,696s UTC (15h53min07s BRT)**. Trata-se da mesma ocorrência por **agente, EventID, identidade da tarefa e RecordID**; a coincidência não foi inferida apenas pela contagem.

**Resultado tecnicamente demonstrado:** `WINDOWS_SECURITY_4698_NATIVE=VERIFIED`; `4698_INDEXER=VERIFIED`; `4698_DISCOVER=VERIFIED`. O documento indexado também inclui campo `manager.name`. **A inspeção independente do arquivo `alerts.json` dentro do Manager continua não realizada**, em razão da restrição anterior de acesso remoto a logs brutos; não se contornou esse controle. **Não** promover `manager_ingestion` a `verified` no manifesto global da mudança A somente com esta captura.

Um único documento no filtro exato **não prova deduplicação geral dos dois coletores Security** e não elimina o risco estrutural identificado.

## 4. Pós-checks e segurança

| Critério | Verificado |
| --- | --- |
| Política `Success` continua habilitada e Failure inalterada | **PASS** |
| Evento de teste 4698 no Security, RecordID 15301 | **PASS** |
| Remoção/ausência da tarefa temporária | **PASS** |
| WazuhSvc permanece Running | **PASS** |
| Log Security habilitado, circular, limite 20 MiB | **PASS** |
| Contagem Security após teste | **15.316** |
| Idade do registro mais antigo após teste | **353,5 horas** — sem indício de perda súbita do histórico nesta observação |
| Backup original e rollback local | **Presentes**, rollback não executado |
| Configuração de coletores Security e Wazuh | **Não alterada** |
| Duplicidade real ampla, impacto de longo prazo e ingestão futura | **Ainda não mensurados** |
| Aceite global do Manager e revisor independente | **PENDENTES** |

**Evidências privadas:** `.lab/m1-4698-controlled-change-20261105-private.json` reúne 12 arquivos com SHA-256 (roteiros e capturas) e resultado operacional. A exportação nativa de `auditpol`, o baseline e o script de recuperação ficam no armazenamento local do Windows Server, em pasta de trabalho protegida. Nenhuma dessas fontes brutas é publicada no GitHub.

### Condições de acompanhamento

- **Não remover** o backup de política e o rollback; monitorar retenção efetiva do canal Security após a auditoria permanecer ativada.
- Reavaliar os **dois** coletores locais de Security em change request específico e com medição real de duplicidade; o teste único indexado não encerra esse risco.
- Se houver crescimento inesperado de log, perda de visibilidade, alteração involuntária de política ou falha operacional, **utilizar o rollback local somente com verificação de baseline atual e autorização operacional**, restaurando `No Auditing` para a subcategoria sem usar `auditpol /clear`.
- `DEPLOYMENT_GATE` da mudança A continua **BLOCKED** por `manager_ingestion` e revisão humana independente, mesmo com a mudança B/4698 validada no escopo declarado.
- Não ativar novas regras ou realizar testes adicionais sem autorização específica.

## Aceite e roadmap

O item **“Aprovar, executar e validar a mudança 4698 (ainda não aplicada), somente após avaliar retenção e confirmar ingestão Wazuh”** foi cumprido para o **escopo autorizado e documentado**, com evento nativo e documento indexado de identidade correspondente. **M1: 15/17 (88,2%)** após registro desse resultado; pendem a correlação real completa das três hipóteses H01/H02/H03 e o encerramento com revisão independente. O M1 não é um score de segurança.

O ambiente permanece privado; publicação à internet exige arquitetura separada e análise de perímetro, conforme [plano da vitrine SOC](m1-secure-public-showcase-plan-20261105.md).

**Referências:** [Change control original](m1-change-control-4698-fim-agent004.md) · [Risco dos coletores Security](m1-inventory-security-overlap-fim004-closure-20261105.md) · [Issue #15](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15) · [M1 Issue #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9) · [PR #25](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/25).
