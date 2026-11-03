# M1 — segunda verificação de fontes nativas Windows (03/11/2026)

**Modalidade:** observação autorizada e **somente leitura** dos canais nativos da VM Windows Server. **Não foram gerados eventos de teste, alteradas políticas de auditoria ou reiniciados serviços.** A coleta não conclui nenhuma hipótese como incidente.

## Janela e procedência

- **Início UTC:** `2026-11-02T00:00:00Z`
- **Fim de filtro UTC:** `2026-11-04T00:00:00Z` (limite superior futuro; o relatório reflete **somente o que existia na hora da consulta, 03/11 por volta de 20h25–20h26 BRT**)
- **Origem:** `Get-WinEvent` em `Security` e `Microsoft-Windows-Sysmon/Operational` **dentro da VM autorizada**, com conversão de UTC para hora local. Cada tipo teve limite de **2.000 registros** na contagem. `auditpol /get` verificou a subcategoria sem modificá-la.
- **Privacidade e integridade:** o compartilhamento VirtualBox estava **protegido contra escrita** na VM, então os relatórios novos `.csv/.txt` **não foram salvos**. Reexecutei as consultas de maneira que retornassem **apenas contagens no console**, com capturas restritas à pasta `.lab/` privada do computador. Nenhum SID, usuário, hostname, endereço, logon ID ou evento bruto foi exportado ao repositório. Resultados abaixo são **transcrição das capturas da tela**, não arquivos de telemetria preservados em formato estruturado.

## Fontes observadas nesta janela

| Canal | ID | Contagem observada | Estado |
| --- | --- | ---: | --- |
| Windows Security | **4698** — tarefa criada | **0** | `no_matches` |
| Windows Security | **4720** — conta criada | **0** | `no_matches` |
| Windows Security | **4672** — privilégios especiais no logon | **289** | `ok` |
| Windows Security | **4624** — logon bem-sucedido | **295** | `ok` |
| Sysmon/Operational | **1** — criação de processo | **≥2.000** | `capped_at_2000` — limite da consulta, total exato desconhecido |

A subcategoria **Audit Other Object Access Events** continuava em **`No Auditing`**. Portanto, o `4698=0` **não prova ausência de criação de tarefas**; o trabalho da [Issue #15](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15) continua pendente de autorização.

## H02 — conta criada e logon privilegiado

Uma segunda consulta privada, ainda somente leitura, buscou `4720` e procurou associações com `4624` e `4672` da **mesma identidade de conta, no máximo 30 minutos** após a criação, sem mostrar SIDs/usuários ou identificadores de sessão.

| Medida H02 | Valor no recorte |
| --- | ---: |
| `account_created_events` | **0** |
| `account_events_with_target_sid` | **0** |
| `privileged_logons_same_sid_30m` | **0** |
| `successful_logons_same_sid_30m` | **0** |
| `matching_4624_4672_logon_id_chains` | **0** |

**Interpretação:** **nenhum par H02 foi observado neste recorte** porque não houve um `4720` disponível para iniciar a correlação. **Não inferir** que nenhum usuário novo existe, nem correlacionar os 289 eventos `4672` genericamente com alguma conta. A revisão anterior de 02/11 (janela diferente) encontrou um `4720` histórico; os recortes **não são intercambiáveis**.

## H03 — FIM e execução do mesmo artefato

A fonte **Sysmon 1** está presente e atingiu o teto de leitura (≥2.000 eventos). **Isso não demonstra nenhum par com FIM**. A interface Wazuh Dashboard exibiu `Wazuh dashboard server is not ready yet` quando se tentou abrir o Discover, apesar de os contêineres retornarem `Running` e os endpoints HTTP responderem. **Nenhuma consulta nova conclusiva de FIM ao Indexer/Discover foi realizada nesta rodada.**

A verificação adicional pretendida do Manager para agregados FIM **não pôde ser executada pelo canal disponível**. Não usar essa falha como evidência de zero alertas. Os 102 alertas FIM históricos do agente `004` permanecem uma observação de **outra janela** (revisão de 02/11). Ainda precisamos do **mesmo arquivo** em alerta FIM e em Sysmon 1, com ativo, caminho/hash e ordem temporal conferidos pelo operador autorizado.

## Próximos critérios sem mudança operacional

1. **H02:** como a fonte inicial `4720` não foi observada, o estado conservador do motor seria **`insufficient_source_coverage`**, não `no_candidate_in_supplied_sample`; avaliar outras janelas e a completude de retenção se houver motivo operacional, sem fabricar identidade nem incidente.
2. **H03:** recuperar a disponibilidade **funcional** do Dashboard/Discover por rotina autorizada e consultar as contagens e evidências FIM **somente leitura**. Inspecionar arquivo real e evento Sysmon de execução correspondente, com aliases vinculados a evidências originais.
3. **H01:** a auditoria `4698` permanece sem habilitação; qualquer mudança de política segue plano e aprovação próprios.
4. **Controle de mudança FIM:** `DEPLOYMENT_GATE=BLOCKED`; nenhum `agent.conf`, Wazuh, Docker, `auditpol`, agentes ou grupos foram modificados.

O progresso documental do M1 não implica cobertura de dados reais nem aprovação do change control. Ver [hipóteses e lacunas](m1-hunting-source-readiness-20261103.md), [Issue #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9) e [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17).
