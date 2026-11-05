# M1 — revisão de tuning, falsos positivos e cobertura MITRE ATT&CK por hipótese (05/11/2026)

> **Atualização posterior em 05/11 — H01:** após a revisão retrospectiva descrita abaixo, uma janela específica foi autorizada e executada: [H01 benigno real no Windows `004`](m1-h01-authorized-real-powershell-task-test-20261105.md), com Sysmon EID1 → Security 4698 do mesmo ator e ativo, **1,34 s** e limpeza comprovada. O `4698` está no Indexer/Discover; o **Sysmon EID1 dessa execução não foi localizado no índice de alertas**, logo H01 ponta a ponta segue incompleto. As observações abaixo sobre `4698` ausente referem-se ao **baseline histórico anterior ao cutover** e não à configuração atual. Sem reclassificar H01 como incidente, sem alterar tuning e sem marcar as três correlações como validadas.

**Entrega:** revisão técnica de H01, H02 e H03 com evidências observadas, critérios negativos e decisões de tuning.  
**Status desta revisão:** **CONCLUÍDA COM LACUNAS OPERACIONAIS EXPLÍCITAS**. Nenhuma hipótese foi promovida a detecção correlacionada validada, nenhum incidente foi declarado, nenhum limiar/regra Wazuh foi alterado e **nenhum falso-positivo percentual foi estimado**.  
**Escopo:** recortes reais anteriormente preservados e revisados (02–05/11), casos FIM benignos autorizados, contrato do correlacionador e controles negativos sintéticos rotulados. Sem novas simulações nem acesso a canais de log restringidos.

## Método de classificação

- **Observado:** registro nativo/documento FIM efetivamente visto no recorte especificado; não extrapolar para outros horários.
- **Controle negativo real:** comparação direta de eventos existentes que **falha em uma condição necessária** (ordem temporal, identidade da conta); isso não equivale a um experimento negativo controlado independente.
- **Controle sintético:** fixtures do correlacionador, úteis para testar lógica, nunca evidência operacional do Wazuh.
- **Potencial falso positivo de correlação:** artefatos/eventos genuínos, mas **associação ou conclusão de ameaça indevida** se faltar contexto. Um evento FIM benigno não é “falso” como telemetria.
- **Tuning revisado:** decisão explícita sobre filtros, identidade, temporização, contexto e resposta; **propostas não implantadas**.
- **ATT&CK mapeado:** técnica plausível para hipótese, **não técnica detectada como comportamento adversário**. Revisão independente e rastreabilidade de fontes ainda exigidas.

## H01 — PowerShell → tarefa agendada criada

| Controle | Evidência e resultado |
| --- | --- |
| Lado A | `110100` (PowerShell) disponível em amostra histórica real; **não comprova, sozinho, persistência** |
| Lado B exigido | **Security 4698**, criação real de tarefa, ainda **sem coleta habilitada** no último baseline (`Audit Other Object Access Events=No Auditing`) |
| Apenas tentativa | Regra `110120` do `schtasks /create` indica **tentativa de comando**, não criação efetiva |
| Controle negativo real de ordenação | `110120` em 01/11 23:19:52.407Z ocorreu **1h02m23s ANTES** de `110100` em 02/11 00:22:15.606Z. A ordem é inversa e o intervalo excede **15 min**; **não formam H01**. Sem identidade do mesmo ator na amostra resumida |
| Status no recorte | **Fonte B insuficiente / H01 não corroborada**, sem descartar comportamento em outras janelas |
| ATT&CK — hipótese, não cobertura validada | [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/) + [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) |
| Tuning decidido | **Manter** janela de 15 minutos, mesmo ativo/ator, ordem PowerShell→`4698`, e exigir confirmação da criação. **Não transformar 110120 em 4698**, nem abrir incidente apenas por comando ou proximidade temporal |
| Falso positivo/controle benigno | Manutenção administrativa pode usar PowerShell/tarefas. Antes de elevar, conferir ator, tarefa real, processo pai, mudança aprovada. **Não cadastrar suppressão genérica** |
| Ação pendente | Mudança `4698` em [Issue #15](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15), com avaliação de log Security circular **20 MiB** e dos dois coletores potencialmente sobrepostos; teste e rollback mediante GO separado |

**Decisão:** `TUNING_REVIEWED_NO_RULE_CHANGE`; `ATTACK_HYPOTHESIS_ONLY`; `CORRELATION_NOT_VERIFIED`.

## H02 — conta local criada → logon privilegiado

| Controle | Evidência e resultado |
| --- | --- |
| Fonte A real | Em janela retrospectiva 31/10–04/11, **1 evento Security 4720** com TargetSid válido |
| Fontes B reais (gerais) | No recorte 31/10–03/11 havia **375 eventos 4672** e **387 eventos 4624**; seus totais não estabelecem identidade com a conta criada |
| Controle negativo real de identidade/janela | **0** `4624` ou `4672` do **mesmo SID** nos 30 minutos seguintes ao `4720`; **0 cadeias** `4624↔4672` correlacionadas por Logon ID naquela investigação |
| Nova janela distinta | Em 02/11–03/11: `4720=0`, `4672=289`, `4624=295`. Não misturar a janela com a anterior nem dizer que todo o laboratório possui 0 criações |
| Status no recorte | **Sem par H02 real verificado**; a amostra retrospectiva falha na junção por SID/Logon ID; outras atividades não são descartadas |
| ATT&CK — hipótese, não cobertura validada | [T1136.001 Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) + [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) **somente se houver abuso demonstrado**, não a partir de `4720` administrativo isolado |
| Tuning decidido | **Manter** janela de 30 min, mesmo ativo, **SID da conta-alvo**, vincular `4624` a `4672` por Logon ID; ausência de vínculo → sem candidato. Nunca agrupar por “usuário administrador” genérico |
| Falso positivo/controle benigno | Provisionamento legítimo de conta/serviço deve ser triado com ticket/autorização; **não suprimir** `4720` nem `4672` globalmente |
| Ação pendente | Normalizar apenas eventos reais com identidade auditável; revisar contexto de provisionamento se novas evidências existirem |

**Decisão:** `TUNING_REVIEWED_SID_JOIN_GUARDRAIL`; `ATTACK_HYPOTHESIS_ONLY`; `NO_MATCH_IN_SCOPED_REAL_SAMPLE`.

## H03 — alteração FIM → execução do MESMO arquivo

| Controle | Evidência e resultado |
| --- | --- |
| Lado A real | Em 05/11, **9 documentos reais FIM**: 3 operações `added/modified/deleted` por agente `002`, `004` e `005`, em arquivos **inertes de prova autorizados**; Indexer/Discover confirmados |
| Lado B necessário | **Sysmon Event ID 1** de execução do **mesmo arquivo e ativo** após a alteração, até 20 minutos. A fonte Sysmon 1 existia (≥2.000 eventos na amostra limitada de 03/11), **mas não foi comprovado par com os arquivos de teste do dia 05/11** |
| Controle benigno real | Os três ciclos FIM de prova têm janela de autorização, artefato descartável, limpeza e contexto de alteração **não maliciosa**. São **detecções verdadeiras de mudança de arquivo, não incidentes nem prova de execução** |
| Controle negativo independente | **Não realizado**: não foi executado um teste negativo próprio de Sysmon/mesmo arquivo. **Não classificar como “negativo validado”** por ausência de prova de B |
| Status no recorte | **FIM comprovado; correlação H03 incompleta**, sem interpretação de execução ausente no universo de logs |
| ATT&CK | **Nenhum mapeamento automático** para a alteração FIM isolada. Técnicas dependem do comportamento de execução comprovado e seu contexto; não reivindicar cobertura adversária pelo teste de arquivo |
| Tuning decidido | **Manter** janela até 20 minutos, mesmo ativo e **caminho normalizado/identidade forte do artefato**, conferir hash quando presente e Sysmon Image/parent. FIM isolado → triagem de integridade, **não H03** |
| Falso positivo/controle benigno | Arquivo temporário legítimo, atualização e rotina autorizada podem produzir FIM; usar mudança aprovada e artefato, nunca suprimir todos os alertas FIM do diretório |
| Ação pendente | Inspecionar **Sysmon 1 do mesmo caminho** por acesso autorizado se houver atividade natural já existente; caso contrário, documentar fonte B ausente no recorte, sem executar binário para “forçar” correlação |

**Decisão:** `TUNING_REVIEWED_OBJECT_IDENTITY_GUARDRAIL`; `ATTACK_NOT_ASSIGNED`; `FIM_REAL_CONFIRMED_H03_CORRELATION_NOT_VERIFIED`.

## Matriz de decisão, tuning e cobertura

| Hipótese | Fonte real observada | Controle negativo real | Risco de FP evitado | Tuning (aplicado?) | Cobertura MITRE |
| --- | --- | --- | --- | --- | --- |
| **H01** | `110120`, `110100` em ordem invertida; `4698` ausente | **Sim, temporal**, sem identidade de ator comprovada | Tentativa `schtasks` ≠ tarefa criada; ordem invertida | Regras de junção **revisadas, não alteradas** | T1059.001/T1053.005 **somente mapeamento hipotético** |
| **H02** | `4720` real e eventos `4624/4672` gerais | **Sim, SID e janela**, 0 matches no recorte | Logon privilegiado de outra conta atribuído à recém-criada | SID/Logon ID **revisados, não alterados** | T1136.001/T1078 **condicional, não validado** |
| **H03** | **9 FIM reais** em 3 agentes; Sysmon 1 disponível em amostra antiga | **Não**, apenas cenário benigno que não demonstra execução | FIM benigno tratado como execução/comprometimento | Mesmo artefato e janela **revisados, não alterados** | **Sem técnica atribuída** |

**Nenhum falso positivo quantitativo foi medido**; os recortes não permitem calcular taxa de FP, sensibilidade, precisão, MTTD ou contagem de incidentes. Não afirmar que há controles negativos reais completos em H03. Não alterar limiares, severidades, filtros Wazuh nem registros/coletores como resultado desta revisão.

## Aceite da entrega de revisão M1

O item **“Revisar tuning, falsos positivos e cobertura ATT&CK com evidência por hipótese”** do `ROADMAP.md` é uma **revisão técnica**, não uma promessa de tuning implantado nem de correlações reais completas. Os três pareceres acima registram **fontes reais, recortes, limites, decisões explícitas de tuning, riscos de falsos positivos, controles disponíveis e mapeamentos ATT&CK honestos**. A análise de H03 conserva uma lacuna de controle negativo independente e a sinaliza como impedimento de validação operacional, não de concluir a revisão.

**Aceite documental delimitado: `REVIEW_COMPLETE_WITH_OPEN_EVIDENCE_GAPS`.** É elegível para marcar **esse item de revisão** como concluído, desde que o progresso continue identificado como **checklist documental**, não índice de segurança nem prontidão de deploy. Permanecem **abertos e distintos**: correlação real completa H01/H02/H03, auditoria `4698`, verificação independente do log Manager, revisão externa do PR e aceite final. O gate estrito permanece bloqueado; o GO do proprietário vale apenas para desenvolvimento offline e leitura autorizada.

### Fontes e proveniência

- [H01 — ordenação retrospectiva real](m1-h01-prior-evidence-review-20261102.md)
- [H02 e H03 — telemetria nativa real](m1-native-windows-wazuh-visibility-review-20261102.md) e [checkpoint mais recente](m1-native-telemetry-checkpoint-20261103.md)
- [FIM real dos três agentes](m1-change-a-three-agent-fim-evidence-20261105.md), [três casos investigados](m1-three-real-fim-investigation-case-studies-20261105.md)
- [Hipóteses e critérios do motor offline](m1-three-hunting-hypotheses.md)
- [Issue #9 — revisão M1](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9)
- MITRE ATT&CK técnicas [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1053.005](https://attack.mitre.org/techniques/T1053/005/), [T1136.001](https://attack.mitre.org/techniques/T1136/001/), [T1078](https://attack.mitre.org/techniques/T1078/).

**Privacidade:** IDs brutos, SIDs, contas, nomes de host, caminhos completos e capturas não são publicados. Este parecer não importa dados brutos do Manager nem modifica a VM ou o Wazuh.
