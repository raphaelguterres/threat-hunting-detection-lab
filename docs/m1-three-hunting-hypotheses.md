# M1 — Três hipóteses de Threat Hunting com correlação offline

**Início:** 02/11/2026. **Estado:** especificação e validação sintética; triagem de novos eventos reais **não executada**. Este incremento não comprova novos incidentes nem classifica as três hipóteses como detecções implantadas.

O laboratório já contém cinco estudos de caso históricos, Sysmon IDs 1, 3 e 11, auditoria Windows e FIM Linux/Windows. Este M1 cria hipóteses **adicionais**, em vez de renomear os estudos antigos.

## Atualização read-only do ambiente — 02/11/2026

A [auditoria de visibilidade do Windows Server e Wazuh FIM](m1-native-windows-wazuh-visibility-review-20261102.md) encontrou **0 eventos Security 4698** e `Other Object Access Events = No Auditing`, **1 evento 4720** sem logons `4624/4672` associados ao mesmo SID nos 30 minutos seguintes e **0 documentos FIM do agente 004** na janela recente, embora existam **102 documentos FIM históricos** desse agente. Esses são **limites do recorte e da instrumentação**: não permitem confirmar nem descartar integralmente H01/H02/H03.

## Modelo de entrada: registros normalizados e pseudonimizados

O correlacionador em [scripts/hunt_correlations.py](../scripts/hunt_correlations.py) executa **somente operações offline**, sem acessar VMs ou consultar Wazuh. O analista precisa normalizar fielmente cada evento e fornecer **exatamente sete campos**:

| Campo | Significado |
| --- | --- |
| **timestamp** | ISO 8601 com UTC ou fuso explícito; comparado após normalização para UTC |
| **kind** | Categoria observada: powershell_process, task_created, account_created, privileged_logon, file_change ou file_execution |
| **source** | Tipo de evento original permitido para a categoria; validado pelo programa |
| **event_ref** | Referência única à evidência, preservada privadamente e nunca impressa |
| **asset_key** | Alias estável do ativo, nunca hostname real |
| **actor_key** | Alias estável do usuário/ator, sem nomes reais |
| **object_key** | Alias estável do objeto envolvido, como conta ou arquivo |

**Atenção:** nenhuma categoria pode ser inferida só porque uma regra Wazuh gerou um alerta. A regra 110140 do Detection Engineering identifica uma **tentativa/comando de conta**, e não comprova que a conta foi criada. Nesta versão, account_created exige um evento de auditoria Windows 4720 verificado.

## H01 — PowerShell seguido de criação de tarefa

**Hipótese:** um processo PowerShell seguido de tarefa agendada no mesmo ativo/ator pode merecer investigação de persistência se a mudança não for autorizada.

- **Etapa A:** powershell_process, evidência Sysmon ID 1 ou regra customizada 110100 confirmada.
- **Etapa B:** task_created, evidência de evento Security 4698 ou regra 110120 **somente quando o conteúdo confirmar criação efetiva**.
- **Junção:** mesmo asset_key e actor_key; A deve ocorrer antes de B, no máximo **15 minutos**.
- **Contexto que falta a analisar:** comando, processo pai, relação entre processos, ação agendada, usuário, ticket de manutenção.
- **Controles negativos:** ator ou host diferente, tarefa anterior ao PowerShell, janela vencida, tarefa administrativa aprovada.
- **MITRE como hipótese:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/) + [T1053.005](https://attack.mitre.org/techniques/T1053/005/).
- **Estado:** planejada para revisão de telemetria real; correlacionador testado apenas sinteticamente.

**Limite:** proximidade de eventos não prova relação causal nem intenção maliciosa.

### Revisão retrospectiva H01 — 02/11/2026

Já foi analisada uma amostra **real delimitada** de seis identidades de alertas do laboratório, guardada privadamente no projeto irmão. O evento da regra **110120 (schtasks)** ocorreu **1h02min23s antes** do alerta **110100 (PowerShell)**. Portanto **não corresponde** à sequência PowerShell → tarefa de H01, nem à janela de 15 minutos.

Isso é somente a **avaliação temporal de dois registros**; não significa que a hipótese esteja descartada no ambiente, nem confirma criação da tarefa ou correspondência de usuário. A auditoria é reproduzível em modo read-only e sem divulgar IDs. Veja o [relatório retrospectivo sanitizado](m1-h01-prior-evidence-review-20261102.md).

## H02 — Criação de conta local seguida de sessão privilegiada

**Hipótese:** uma conta recém-criada que aparece em logon com privilégios deve ser triada quanto a aprovação, origem e contexto.

- **Etapa A:** account_created, evento de auditoria Security 4720 **validado**.
- **Etapa B:** privileged_logon, Security 4672; confirmar vínculo ao 4624 e Logon ID antes de uma conclusão.
- **Junção:** mesmo asset_key e **object_key da conta-alvo**, A anterior a B em até **30 minutos**.
- **Controles negativos:** outra conta, outro host, prazo excedido, provisionamento autorizado de serviço.
- **MITRE condicional:** [T1136.001](https://attack.mitre.org/techniques/T1136/001/) e [T1078](https://attack.mitre.org/techniques/T1078/).
- **Estado:** hipótese não validada em eventos reais deste incremento.

**Limite:** eventos 4672 e 4720 isolados não comprovam uso indevido de credenciais.

## H03 — Mudança de arquivo monitorado seguida da sua execução

**Hipótese:** alteração FIM de um artefato e execução posterior desse **mesmo artefato** podem justificar uma investigação de integridade.

- **Etapa A:** file_change, telemetria Wazuh FIM com horário, caminho e hash.
- **Etapa B:** file_execution, Sysmon ID 1 com imagem correspondente ao mesmo artefato.
- **Junção:** mesmo asset_key e **object_key estável do arquivo**, em até **20 minutos**, na ordem correta.
- **Controles negativos:** arquivo distinto com nome parecido, host diferente, execução anterior à modificação, atualização legítima.
- **MITRE:** sem técnica atribuída automaticamente; mapear após confirmação do comportamento.
- **Estado:** hipótese não validada em eventos reais deste incremento.

**Limite:** registro FIM e processo no mesmo host não provam vínculo sem confrontar imagem, caminho e hash.

## Reproduzir o motor offline

Na raiz do repositório, executar:

    python scripts/hunt_correlations.py --input tests/fixtures/m1-synthetic.jsonl --fixture

Os **12 registros de fixture são explicitamente sintéticos**. Saída agregada esperada:
- H01_POWERSHELL_TASK: **1 par candidato**
- H02_ACCOUNT_PRIVILEGE: **1 par candidato**
- H03_FIM_EXECUTION: **1 par candidato**

Há também controles com atores/objetos incompatíveis, que não podem se juntar aos pares positivos. A saída contém **quantidades, status e proveniência da amostra**, sem IDs ou nomes de ativos.

Para uma fase **posterior**, um analista pode gerar um JSONL normalizado **privado**, com validação de procedência da telemetria, em um arquivo sob a pasta .lab (ignorada pelo Git) e executar:

    python scripts/hunt_correlations.py

O programa rejeita arquivo fora de .lab (exceto fixture declarada), campos inesperados, fontes incompatíveis, timestamps sem fuso e referências de evento duplicadas; limite de 1 MiB/1000 registros. **Nenhum candidato é classificado automaticamente como incidente.**

## Aceitação para investigações reais de M1 (ainda pendente)

1. Abrir o evento autorizado no Wazuh/Windows e confirmar a fonte, os campos e o contexto sem modificar serviço ou gerar novas simulações desnecessárias.
2. Normalizar os campos em pasta privada com pseudônimos consistentes. **Nunca criar chaves por suposição** nem usar apenas contagens coincidentes.
3. Executar o correlacionador e conferir manualmente **cada par** contra a telemetria original. Sem original, o resultado é *inconclusivo*.
4. Documentar também os controles negativos, alternativas benignas, horários, origem, lacunas, falsos positivos e aprovação de mudanças.
5. Publicar somente evidência sanitizada com classificação clara: **verified, partial, inconclusive, not_tested**.
6. Somente então atualizar cobertura ATT&CK e concluir M1. CI sintético **não** equivale a hunting realizado sobre eventos reais.

### Modelo de registro

| Campo | Preencher durante o caso |
| --- | --- |
| Hipótese, período e ativo (alias) | |
| Fonte original e referência privada | |
| Evidência A e B, normalização de fuso | |
| Critério de junção e prova de identidade | |
| Alternativas benignas e mudança aprovada | |
| Controle negativo | |
| Decisão, confiança e motivo | |
| Falsos positivos, lacunas e próxima ação | |

Referências: [matriz de telemetria](telemetry-matrix.md), [cobertura ATT&CK](mitre-coverage.md), [registro de falsos positivos](false-positive-register.md), [modelo de investigação](registro-de-investigacao.md), [MITRE ATT&CK](https://attack.mitre.org/), [Microsoft Security Event 4698](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698), [4720](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720) e [4672](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672).
