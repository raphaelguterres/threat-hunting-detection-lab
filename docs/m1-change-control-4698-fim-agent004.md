# M1 — Change control: auditoria Windows 4698 e cobertura FIM do agente 004

**Estado em 02/11/2026:** **pré-verificações e scripts de mudança/rollback preparados**, sem execução de mudanças de política. **Aprovação do operador pendente.** A revisão da configuração FIM é somente leitura.

**Escopo:** VM WindowsServer do laboratório autorizado, agente Wazuh identificado como `004` durante os testes anteriores. **Não se aplica automaticamente a ambientes de produção.** [Controle da mudança — Issue #15](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15).

## 1. Baseline observado remotamente (somente leitura)

| Área | Estado confirmado | Implicação |
| --- | --- | --- |
| Domínio | Servidor não associado a domínio | Reduz probabilidade de uma GPO de domínio sobrescrever política, mas não exclui políticas locais |
| `Audit Other Object Access Events` | **No Auditing** | Security `4698` (tarefa criada) não está sendo coletado por essa subcategoria |
| Canal Security | **Enabled**; limite **20 MB** | Risco de rotação prematura dos eventos se o volume aumentar; avaliar retenção **antes** de habilitar |
| `WazuhSvc` | **Running** | Serviço ativo, mas não comprova que cada evento Security está sendo encaminhado ao Manager |
| FIM `<syscheck>` local | `disabled=no` | Monitoramento FIM habilitado na configuração local |
| Varredura FIM | `frequency=43200` segundos (**12 horas**) | Alterações fora do realtime podem aparecer somente na próxima varredura |
| Diretórios FIM | **6 locais e existentes**: 5 WindowsSystem / 1 OtherLocal | Escopo majoritariamente de áreas do sistema; exige verificação de inclusão do arquivo-alvo da hipótese H03 |
| Modos | **5 programados**, **1 realtime**, **0 whodata** | Apenas um diretório configurado para alterações em tempo real; sem atribuição de quem alterou por whodata |
| Registro Windows | **23 configurações** de `windows_registry` | Não equivalem a 23 chaves individuais; podem abranger escopos |
| Caminhos de rede | **0 UNC** | Compatível com a limitação de suporte UNC do Wazuh moderno |
| Diagnóstico do `ossec.log` | 2.088 linhas do final do log; **5 menções** de FIM/varredura e **0 menções de erro FIM** no filtro aplicado | Evidência apenas da amostra do log, **não** certificação de saúde completa |

**Proveniência:** os dados acima foram extraídos por comandos read-only executados **dentro da VM autorizada**, armazenando apenas contagens e estados em arquivos privados no host: `.lab/m1-change-prep/M1_PRECHECK_PRIVATE.txt`, `.lab/m1-change-prep/M1_FIM_LOCAL_PRIVATE.txt` e `.lab/m1-change-prep/M1_FIM_COVERAGE_PRIVATE.txt`. Arquivos XML, registros e caminhos concretos não foram publicados.

**Evidência complementar:** o [levantamento anterior de visibilidade](m1-native-windows-wazuh-visibility-review-20261102.md) encontrou **102 documentos FIM históricos** do agente 004 no Indexer e **0 documentos FIM na janela 31/10 00:00–03/11 00:00 UTC**, com consulta de controle positiva para regra 110100 nesse mesmo período. Nenhum alerta recente não prova, por si só, falha do FIM: varreduras sem alteração observável podem não gerar alertas.

## 2. Decisão de mudança: habilitar auditoria 4698

**Objetivo defensivo:** coletar Security Event ID **4698**, que registra que uma tarefa agendada foi efetivamente criada, para enriquecer **H01**. A detecção Wazuh `110120` sinaliza a execução de `schtasks.exe /create`, **não** sucesso da criação; o motor M1 mantém esses conceitos separados.

A Microsoft recomenda auditar **Success** na subcategoria **Other Object Access Events** para operações de tarefas agendadas. Isso também produz eventos de criação/remoção/atualização conforme as ações realizadas, de modo que o impacto no canal Security deve ser monitorado. [Referência de auditoria](https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-other-object-access-events), [comando auditpol](https://learn.microsoft.com/pt-br/windows-server/administration/windows-commands/auditpol-set).

### Gate obrigatório antes da aplicação

1. Solicitar **aprovação explícita** para a alteração e definir janela curta com operador disponível, inclusive acesso de rollback.
2. Capturar novo baseline de `auditpol /get /subcategory:"Other Object Access Events"` **imediatamente antes** da mudança; comparar com **No Auditing** observado. Caso tenha divergido, **não aplicar** automaticamente.
3. Verificar privilégios administrativos, políticas locais e eventos `4698` históricos; decidir como garantir retenção com o log Security limitado atualmente a **20 MB**. **Não aumentar o log automaticamente** no mesmo change request sem aprovação.
4. Confirmar que o canal Security é ingerido pelo agente Wazuh (logcollector/canais configurados local ou centralmente). Habilitar auditoria Windows **não implica** indexação automática.
5. Manter somente `Success`; não habilitar `Failure` por padrão e não modificar outros subitens `auditpol`.
6. Usar os arquivos locais privados **somente após a aprovação**. Os scripts estão desenhados para **dry-run por padrão** e requerem argumento reservado mais uma frase de confirmação.

**Comando previsto, não executado nesta revisão:**

```bat
auditpol /set /subcategory:"Other Object Access Events" /success:enable
```

### Aceite técnico após a mudança — ainda pendente

- Conferir `auditpol /get` indicando `Success`; registrar a hora UTC da ativação e o baseline anterior.
- Executar **apenas um teste benigno aprovado** de criação de tarefa descartável, com limpeza validada, em janela de laboratório; **não executar sem aprovação explícita**.
- Confirmar Security `4698` na VM, timestamp e referência ao teste; verificar a chegada do evento ao Wazuh Manager, Indexer e Discover **somente se a regra de coleta e pipeline correspondente suportarem esse evento**.
- Registrar contagem de eventos da subcategoria, crescimento do log Security, possíveis perdas e critérios de parada; **não** publicar dados brutos, nomes de contas, SIDs nem conteúdo de tarefas.
- Tratar falha de `4698` ou ausência de ingestão como **gate não satisfeito**, não produzir evidência alternativa artificial.

### Rollback preparado — não executado

O baseline da subcategoria era **No Auditing**, portanto, **se a mudança ocorrer e o baseline continuar aplicável**, o rollback mais restrito é desabilitar apenas `Success` da **mesma subcategoria**:

```bat
auditpol /set /subcategory:"Other Object Access Events" /success:disable
auditpol /get /subcategory:"Other Object Access Events"
```

Não usar `auditpol /clear`, `auditpol /restore` geral ou alterações de GPO como rollback improvisado. Se a política mudar por outra fonte durante a janela, interromper e reavaliar antes de aplicar o rollback. Os scripts privados exigem confirmação explícita e a presença do baseline `No Auditing`.

**Gatilhos de rollback:** crescimento inesperado do Security, comportamento não previsto da auditoria, falha em confirmar `4698`, conflito com política vigente ou perda de visibilidade devido à retenção.

## 3. Revisão FIM 004: decisão de cobertura antes de H03

A leitura do arquivo local `C:\Program Files (x86)\ossec-agent\ossec.conf` é **preliminar**, não uma prova da configuração **efetiva**, pois configurações centralizadas em `agent.conf` podem ter precedência. [Documentação Wazuh](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/how-to-configure-fim.html).

Ações read-only para completar a revisão:

- Comparar configuração local e distribuição centralizada efetiva do agente **004** no Manager (acesso autorizado, sem leitura/publicação de segredos).
- Validar **dentro da VM** se o artefato-alvo de H03 é coberto por um dos diretórios monitorados e se o caminho é real, acessível e local; não inferir cobertura a partir de seis entradas genéricas.
- Conferir se o diretório relevante está em `realtime=yes` ou somente em varredura de 12h. **Não mudar frequência, realtime ou whodata** sem nova avaliação de carga/impacto.
- Em futuros testes aprovados, registrar baseline, varredura/mudança e, se houver alteração, ID e UTC no FIM do Manager e Indexer antes de relacionar com Sysmon Event ID 1 do **mesmo artefato**.
- Manter sem mudança o agente Wazuh se a cobertura for suficiente; casos sem correspondência permanecem **inconclusivos**.

### Checkpoint e responsabilidade

**Pronto:** inventário read-only, verificação de paths existentes, riscos levantados, script de ativação com proteção e script de rollback preparados **somente no host**. **Pendente:** aprovação humana, aplicação da auditoria, teste de criação real de tarefa, confirmação de ingestão Wazuh, inspeção de `agent.conf` efetivo e eventual validação de H03.

**Status:** a [Issue #15](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15) permanece aberta até essas decisões; M1 [Issue #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9) não está concluído.
