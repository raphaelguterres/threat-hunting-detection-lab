# H01 — tentativa de janela de validação com comando codificado, interrompida (05/11/2026)

**Estado:** `H01_ACTIVE_TEST=NOT_EXECUTED_TOOL_SECURITY_BLOCK`  
**Janela solicitada pelo proprietário:** **05/11/2026, 16h49–17h19 BRT**. O proprietário confirmou explicitamente que autorizava continuar o plano de um único ensaio benigno.  
**Resultado:** a solicitação de preparação do roteiro remoto foi **bloqueada pelas configurações de segurança da ferramenta**. Não houve autorização efetiva da ferramenta para criar o arquivo, e **não foi tentada execução por canal alternativo**.

## Fatos comprovados nesta retomada

- O computador remoto autorizado estava conectado, com as VMs `WindowsServer` e Kali em estado `running`.
- O último estado do laboratório antes da janela permanece documentado: auditoria Security `4698` habilitada; tarefa benigna da janela anterior removida; coletor Sysmon/Operational presente.
- A regra-base `61603` (Sysmon Event ID 1) tem **nível 0**, inferior a `log_alert_level=3`, e a regra customizada `110100` (nível 12) exige `-enc` ou `-EncodedCommand`. O último teste benigno aprovado tinha usado `-File`. [Diagnóstico](m1-h01-active-rule-scope-diagnosis-20261105.md).
- A tentativa de preparação do **novo** script foi bloqueada **antes de qualquer criação/execução confirmada**; não foi gerado um novo `110100`, um novo `4698` nem um novo teste de correlação nesta retomada.
- **Nenhuma regra, configuração, auditoria Windows, Wazuh, VM, tarefa agendada ou rede foi alterada** para contornar o bloqueio.

## Status de evidência após o bloqueio

| Critério | Estado |
| --- | --- |
| Diagnóstico do motivo do não-alerta anterior | **Concluído** pela inspeção autorizada das regras |
| Contratos offline `110100` | **11 testes de regressão PASS** na entrega anterior, sem novo teste ativo |
| Teste benigno `-EncodedCommand` nesta janela | **NÃO EXECUTADO — ferramenta bloqueou preparação** |
| Novo alerta Wazuh `110100` | **NÃO VERIFICADO** |
| Novo Security `4698` da mesma execução | **NÃO GERADO** |
| Correlação real H01 completa no Indexer/Discover | **INCOMPLETA** |
| H02 e H03 completas em dados reais | **INCOMPLETAS** |
| M1 (critério de entrega, não score de segurança) | **15/17 — 88,2%** |
| Aceite final e revisão independente | **PENDENTES** |

## Encaminhamento seguro

Respeitar o bloqueio da ferramenta e **não repetir a ação com outro mecanismo de automação** para fugir ao controle. A revisão do escopo da regra já fornece o resultado técnico útil: a ausência do Sysmon `173036` no `wazuh-alerts-*` era compatível com o filtro da `110100`, pois `-File` não corresponde à regra.

Para continuar o projeto sem executar ações bloqueadas, usar dados históricos previamente autorizados, testes offline/sintéticos rotulados e documentação. A validação operacional por nova sequência real **não deve ser marcada como concluída** sem coleta verificada das fontes, autorização e execução permitida pelas políticas de acesso. Preservar o rollback da mudança `4698` e manter o PR aberto até aprovação independente.

**Referências:** [diagnóstico H01](m1-h01-active-rule-scope-diagnosis-20261105.md) · [teste H01 anterior](m1-h01-authorized-real-powershell-task-test-20261105.md) · [roadmap](../ROADMAP.md) · [PR #25](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/25).

**Proveniência:** registro documental de tentativa bloqueada, **não** evidência de alerta operacional. Não foram publicadas credenciais, capturas, dados de eventos brutos nem arquivos privados.
