# M1 — Discover autenticado: FIM agente 004 em sete dias

**Observação:** 03/11/2026, 22h43–22h44 BRT (relógio do host); data view `wazuh-alerts-*`; intervalo do Discover **Last 7 days**, exibido como 27/10/2026 20:42 até 03/11/2026 20:44 no relógio da VM. As contagens pertencem a janelas móveis próximas, não exatamente idênticas.

## Resultados no Wazuh Discover (somente leitura)

| Filtro DQL | Hits exibidos | Interpretação |
| --- | ---: | --- |
| `agent.id:004 and syscheck.path:* and not syscheck.path:HKEY*` | **0** | Não houve correspondência fora de paths `HKEY*` dentro dos alertas indexados nesse intervalo; requer verificação do mapeamento e da semântica DQL |
| `agent.id:004 and syscheck.path:*` | **488** | Controle positivo: Syscheck do agente Windows `004` está pesquisável no Indexer/Discover |

Nas linhas exibidas pelo controle positivo, `syscheck.path` iniciava com `HKEY_LOCAL_MACHINE`, demonstrando telemetria de Registro. Os **488 alertas não são 488 mudanças de arquivos**, tampouco incidentes distintos. Esta busca cobre **alertas** do padrão `wazuh-alerts-*`; não equivale a toda a telemetria `archives` ou a prova de que o agente não monitora arquivos.

## Conciliação com auditoria privada de 02/11

- Configuração local: `syscheck` habilitado, **seis diretórios existentes**, cinco em modo scheduled, um realtime, 23 regras de Registro, frequência de scan de 43.200 segundos.
- A configuração confirma intenção de cobertura, **não** sucesso de um teste controlado de alteração de arquivo com alerta visível.
- Não há, nesta coleta, prova de correlação de **mesmo arquivo/mesmo endpoint** entre FIM e Sysmon Event ID 1 no máximo 20 minutos depois.

## Condições para prosseguir

1. Verificar em revisão autorizada a correspondência de caminhos de arquivo no `syscheck.path` (mapeamento do Indexer e `rule.groups`), distinguindo *alertas* de eventos arquivados.
2. Se existir evidência real de arquivo, conferir os documentos brutos apenas em armazenamento privado, identificador do agente, caminho/hash, origem, timestamps/fuso, ordem temporal e event ID do Sysmon.
3. Sem evidência de arquivo: revisar política de alerta, varreduras agendadas/realtime e exclusões, sem forçar alterações nem reiniciar serviços.
4. Não aprovar FIM, change `os="^Linux"` ou `4698` sem inventário, revisão independente, rollback e autorização formal.

**Decisão:** `SYSHECK_004_7D_TOTAL=488`; `NON_HKEY_MATCHES_7D=0`; `H03=INCONCLUSIVE`; `DEPLOYMENT_GATE=BLOCKED`. Nenhum teste de ataque nem alteração operacional realizada.
