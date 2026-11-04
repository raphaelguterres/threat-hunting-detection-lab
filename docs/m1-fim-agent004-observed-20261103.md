# M1 — FIM do agente 004: revisão visual autenticada

**Data:** 03/11/2026, por volta de 21h53–21h54 BRT. **Origem:** Discover autenticado no Kali, data view `wazuh-alerts-*`. **Recorte:** `Last 24 hours`, uma janela móvel medida pelo relógio da interface. Somente leitura e contagens visuais, sem exportação de documentos.

## Resultados observados

| Consulta DQL aplicada | Hits na interface | Interpretação restrita |
| --- | ---: | --- |
| `agent.id:"004" and syscheck.path:*` | **488** | Eventos Syscheck/FIM indexados para o agente 004 na janela móvel |
| `agent.id:004 and syscheck.path:* and not syscheck.value_type:*` | **126** | Registros sem `value_type`; **não** são automaticamente arquivos, pois amostra visível exibia caminho `HKEY_LOCAL_MACHINE` |
| `agent.id:004 and syscheck.path:* and not syscheck.path:HKEY*` | **0** | Nenhum registro fora de caminhos com prefixo `HKEY` foi encontrado por este filtro nesta janela; interpretar com cautela e confirmar semântica/mapeamento do campo |

Amostras visuais incluíram caminhos sob o Registro do Windows (não publicar dados brutos nem valores privados). Esses resultados **não** constituem prova de monitoramento ou execução do mesmo arquivo para a hipótese H03, e não autorizam a mudança FIM. A contagem principal confirma telemetria do agente indexada e consultável; os filtros adicionais servem para qualificar sua natureza.

## Pendências

- Verificar janela histórica de sete dias e, se necessário, um intervalo UTC absoluto, mantendo recortes separados.
- Revisar o mapeamento de `syscheck.path` e as diferenças entre eventos de registro e integridade de arquivo; pesquisar eventos Windows com caminhos de arquivo usando filtro compatível com DQL.
- Para H03, confirmar um **evento FIM de arquivo**, e correlacionar com **Sysmon 1 para o mesmo artefato e host**, em ordem temporal de até vinte minutos; revisar explicação benigna e integridade da evidência privada.
- A tentativa de continuar a operação gráfica remota foi bloqueada por um controle de segurança; interromper esse caminho, sem contornar o bloqueio.

**Status:** `DISCOVER_UI=AVAILABLE`; `SYSHECK_004_24H=488`; `H03=INCONCLUSIVE`; `DEPLOYMENT_GATE=BLOCKED`. Sem reinicialização de contêineres, geração de eventos ou alteração ativa.
