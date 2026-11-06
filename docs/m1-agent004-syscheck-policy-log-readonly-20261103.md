# M1 — agente 004: mapeamento, política de alertas e registros de varredura

**Checkpoint:** 03/11/2026 ~22h49–22h57 BRT. Auditoria **somente leitura**, com console administrativo já aberto na VM Windows Server e interface autenticada do Wazuh Discover no Kali. Nenhum serviço reiniciado, arquivo de configuração editado, alteração de auditoria aplicada ou evento FIM gerado.

## 1. `syscheck.path` e Indexer

- Data view `wazuh-alerts-*`, Discover autenticado: `agent.id:004 and syscheck.path:*` retornou **488 hits** em *Last 7 days*; os documentos exibidos tinham `syscheck.path` iniciado por `HKEY_LOCAL_MACHINE` (Registro do Windows).
- No mesmo período, `agent.id:004 and syscheck.path:* and not syscheck.path:HKEY*` retornou **0 hits**; contagens em janelas móveis adjacentes.
- Isso valida **presença e capacidade de pesquisa do campo** nos alertas visualizados. O tipo exato foi **confirmado posteriormente** no índice de 03/11 como `keyword` pela API de mapping (veja atualização cronológica abaixo). A equivalência do filtro de negação DQL com uma consulta DSL agregada ainda não foi verificada.
- `wazuh-alerts-*` contém somente alertas gerados pelo Manager, **não** todos os registros internos de arquivo/arquivamento. Zero hits não autoriza a conclusão de que não existem arquivos monitorados.

**Revisão visual adicional em 03/11 ~23h12 BRT (Index Management → índice do dia 03/11 → Mappings → JSON Editor):** o JSON apresentado continha `dynamic_templates` com a regra `string_as_keyword` (`match_mapping_type: string`, mapping `type: keyword`), `date_detection: false` e `properties: {}`. **Não havia declaração explícita de `syscheck.path` no conteúdo visível.** Isso apoia a hipótese de indexação dinâmica como `keyword`, mas **não prova o field mapping efetivo de `syscheck.path`** nem equivalência de wildcard/negação DQL. Nenhuma ação de salvar/aplicar mapeamento foi executada.

**Conferência adicional em 03/11 ~23h15–23h18 BRT:** o botão `See previous mappings` abriu o **mapeamento anterior efetivamente exibido no Index Management**. Diferentemente do JSON Editor principal, a visualização anterior incluía propriedades materializadas, entre elas `@timestamp` (`date`), `@version` (`text`) e campos estruturados (`GeoLocation`, `gcp`). **A seção específica `syscheck.path` não foi localizada nem teve seu tipo identificado** nesta revisão visual. A tentativa seguinte de navegação foi bloqueada pelo controle de segurança remoto; a inspeção foi interrompida sem contornar o bloqueio. Não usar o template `string_as_keyword` como prova do tipo do campo real.

**Confirmação definitiva do tipo do campo para o índice de 03/11, ~23h25 BRT:** Dev Tools do Wazuh Indexer executou exclusivamente `GET wazuh-alerts-4.x-2026.11.03/_mapping/field/syscheck.path`. Resposta HTTP **200 OK**: o objeto `syscheck.path` exibe `full_name: "syscheck.path"` e `mapping.path.type: "keyword"`. Portanto **`syscheck.path` é `keyword` nesse índice**, não uma dedução baseada em `dynamic_templates`. A investigação de outros índices/dias e a comparação com artefatos arquivados continuam pendentes. Não houve operação de escrita no Indexer.

## 2. Configuração e política de alertas

Consulta XML **direta e atual** na VM Windows Server, `ossec.conf` local, sem exibir conteúdo privado:

| Item | Valor lido |
| --- | --- |
| `syscheck.disabled` | `no` |
| `syscheck.frequency` | `43200` segundos |
| `syscheck.directories` | 6 diretivas |
| `syscheck.ignore` | 2 nós |
| `syscheck.scan_on_start` | ausente no XML local |
| `syscheck.alert_new_files` | ausente no XML local |
| `syscheck.auto_ignore` | ausente no XML local |

A auditoria privada anterior verificou 6 caminhos locais existentes, sendo 5 agendados e 1 realtime; 23 diretivas de Registro. No grupo central `default`, há um bloco sem escopo OS com diretiva FIM UnixStyle inexistente no Windows. Configuração central e local podem ter precedência relevante; **cobertura efetiva não está demonstrada**. A ausência de opções explícitas exige consideração dos defaults por versão, não representa status `no`.

**Rechecagem da VM às 23h05 BRT:** a inspeção direta das seis diretivas confirmou 5 entradas sem `realtime=yes` e 1 com `realtime=yes`. Uma tentativa adicional de classificar as duas exclusões não foi concluída; não foi avaliado o texto dos padrões de exclusão. Não tratar a checagem parcial como validação da política efetiva.

**Verificação autenticada do Manager às ~23h22 BRT, Server Management → Settings → Alerts → General:** nível mínimo para armazenar alertas = **3**; nível mínimo para envio por e-mail = **12**; GeoIP = **no**. São valores mostrados pela interface e não uma autorização para editar as opções.

**Ainda não verificados no Manager:** `jsonout_output`, `auto_ignore` efetivo, regras FIM aplicáveis com seus respectivos níveis, e outras possíveis etapas de filtragem no pipeline. Eventos correspondentes a regras abaixo do limite de armazenamento podem não aparecer em `wazuh-alerts-*`; isso é uma hipótese a testar por evidência, não a explicação confirmada para os zero alertas de arquivo.

## 3. Registro do agente e varreduras

Leitura direta do `ossec.log` atual na VM Windows Server:

- `WazuhSvc`: **Running** no instante da consulta.
- Arquivo `ossec.log` presente, aproximadamente 48,8 KB, **377 linhas**, entradas datadas de 03/11/2026 (relógio da VM).
- **0** linhas contendo `syscheck` ou `fim` no log atual; por consequência, **0** matches do filtro de menções a `scan|sync|start|end` combinado com esses nomes.
- A amostra privada de **02/11/2026** tinha 2.088 linhas e 5 matches de um filtro textual genérico relacionado a FIM/scan; esses matches **não eram cinco confirmações de varredura completa**.
- O arquivo atual não prova uma varredura bem-sucedida **nem prova ausência de varredura**: verificar nível de log, rotação/retenção e horários em fonte autorizada. Fuso do Windows Server, Kali e host não foi normalizado nesta etapa.

## Decisão e próximos gates

1. Inspecionar com autorização de leitura o mapping real `syscheck.path`/`.keyword` e as regras de FIM efetivamente carregadas, sem editar configurações.
2. Confirmar `log_alert_level` e pipeline Manager → `alerts.json` → Indexer; distinguir ausência de mudanças de ausência de alertas e de logs de varredura.
3. Reconciliar horários da VM, scans agendados e possíveis fontes arquivadas sem gerar alterações artificiais.
4. Requerer evidência real de **arquivo alterado e mesmo artefato executado** (Sysmon 1, mesmo host, até 20 minutos) antes de aceitar H03.
5. `DEPLOYMENT_GATE=BLOCKED`: sem alteração de `default/agent.conf`, `os="^Linux"`, 4698, regras, contêineres ou serviços até aprovação.

## Referências oficiais

- https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html
- https://documentation.wazuh.com/current/user-manual/manager/alert-management.html
- https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html
- https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/how-to-configure-fim.html

**Estado:** `MAPPING_FIELD_PRESENT=YES`; `EXACT_MAPPING_TYPE_20261103=keyword`; `FIM_LOCAL_ENABLED=YES`; `AGENT_SERVICE_RUNNING=YES`; `CURRENT_LOG_FIM_MENTIONS=0`; `SCAN_COMPLETION=UNVERIFIED`; `H03=INCONCLUSIVE`; `DEPLOYMENT_GATE=BLOCKED`.
