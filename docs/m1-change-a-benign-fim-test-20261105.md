# M1 — teste FIM benigno autorizado após mudança A (05/11/2026)

## Atualização: evidência no Indexer/Discover após o teste (05/11, ~13h49 BRT)

A sessão Wazuh foi desbloqueada pelo operador. No **Discover**, data view `wazuh-alerts-*`, a pesquisa DQL `agent.id: 002 and syscheck.path: *` na janela `Last 24 hours` retornou **3 documentos de FIM**, todos com o mesmo `syscheck.path` do arquivo descartável do teste `002`, agente `002` e campo de origem `manager.name`.

| Evento FIM observado | Horário exibido no Discover | Correspondência com ação no host |
| --- | --- | --- |
| `added` | 11:22:50.977 | criação 13:22:29 BRT |
| `modified` | 11:22:58.379 | modificação 13:22:36 BRT |
| `deleted` | 11:23:05.711 | exclusão 13:22:43 BRT |

Os horários do Dashboard usam apresentação diferente do host BRT (deslocamento de aproximadamente 2 horas) e o relógio do guest já apresentava deriva de cerca de **22 segundos**. A sequência, identidade do agente e artefato de teste correspondem; **a configuração de horário e a deriva não foram alteradas**. Captura e correlação detalhada são **privadas em `.lab/`**, sem publicar IDs internos, hostname ou caminho completo.

**Aceitação delimitada:** `AGENT_002_FIM_INDEXER=CONFIRMED`; `AGENT_002_FIM_DISCOVER=CONFIRMED`, com **3 ocorrências reais**. O campo `manager.name` identifica o processamento esperado, mas **não substitui a inspeção independente dos alertas locais do Manager**: `MANAGER_DIRECT_LOG=NOT_VERIFIED`. O teste FIM do `005` e uma prova nova de FIM no Windows `004` continuam pendentes. O gate global mantém `DEPLOYMENT_GATE=BLOCKED` e o M1 **11/17**.

**Janela encerrada às 13h48min53s BRT:** nenhuma nova alteração de arquivo ou teste ativo é autorizada por esta janela. Continuar em modo somente leitura até existir nova autorização específica, com rollback da mudança A preservado.

**Situação:** teste de arquivo descartável **concluído no agente Linux 002**, sem comprovação ainda de alertas ponta a ponta. **Agente Linux 005 não testado** por falta de permissão de escrita aprovada no diretório monitorado. **Mudança A não aceita operacionalmente** apenas por este teste.

## Autorização e delimitação

- Proprietário autorizou expressamente, nesta conversa, um teste FIM benigno **somente nos agentes 002 e 005**, criando, modificando e removendo **um arquivo descartável por agente** no diretório isolado previamente monitorado.
- Janela registrada: **05/11/2026, 13h18min53s–13h48min53s BRT** (30 minutos). Não há autorização para alterações em regras, grupos, auditoria 4698, H03, serviços, credenciais ou arquivos preexistentes.
- Controles de segurança: arquivo com identificador aleatório e prefixo de laboratório; verificação de diretório válido, não symlink, permissões, ausência prévia de arquivo e agente ativo/sincronizado; comando limitado ao contêiner do agente 002; exclusão do único arquivo descartável e verificação posterior.
- **Sem bypass de permissões**: o caminho do agente nativo 005 é pertencente ao root, inacessível para escrita à conta remota. O teste do 005 foi **não executado**, sem utilizar contêiner, usuário alternativo ou outra técnica para contornar essa limitação.

## Execução real — agente 002

| Evento do teste | Hora local (BRT) | Resultado |
| --- | --- | --- |
| Criar novo arquivo benigno no diretório isolado | 13h22min29s | **PASS** |
| Modificar arquivo (truncar/preencher 64 bytes) | 13h22min36s | **PASS** |
| Excluir somente o arquivo descartável | 13h22min43s | **PASS** |
| Conferir ausência do arquivo após a limpeza | pós-execução | **PASS** |
| Confirmar agentes 002/004/005 ainda ativos | pós-execução | **3/3 active** |
| Conferir hash da configuração A ativa | pós-execução | **PASS** |
| Comprovar criação/modificação/exclusão no Manager | — | **NÃO VERIFICADO** |
| Comprovar mesmo evento no Indexer e Discover | — | **NÃO VERIFICADO** |

A execução retornou **exit 0**. Cada operação foi espaçada por aproximadamente 7 segundos, sem manipulação de processos Wazuh ou reinício. O arquivo de teste **não permanece no ambiente**.

O teste pode, ou não, ter produzido alertas FIM. A execução local do arquivo **não autoriza** declarar detecção bem-sucedida nem falha de coleta. A inspeção de alertas brutos via acesso remoto havia sido restringida pelas ferramentas e **não foi contornada**. O console gráfico Kali estava **bloqueado por sessão de usuário** quando foi tentada a inspeção do Dashboard; **não houve desbloqueio indevido**.

## Evidências e limites

- Roteiro PowerShell e JSON de execução privados, incluindo nome, caminho e identificador completos do artefato de teste, em `.lab/`; **não publicar** esses arquivos.
- Capturas da tela da VM permanecem privadas; a observação de sessão bloqueada não significa que Wazuh Manager/Indexer estejam indisponíveis.
- O backup original DPAPI e o rollback no Manager permanecem preservados.
- Não foram testados o Windows `004` nem a auditoria `4698` ou a hipótese H03.
- Não promover os campos `windows_fim`, `linux_fim`, `manager_ingestion`, `indexer_ingestion`, `discover_visibility` para `verified` sem evidências reais.

## Próximo passo

1. Operador autorizado desbloqueia a sessão Kali/Dashboard com suas próprias credenciais. A automação **não** deve pedir senha no chat nem alterar controles de tela de bloqueio.
2. No Wazuh **Discover**, selecionar `wazuh-alerts-*`, delimitar janela **após 13h22 BRT de 05/11/2026** e filtrar `agent.id: 002` + `syscheck.path:*`, com tolerância para o desvio observado de ~22s. Conferir criação, modificação e remoção do artefato de teste por identidade, sem publicar seu nome/caminho.
3. Somente em caminho de acesso expressamente autorizado, correlacionar identificador da ocorrência e timestamps no **Manager → Indexer → Discover**. **Contagens históricas, simples presença de FIM na UI ou testes unitários não constituem prova do mesmo evento pós-mudança.**
4. Para testar o agente nativo `005`, solicitar ao operador a execução **local autorizada**, com privilégios legítimos, do mesmo tipo de teste benigno no diretório isolado; não tentar contornar permissões remotas.
5. Caso a janela acima tenha expirado, uma nova janela e autorização serão necessárias **antes de qualquer novo teste ativo**. Nenhuma alteração B/C ou merge do PR está autorizada aqui.

**Estado final documentado:** `M1=11/17`; `DEPLOYMENT_GATE=BLOCKED` (fail-closed intencional); `CHANGE_A_POSTCHANGE_ACCEPTANCE=PENDING`. Consultar [handoff da madrugada](m1-change-a-cutover-postcheck-handoff-20261105.md), [plano de observabilidade da retomada](m1-change-a-postresume-observability-plan-20261105.md) e [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17).

## Comparação adicional, somente leitura, dos agentes 004 e 005 (05/11)

No mesmo Discover autorizado, data view `wazuh-alerts-*`, período **Last 24 hours**:

| Agente | Consulta sanitizada | Resultado observado | Limite |
| --- | --- | --- | --- |
| `004` / Windows | `agent.id: 004 and syscheck.path: *` | **35 registros FIM** | Caminhos exibidos são **Registro do Windows** (`HKEY*`), não evidência de arquivo Windows |
| `004` / Windows | filtro acima **excluindo** `syscheck.path: HKEY*` | **0 registros de arquivo** | Falta criar/validar evento benigno de arquivo no Windows em janela própria |
| `005` / Kali | `agent.id: 005 and syscheck.path: *` | **0 registros** | Teste ativo do `005` não ocorreu por restrição de permissão; ausência de evento **não prova falha** |

As capturas e a folha de comparação ficam somente no diretório privado `.lab/`. Nenhuma consulta alterou sistema, arquivos, regras ou serviços. **A validação independente do Manager continua pendente**, assim como o teste FIM ativo e autorizado em `005` e um novo evento de arquivo em `004`.

A janela já estava encerrada; nenhuma operação de teste ativo foi executada durante esta comparação.
