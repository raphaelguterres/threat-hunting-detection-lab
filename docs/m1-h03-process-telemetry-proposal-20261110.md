# H03: proposta de telemetria restrita de processos

Estado atualizado: **regra instalada em 10/11, 21:05:44 UTC (18:05:44 BRT)**.
A autorização específica do proprietário permitiu a regra restrita e restart
do Manager por 30 minutos; o executor usou o limite de 21:31:46 UTC
(18:31:46 BRT). A mudança é separada da configuração FIM aplicada no Windows.

## Problema observado

A regra-base Sysmon EID1 `61603` tem nível 0 e o Manager armazena alertas a
partir do nível 3. As regras customizadas existentes tratam outros padrões;
nenhuma delas dá cobertura explícita ao probe H03. Portanto, um processo
benigno pode estar no Sysmon nativo e ficar ausente de `wazuh-alerts-*`.

## Mudança concreta

[XML proposto](../config/h03-benign-process-telemetry.xml): regra `110150`,
nível **3**, provider Sysmon, Event ID **1**, grupo `sysmon_event1` e imagem
limitada exatamente aos dois caminhos:

- `C:\SecurityLab\H03\H03-BenignProbe.exe`: versão v1 substituída pela v2;
- `C:\SecurityLab\H03\H03-NegativeProbe.exe`: controle de objeto diferente.

Sem alteração de regra-base, limiar, archives, FIM, coleta, auditoria ou
Indexer. A descrição identifica telemetria benigna de laboratório, sem
atribuir ataque ou técnica MITRE. A regra limita caminho e tipo de evento;
não autentica o conteúdo do executável nem substitui verificação de hashes.

## Validação anterior à aplicação

- 34 testes Python passaram; 1 foi ignorado; 62 subtestes passaram, incluindo
  limites dos caminhos e contratos do correlacionador.
- `wazuh-analysisd -t` retornou **0** com a proposta em contêiner descartável
  da mesma imagem, sem rede e sem volumes do Manager ativo.
- ID `110150` não encontrado nos arquivos de regras XML ativos durante o
  preflight. Deve ser reconferido no instante da aplicação.
- Os vetores EventChannel no logtest legado não comprovaram correspondência:
  o JSON foi decodificado como `json`, não `windows_eventchannel`. Não são
  tratados como testes positivos aprovados. A limitação do EventChannel no
  logtest também é discutida no [repositório oficial Wazuh](https://github.com/wazuh/wazuh/issues/30472).
- A comprovação final depende dos eventos reais do agente e do Indexer.

## Aplicação e rollback propostos

1. Registrar hashes privados das configurações e regras existentes; conferir
   três agentes ativos e ausência do novo arquivo/ID.
2. Acrescentar somente `etc/rules/h03-benign-process-telemetry.xml` no Manager.
3. Validar com `wazuh-analysisd -t`; falha remove somente a nova regra, antes
   de qualquer restart.
4. Reiniciar somente os serviços Wazuh do **Manager** para carregar a regra.
   Há breve interrupção de processamento; Indexer, Dashboard e agentes não
   são reiniciados.
5. Conferir serviços/agentes e preservação dos arquivos anteriores. Em falha,
   remover somente o novo arquivo se seus bytes ainda coincidirem com a
   proposta, validar e reiniciar o Manager com as regras anteriores.
6. Após o teste, decidir e registrar retenção ou remoção dessa telemetria.

## Resultado da aplicação autorizada

A primeira aplicação validou sintaxe e reiniciou os serviços, mas o
pós-check interpretou o retorno global de `wazuh-control status` como falha:
serviços opcionais desativados também tornam esse retorno diferente de zero.
O executor removeu a nova regra e realizou rollback, confirmado como aprovado.

Após corrigir o pós-check para verificar explicitamente os serviços essenciais,
a aplicação foi repetida na mesma janela autorizada. Resultado:
`rule_110150_installed=true`, `official_parser_pass=true`,
`manager_services_restarted=true`, `required_services_running=true`,
`prior_files_unchanged=true`, `rollback_needed=false`.
Indexer, Dashboard e agentes não foram reiniciados por esta mudança.

A regra instalada comprova configuração e carga dos serviços, não o evento
do probe. **Validação real de Sysmon do binário ainda pendente.**

## Correções verificadas após a implantação

O status de serviços acima não comprovava que a regra havia sido lida.
O log mostrou `Permission denied` no arquivo: o modo 640 foi mantido,
mas o grupo precisou ser corrigido para `wazuh`. A leitura foi comprovada
executando a verificação com a identidade do serviço; parser e restart
passaram, concluídos às 21:31:07 UTC no relógio do Manager, dentro do limite
autorizado. Um parser executado como root não substitui esse teste de acesso.

Os eventos nativos dos probes foram depois confirmados, mas a busca não
mostrou os respectivos alertas Sysmon. A auditoria de 342 imagens EID1
existentes confirmou a representação com barras duplicadas. O XML versionado
agora contém a **correção proposta** do único campo de caminho, aceitando
separadores simples ou duplicados nos mesmos dois objetos. Isso ainda não
significa que essa revisão do XML esteja aplicada. O parser isolado passou;
a aplicação/restart aguardam nova janela de 20 minutos solicitada ao dono.

O proprietário autorizou a nova janela, delimitada no executor até
**21:56:40 UTC (18:56:40 BRT)**. A correção do único padrão foi aplicada;
parser e restart retornaram sucesso, serviços essenciais ativos e demais
configurações iguais à baseline. Conclusão às **21:37:49 UTC pelo relógio
do Manager**, sem rollback. A nova rodada dos probes é necessária para
atestar a geração de alertas reais com essa revisão carregada.
