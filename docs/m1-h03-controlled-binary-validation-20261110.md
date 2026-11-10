# H03: validação controlada do binário benigno — 10/11/2026

**Estado: correlação positiva e controle negativo comprovados; conferência visual final no Discover pendente.** Este documento
separa preparação e testes automatizados de eventos efetivamente observados.
O smoke de texto já foi [confirmado em Manager, Indexer e Discover](m1-h03-change-c-activated-20261110.md).

## Escopo autorizado e implementação

O proprietário solicitou a sequência H03 completa e seu controle negativo.
Separadamente, autorizou por 30 minutos a [regra de telemetria 110150 e o
restart do Manager](m1-h03-process-telemetry-proposal-20261110.md). A regra
foi aplicada; a configuração FIM do agente não foi regravada.

O [executor Windows](../scripts/M1_H03_CONTROLLED_BINARY_TEST.ps1), iniciado
manualmente por `TESTAR_H03.cmd`, usa duas versões do
[mesmo código C# benigno](../tests/fixtures/h03_benign_probe.cs). As versões
foram recompiladas no host sem execução no host e com SHA-256 distintos.
O manifesto e os executáveis permanecem em `.lab/`, fora do Git.

O executor:

1. Recusa outro agente, operador inesperado, serviço indisponível, volume
   inadequado, ACL inesperada, reparse point ou diretório não vazio.
2. Confere o alvo FIM e os hashes; cria v1 no caminho positivo.
3. Aguarda recibo do host após confirmar inclusão de v1 idêntica no Manager
   e no Indexer. Só então substitui pelo v2.
4. Aguarda outro recibo com FIM `modified` e hashes v1→v2 idênticos nas duas
   fontes. Só então executa o probe positivo uma vez.
5. Cria uma cópia v2 em outro caminho e a executa uma vez como controle de
   objeto diferente, sem alterar previamente essa cópia.
6. Coleta EID1 nativo dos dois processos, com RecordID, ProcessGuid e hash;
   preserva os XMLs originais no AppData privado do operador na VM.
7. Remove apenas os dois arquivos criados, se ainda tiverem os hashes
   previstos, e confere integridade da configuração e serviço.

O [auditor de leitura](../scripts/m1_h03_live_manager_indexer_audit.py) exige
busca completa, sem timeout ou shards com falha, e igualdade das identidades
e campos relevantes entre Manager/Indexer. Fontes vazias não liberam os
gates; hashes incorretos, eventos divergentes ou duplicidades impedem avanço.

## Adaptações durante a preparação

A primeira tentativa parou ao tentar salvar seu estado na pasta compartilhada
em modo somente leitura. Não executou o probe. A comunicação foi adaptada
para propriedades transitórias do VirtualBox; a pasta continuou protegida.
A localização do VBoxControl foi corrigida para incluir Windows\System32.

O nome das propriedades foi reduzido para respeitar o limite de 63 caracteres
mais terminador. Cada valor codificado fica abaixo de 1024 bytes. O teste de
marcador host→VirtualBox passou. Esses limites são definidos no
[código oficial do serviço de propriedades](https://github.com/VirtualBox/virtualbox/blob/main/include/VBox/HostServices/GuestPropertySvc.h).

O proprietário reiniciou o Windows após travamento do computador. A consulta
ao Manager confirmou agente `004` ativo e varredura FIM posterior ao reboot
concluída. As tentativas abortadas não são prova de execução nem de correlação.
O recorte da nova sessão exclui os eventos da primeira tentativa.

## Validação de código

- Parser PowerShell e compilação sintática Python: aprovados.
- Suite final: **288 testes aprovados, 5 ignorados, 206 subtestes aprovados**.
  O novo teste do finalizador PowerShell foi ignorado neste host porque a
  política bloqueou o script temporário; a política foi preservada. A limpeza
  real na VM foi conferida separadamente.
- Testes adicionais verificam fonte vazia, duplicidade, identidade divergente,
  hash anterior errado, consulta incompleta e ausência de identidade do ator.
- Parser oficial da regra: aprovado em contêiner isolado; eventos reais
  continuam sendo requisito separado.

## Aceite ainda necessário

| Verificação | Estado nesta preparação |
| --- | --- |
| Regra restrita 110150 instalada e serviços essenciais ativos | PASS |
| Baseline v1 da sessão confirmada nas duas fontes | PASS |
| Alteração v1→v2 confirmada nas duas fontes | PASS |
| Execução positiva e negativa: EID1 nativo e SHA-256 v2 | PASS, dois registros nativos |
| Mesmas identidades Sysmon no Manager/Indexer | PASS, dois RecordIDs/ProcessGuids e hashes coincidentes com a fonte nativa |
| Correlação positiva: 1 candidato; controle de outro objeto: 0 | PASS, 1 positivo e 0 no controle |
| Eventos dessa sessão visíveis no Discover | PENDENTE |
| Limpeza e pós-check da sessão | PASS, arquivos do teste removidos, configuração preservada e serviço ativo |

O motor usa timestamps de recebimento do Manager para os dois lados da
correlação, com fuso explícito; os horários nativos são preservados em separado.
Os recibos anteriores à execução também comprovam a ordem operacional. Não
misturar horário de exibição do navegador, mtime e UTC nativo sem verificar
sua relação.

**M1 continua 15/17:** concluir H03 isoladamente não conclui as correlações
H01/H02 nem substitui a revisão independente final.

## Rodadas executadas e problemas identificados

A rodada posterior à correção do recibo confirmou a inclusão v1 e a
alteração v1→v2 no Manager/Indexer antes de chamar o probe positivo e o
controle em outro caminho. A extração XML inicialmente ignorava o namespace
dos eventos Windows; o coletor de leitura foi corrigido e confirmou dois
Sysmon EID1 existentes, sem novas execuções. Os hashes eram os esperados.

Uma tentativa cancelada por Ctrl+C havia produzido um recibo de limpeza
insuficiente: o pré-check seguinte detectou arquivo restante. Foi acrescentada
recuperação limitada à cópia v1 no caminho fixo, com hash exato e sem outros
itens no diretório. A limpeza normal passou a usar operações de arquivo .NET
e verificação explícita de existência. Recibos durante cancelamento não são
tratados como prova suficiente de diretório vazio.

O Manager registrou falta de permissão de leitura da nova regra. O arquivo
estava em modo 640 com grupo herdado incorretamente da referência. Dentro
da janela autorizada, o grupo foi corrigido para `wazuh`, com leitura testada
após reduzir privilégios para a identidade do serviço. Parser e restart
passaram; conclusão registrada às **21:31:07 UTC pelo relógio do Manager**.

Uma nova rodada executou apenas os dois probes, sem outra mudança de
serviço. A extração XML corrigida confirmou dois EID1, hashes v2 e referências
RecordID/ProcessGuid privadas. O pós-check independente confirmou pasta
vazia, configuração igual à proposta e serviço ativo. Ainda assim, o
recorte consultado não continha os dois alertas Sysmon no Indexer.

A inspeção de **342 imagens Sysmon EID1 já recebidas** mostrou barras
duplicadas em todas elas. O padrão ancorado da regra só aceitava separadores
simples. A correção proposta aceita as duas representações dos mesmos
caminhos; o auditor também normaliza os separadores para comparar FIM/Sysmon.
O parser oficial aprovou a proposta em contêiner isolado e os testes de
escopo/correlação passaram. A janela anterior terminou; uma nova autorização
de 20 minutos foi solicitada para a troca desse único padrão e restart.

Os XMLs nativos permanecem no AppData privado da VM; referências, manifestos,
recibos e snapshots selecionados do Manager/Indexer estão em `.lab/`.
Nenhum evento bruto foi injetado ou apresentado como alerta real.

## Rodada após a correção do padrão

A correção do padrão foi aplicada na nova janela explicitamente autorizada,
com parser/restart aprovados e demais configurações preservadas. A rodada
seguinte confirmou baseline e alteração nas duas fontes antes da execução.
O auditor retornou:

- **7 eventos no Manager e 7 no Indexer**, com igualdade dos campos de
  identidade e conteúdo relevantes: cinco FIM e dois Sysmon EID1.
- Os dois processos geraram regra **110150**, com SHA-256 v2 esperado;
  RecordID e ProcessGuid coincidem com os dois registros nativos da VM.
- Zero eventos FIM `modified` do objeto de controle; sua execução, por outro
  lado, está comprovada nas fontes. A ausência de modificação do controle
  não foi confundida com ausência de execução.
- O executor confirmou remoção dos arquivos do teste, configuração preservada
  e serviço ativo.

Três registros reais normalizados foram submetidos ao correlacionador
existente: alteração do objeto positivo, execução desse mesmo objeto e
execução do outro objeto. Resultado **1 candidato H03**, com intervalo de
**7,159 segundos** entre alteração e execução.

O controle usa a alteração do objeto positivo e a execução do objeto diferente
no mesmo ativo, com o mesmo hash v2 e intervalo de **7,204 segundos**.
Resultado **0 candidatos**: o hash igual não substitui a identidade do caminho.
Os controles são baseados em eventos reais, sem trocar artificialmente
identificadores ou fabricar linhas sintéticas para esta evidência.

Esses eventos representam um teste benigno autorizado, não um incidente.
O resumo do correlacionador, originais selecionados e referências nativas
permanecem privados. A conferência visual final do Discover é o último
controle desta rodada ainda não atestado nesta atualização.

### Linha do tempo da rodada comprovada

Horários abaixo são os timestamps UTC dos documentos, não o fuso exibido
na interface do navegador.

| UTC em 10/11/2026 | Evento | Regra |
| --- | --- | --- |
| 21:40:45.292 | Inclusão v1 do objeto positivo | 554 |
| 21:41:00.636 | Alteração v1→v2 do mesmo objeto | 550 |
| 21:41:06.933 | Inclusão da cópia de controle em outro caminho | 554 |
| 21:41:07.795 | Execução do objeto positivo, Sysmon EID1 | 110150 |
| 21:41:07.840 | Execução do objeto de controle, Sysmon EID1 | 110150 |
| 21:41:10.071–21:41:10.072 | Exclusão dos dois arquivos do teste | 553 |

O resultado de um candidato se refere ao **recorte desta rodada**. Os mesmos
dois caminhos foram reutilizados nas tentativas documentadas; uma busca
histórica mais ampla pode produzir outros pares válidos dentro de 20 minutos.
O teste não comprova precisão global, deduplicação por execução ou ausência
de falsos positivos em um ambiente real.
