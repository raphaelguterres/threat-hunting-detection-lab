# Checkpoint read-only — agente `004` desconectado — 10/11/2026

**Modalidade:** consulta visual somente leitura no Wazuh Dashboard.
**Atualização posterior de 10/11:** Dashboard recuperado; `002`/`004`/`005` ativos. A página Configuration do `004` exibiu `SYNCHRONIZED` e somente `default`. A desconexão abaixo é histórica. Change C/H03 continua pendente de preflight e janela.

## Resultado observado

No seletor **Explore agent** do Dashboard, a coleta de 10/11 exibiu o
inventário atual abaixo. Não foram feitas alterações em agentes, grupos,
Manager, serviços, FIM, regras, arquivos ou políticas.

| ID | Grupo exibido | Sistema operacional exibido | Cliente | Estado exibido |
|---|---|---|---|---|
| `002` | `default` | Amazon Linux 2023 | Wazuh `v4.14.9` | `active` |
| `004` | `default` | Microsoft Windows Server 2022 Standard Evaluation `10.0.20348.587` | Wazuh `v4.14.9` | `disconnected` |
| `005` | `default` | Kali GNU/Linux 2026.3 | Wazuh `v4.14.9` | `active` |

O seletor exibiu somente o grupo `default` para cada um dos três membros;
portanto, a ordem observável de grupos para cada um é a lista unitária
`[default]`. O agente `003` permaneceu fora desse grupo e `never connected`.

## Limites e impacto

- Esta observação **não** reatesta sincronização de configuração: o seletor
  não mostra esse atributo e o `004` estava desconectado.
- Ela substitui qualquer inferência de que o conjunto `002`/`004`/`005` esteja
  `3/3 active` após o último checkpoint de 06/11. Checkpoints anteriores
  continuam históricos, com suas datas preservadas.
- O resumo visual do Dashboard exibiu dois agentes ativos; a linha do `004`
  no seletor é a evidência usada para a classificação deste checkpoint.
- Não se tentou reiniciar, reconectar, reparar ou alterar o `004`. Uma ação
  desse tipo requer autorização operacional nova e explícita, fora deste
  checkpoint.

## Recuperação observada na mesma sessão

Após reinícios realizados pelo proprietário, o Dashboard voltou a carregar.
A listagem de endpoints confirmou `002`, `004` e `005` ativos, todos em
`default`, e a aba Configuration do `004` confirmou `SYNCHRONIZED`.
O operador também forneceu saída de `findmnt` com a raiz do Kali em `rw`
e os contêineres Manager, Indexer e Dashboard em execução. A causa da
montagem anterior em somente leitura permanece desconhecida; recuperação
de acesso não equivale a comprovação de integridade do sistema de arquivos.

O próximo passo de H03 é revalidar backup DPAPI, baseline e configuração
ativa. M1 permanece 15/17 e o gate final bloqueado.

## Backup Windows revalidado em 10/11

O proprietário executou `VERIFICAR_BACKUP.cmd` na VM Windows, usando uma
cópia local conferida byte a byte do verificador privado. A política
`RemoteSigned` foi preservada; a primeira tentativa diretamente pela unidade
compartilhada havia sido bloqueada por exigência de assinatura.

O resultado observado na tela confirmou `BACKUP_FILE_PRESENT=TRUE`,
`BACKUP_DIRECTORY_ACL_PROTECTED=TRUE`, backup cifrado de 9942 bytes,
recuperação de 9725 bytes e `BACKUP_MATCHES_CURRENT_ACTIVE_FILE=True`.
A descriptografia ocorreu somente em memória, com código de saída 0,
`RESTORE_WRITE_PERFORMED=NO` e `WAZUH_SERVICE_MODIFIED=NO`.

Isso confirma recuperabilidade dos bytes sob o perfil atual e igualdade com
o arquivo atual, não uma restauração operacional nem validação da configuração
efetivamente carregada. A checagem de ACL do script usa nomes de grupos;
não substitui uma revisão completa de permissões por SID. Gate final bloqueado.

## Configuração FIM ativa consultada no Dashboard em 10/11

Na página Configuration / Integrity monitoring do agente `004`, a interface
exibiu FIM `enabled`, intervalo `43200` segundos e `Scan on start=yes`.
Em Monitored foram observadas seis entradas Windows; nenhuma contém o
diretório proposto `C:\SecurityLab\H03`. A entrada de inicialização
selecionada exibiu `realtime=yes`. Não foi feita uma conferência individual
dos demais atributos de cada entrada.

Em Ignored foram exibidos um caminho `desktop.ini` na pasta Startup e a
expressão de sufixos `.log$|.htm$|.jpg$|.png$|.chm$|.pnf$|.evtx$`.
Essa consulta confirma o escopo apresentado pela configuração ativa do
Dashboard, não eventos FIM novos nem execução de artefato H03.

Próximo preflight: NTFS, ausência de reparse points e condições de criação
com ACL mínima no alvo proposto; depois proposta de diff único e janela
operacional. Change C não foi aplicada nesta sessão.

## Preflight local H03 em 10/11

O proprietário executou `VERIFICAR_H03.cmd`; saída 0, coleta concluída.
Volume C: NTFS, HealthStatus Healthy, aproximadamente 34,92 GiB livres;
`WazuhSvc=Running`. Raiz C: diretório real sem reparse point; a triagem por
SID contou duas ACEs Allow com direitos de escrita amplos na raiz. Essa
contagem não avalia condições de aplicação/herança nem prova acesso efetivo.
`C:\SecurityLab` e `C:\SecurityLab\H03` estavam ausentes.

Uma criação futura precisa estabelecer DACL protegida mínima já no momento
da criação, tanto no pai novo quanto no alvo, seguida de inspeção por SID;
não herdar automaticamente as permissões da raiz. Nenhum diretório, ACL,
configuração ou serviço foi alterado pelo preflight. Resultado não autoriza
Change C, smoke test ou execução de binário. Relógios e demais gates ainda
devem ser revalidados na janela operacional.

## Próxima etapa segura — decisão histórica anterior à recuperação

Antes de retomar o Change C/H03 ou qualquer teste que dependa do Windows,
o proprietário deve decidir se autoriza um diagnóstico de conectividade do
agente `004`. Até haver nova autorização e uma evidência de retorno a
`active`, o gate global permanece bloqueado e este checkpoint é `NO_GO`.
