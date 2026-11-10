# Checkpoint read-only — agente `004` desconectado — 10/11/2026

**Modalidade:** consulta visual somente leitura no Wazuh Dashboard.
**Estado operacional:** `NO_GO` para qualquer teste, cutover ou validação que dependa do agente Windows `004`.

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

## Próxima etapa segura

Antes de retomar o Change C/H03 ou qualquer teste que dependa do Windows,
o proprietário deve decidir se autoriza um diagnóstico de conectividade do
agente `004`. Até haver nova autorização e uma evidência de retorno a
`active`, o gate global permanece bloqueado e este checkpoint é `NO_GO`.
