# H01 — preparação do teste controlado em 10/11/2026

Este documento registra a preparação. O [resultado da execução autorizada](m1-h01-controlled-correlation-20261110.md) está em relatório separado.

**Estado: preparado offline, sem execução ativa.** O H03 já foi validado;
M1 permanece **15/17**. O H01 exige Sysmon EID1 do PowerShell seguido por
criação real de tarefa (Security 4698), no mesmo ativo e ator, em até 15 minutos.

A leitura autenticada do Indexer para o agente `004`, últimos sete dias,
retornou **quatro eventos 4698 e zero Sysmon EID1 da regra 110100**. A consulta
foi completa no recorte. Não há par H01 comprovado nessa amostra; isso não
significa ausência global de PowerShell ou falha do coletor.

A cópia privada da regra ativa 110100 passou nos cinco vetores de escopo:
PowerShell codificado corresponde à regra; o ensaio anterior com `-File`,
que já comprovou 4698 e o par nativo, não corresponde. A inspeção de XML não
substitui um alerta real. Nenhuma regra, coletor ou serviço foi alterado.

## Verificação anterior à autorização

Abra `scripts/windows/VERIFICAR_H01.cmd` somente no Windows de laboratório.
Ele verifica agente, serviços, canais, auditoria Success, ausência de tarefa
conflitante e o modelo de tarefa **apenas em memória**, sem registrá-la.
Também procura um 4698 histórico do mesmo ator para um controle de ordem
temporal. As referências ficam privadas, com comunicação transitória pelo
VirtualBox e a pasta compartilhada mantida somente leitura.

## Escopo do futuro ensaio

- Uma execução PowerShell para exercitar a regra existente. O conteúdo
  codificado é apenas a chamada para o [payload revisável](../scripts/M1_H01_DISABLED_TASK_PAYLOAD.ps1)
  copiado localmente, com hash conferido e política de execução preservada.
- Uma tarefa descartável com [definição desabilitada](../config/h01-disabled-task-template.xml),
  sem gatilhos e sem execução sob demanda. Registro somente de criação,
  sob a conta interativa existente e sem elevação da tarefa. Sua ação não é
  executada. O executor remove apenas a tarefa com marcador da sessão e
  reconfirma ausência e integridade da configuração.
- O [controlador](../scripts/M1_H01_ENCODED_CONTROLLER.ps1) exige preflight
  atual, hashes dos arquivos e recibo de nova autorização com horário e
  escopo. O recibo ainda não foi emitido. A tentativa antiga interrompida
  e sua janela expirada não foram reutilizadas.
- Depois da execução, comparar identidades dos dois registros nativos com
  Manager, Indexer e Discover. Duplicatas de transporte, se observadas,
  devem ser registradas e não contadas como tarefas diferentes.
- O controle temporal usa um 4698 real anterior ao novo processo, quando
  sua identidade puder ser verificada. Não gerar outra tarefa nem inventar
  um ator só para o controle.

A API de registro permite separar criação de atualização e usar a sessão
interativa existente: [referência Microsoft](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskfolder-registertaskdefinition).
Os parsers PowerShell e os contratos offline passaram; **não há nova prova
operacional H01** até concluir o pré-check, obter nova autorização e verificar
as fontes da execução real.
