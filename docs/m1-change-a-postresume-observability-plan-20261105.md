# M1 — retomada segura e plano de aceite pós-mudança A (05/11/2026)

**Marco de retomada:** ~13h00 BRT. **Alteração já implantada:** `M1-FIM-OS-SCOPE` (somente seletor `os="^Linux"`). Este documento é um checkpoint novo; não substitui a [evidência do cutover e handoff da madrugada](m1-change-a-cutover-postcheck-handoff-20261105.md).

## O que foi verificado hoje

- O computador remoto estava acessível; as VMs **Kali/Wazuh** e **Windows Server** estavam no estado VirtualBox **saved** (nenhuma running). Foram **retomadas a partir do estado salvo**, sem reinstalação, reset ou modificação de regras.
- Após a retomada, os contêineres **Wazuh Manager, Indexer e Dashboard** foram observados em execução.
- Os agentes **`002`, `004` e `005`** foram consultados individualmente: **Active e synchronized (3/3)**.
- O **hash da configuração central ativa** permaneceu idêntico ao hash esperado da mudança A; o **parser oficial Wazuh = PASS**.
- O arquivo de rollback preservado no Manager continua com o **hash da configuração anterior à mudança**. A existência de backup não substitui restauração operacional.
- O relógio do Kali foi observado cerca de **22 segundos adiantado em relação ao host Windows**, sem atribuição causal. Nenhum relógio foi alterado; correlacionar por identidade e tolerância temporal, não somente pelo horário.
- Testes Python locais, somente offline: **224 executados, 4 pulados, saída `OK`, exit 0**. O contador do roadmap permanece **M1 11/17 (64,7%)**, não representa nota de segurança.
- O último CI confirmado antes desta atualização foi o [GitHub Actions #118](https://github.com/raphaelguterres/threat-hunting-detection-lab/actions/runs/41967705612) (**3/3 SUCCESS**, SHA `540a2e6`). PR [#25](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/25) continua aberto, sem merge/revisão independente.

## Gate atual

`UI_CONFIGURATION_SCOPE=PASS_3_OF_3` se refere ao checkpoint visual anterior de `004` Windows (seis diretórios Windows, sem caminho Unix) e `002/005` Linux (sete diretórios, FIM realtime no caminho do laboratório; `localfile` Unix visível em `005`).

**Não há prova nova de uma mesma ocorrência FIM pós-cutover percorrendo Endpoint → Manager → Indexer → Dashboard Discover.** Consequentemente, `windows_fim`, `linux_fim`, `manager_ingestion`, `indexer_ingestion` e `discover_visibility` seguem **PENDING** no manifesto. `DEPLOYMENT_GATE=BLOCKED` permanece propositalmente; não modificar o gate para obter PASS artificial.

## Roteiro de validação de telemetria — modo leitura

1. **Dashboard autorizado:** abrir `Threat hunting → Discover` ou a área equivalente, selecionar o data view `wazuh-alerts-*` (se disponível) e delimitar a janela **após 05/11 00h42 BRT** (aprox. **03h42 UTC**). Não confundir janela local e UTC.
2. **Windows `004`:** filtrar por agente e campo FIM (como `syscheck.path`); verificar que não existe o diretório Unix indevidamente herdado nos metadados da configuração atual. Essa ausência de configuração não equivale, por si, a um novo evento de alteração de arquivo.
3. **Linux `002/005`:** verificar se há eventos FIM posteriores ao cutover. **Zero eventos após o corte não comprova falha**, pois a monitoração pode estar ociosa. Não gerar arquivo artificialmente para preencher a evidência.
4. Se houver um evento **real, benigno e pré-existente**, correlacionar **ID de agente, ID de regra, caminho/artefato, tipo de alteração e horários**, por registro entre as fontes autorizadas Manager → Indexer → Discover. Salvar rastreabilidade **somente em `.lab/` privado**, com saída pública sanitizada.
5. Para um **novo teste ativo** (criar/alterar arquivo de prova no diretório isolado do laboratório), solicitar **janela e aprovação de teste específicas**; fazer baseline, registrar critérios de parada/limpeza, observar resultado e recuar se surgir regressão. A autorização anterior da mudança A **expirou** e não autoriza nova alteração B, C, `4698`, executáveis H03 nem teste de malware.

**Restrição desta sessão:** uma consulta remota direta aos alertas brutos foi bloqueada pelas configurações de segurança do acesso. **Não houve tentativa de contornar** essa restrição por outra interface ou exportação. As verificações de identidade de eventos ficam pendentes de operação autorizada pelo proprietário nos controles permitidos.

## Critérios de aceite do próximo ciclo

- [x] VMs restauradas de `saved`; Manager/Indexer/Dashboard executando
- [x] Agentes `002/004/005` ativos e sincronizados
- [x] Hash/parser da configuração implantada íntegros
- [x] Cópia temporária de rollback original ainda disponível
- [x] Testes unitários offline passaram e contagem do M1 reconfirmada
- [ ] Evento FIM pós-cutover validado no Linux com cadeia até Discover (quando autorizado/disponível)
- [ ] Evidência da preservação de FIM Windows por evento verificável recente
- [ ] Ingestão e identidade do mesmo evento Manager/Indexer/Discover verificadas
- [ ] Verificação `localfile` em runtime sem perda de telemetria
- [ ] Registro formal de aceite ou de regressão/rollback, com evidências sanitizadas

## Segurança e próximo passo

Não atualizar campos `verified` sem observação real, não realizar `auditpol /set`, restart de containers/VMs, mudança de grupos nem limpeza de backup por conveniência. Manter a branch separada e o PR sem merge até os critérios de revisão. Nenhum incidente foi inferido de dados sintéticos.

**Próximo passo operacional:** validação de eventos no Wazuh autorizado ou preparação de novo teste benigno com aprovação delimitada. Não repetir cutover nem apagar o rollback. **M1 11/17; aceite da mudança A continua pendente.**
