# Roadmap — Threat Hunting & Detection Lab

Este documento espelha os tópicos que devem ser acompanhados como GitHub Issues. Uma etapa só é encerrada com evidência reproduzível e documentação atualizada.

O retrato operacional mais recente está no [painel de progresso](docs/roadmap-progress.md).

## Fase 1 — Base do laboratório

- [x] **[Roadmap] Documentar arquitetura, inventário e limites de segurança**
  - Critério: arquitetura, inventário e evidências reais publicados sem dados sensíveis.
  - Evidência: `docs/architecture.md`, `docs/inventory.md`, `docs/evidencias-reais.md`.

## Fase 2 — Telemetria e visibilidade

- [x] **[Roadmap] Validar telemetria Windows e preparar coleta Sysmon**
  - Critério: `Security`, `System`, `Application`, PowerShell e Sysmon documentados; pelo menos um evento inofensivo por fonte relevante confirmado no Wazuh.
  - Dependência: Sysmon somente no Windows Server isolado.

- [x] **[Roadmap] Validar FIM Linux fora de filesystem de contêiner**
  - Critério: criar e alterar arquivo em endpoint Linux não conteinerizado e registrar alerta com hashes no Manager.

## Fase 3 — Engenharia de detecção

- [x] **[Roadmap] Criar e testar cinco casos de detecção documentados**
  - Critério: cada caso possui evidência positiva, negativa, consulta/regra, severidade justificada e hipótese de triagem.
  - Casos: falhas de login, alteração de conta, PowerShell benigno, FIM e conexão de rede inesperada.

- [x] **[Roadmap] Mapear cobertura MITRE ATT&CK e tratar falsos positivos**
  - Critério: catálogo separa marcadores sintéticos de telemetria real e registra limitações e ajustes.

## Fase 4 — Investigação

- [x] **[Roadmap] Concluir cinco estudos de caso com linha do tempo**
  - Critério: cada caso responde o que aconteceu, ativo/usuário, evidência, classificação e ação recomendada.

## Fase 5 — Resposta segura

- [x] **[Roadmap] Criar playbooks de triagem com aprovação humana**
  - Critério: cada playbook preserva evidências, prevê contenção segura e rollback; nenhuma ação destrutiva automática.

## Fase 6 — Portfólio e publicação

- [x] **[Roadmap] Publicar versão redigida e demonstrável do laboratório**
  - Critério: README profissional, diagramas e capturas redigidas; nenhuma credencial, IP público, token ou evidência bruta exposta.

## Convenções de Issues

- Labels: `roadmap`, `telemetry`, `detection`, `investigation`, `playbook`, `documentation` e `portfolio`.
- Em cada Issue: objetivo, escopo seguro, critérios de aceite, comandos/testes autorizados, evidências e limitações.
- Fechar uma Issue somente após anexar ou referenciar a evidência redigida correspondente.

## M1 — Threat Hunting orientado a hipóteses (iniciado 02/11/2026)

Este M1 é um **incremento novo**, separado das seis fases históricas concluídas deste laboratório.

- [x] Formular três hipóteses adicionais com fontes, junção temporal, riscos e controles negativos.
- [x] Implementar correlacionador Python offline sobre dados **normalizados e pseudonimizados**.
- [x] Criar fixtures sintéticas e testes de contrato em GitHub Actions Linux/Windows (**sujeito a confirmação do CI no PR**).
- [x] Revisar **disponibilidade de telemetria real** do Windows Security, Sysmon e FIM em modo read-only; [análise de 02/11](docs/m1-native-windows-wazuh-visibility-review-20261102.md).
- [ ] **Correlacionar as três hipóteses em eventos reais completos**, com mesmos atores/ativos/artefatos e revisão manual — contagens e ausência de pares não encerram a investigação.
- [x] Registrar **três estudos de caso reais de FIM autorizado**, com timelines, investigação, classificação benigna, ações e limitações documentadas. [Evidências 05/11/2026](docs/m1-three-real-fim-investigation-case-studies-20261105.md).
- [x] **Revisar tuning, falsos candidatos de correlação e cobertura ATT&CK para H01/H02/H03**, com recortes reais, controles disponíveis e decisões sem alteração ativa. [Parecer técnico 05/11/2026](docs/m1-hunting-tuning-fp-attack-review-20261105.md) · [registro FP](docs/false-positive-register.md) · [matriz ATT&CK](docs/mitre-coverage.md). **Revisão concluída, não validação operacional:** H01 sem `4698`, H02 sem vínculo SID/logon, H03 com FIM real mas sem execução comprovada do mesmo arquivo; H03 não teve controle negativo independente, e nenhuma regra/supressão foi alterada.
- [ ] Encerrar o M1 somente com revisão independente e evidência sanitizada, sem confundir simulação com operação.

- [x] Elaborar [change control do 4698 e revisão FIM 004](docs/m1-change-control-4698-fim-agent004.md), com baseline read-only, riscos de retenção, scripts privados de dry-run e rollback.
- [x] Conferir read-only Security circular 20 MB, dois coletores Security eventchannel e arquivo central recebido; identificar [diretiva FIM central Unix incompatível](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17), sem publicar paths.
- [x] Identificar grupo distribuidor do `agent.conf`: **`default` (4 agentes)**, hash igual entre Manager e agente `004`, sincronização confirmada.
- [x] Revisar estruturalmente os dois coletores Security: **um sem filtro**, outro com **exclusões por EventID**; sem bloqueio explícito do `4698`.
- [x] Preparar [proposta de segmentação FIM por OS](docs/m1-fim-os-scoped-remediation-plan.md) e testes offline sintéticos para impedir caminhos Linux em blocos Windows.
- [x] Adicionar gate offline de **diff mínimo** para permitir apenas inclusão de escopo Linux em agent.conf proposto; impedir alterações inadvertidas de caminhos, fontes, regras FIM ou comentários.
- [x] Validar oficialmente no Manager uma proposta mínima `os="^Linux"` em **cópia isolada fora do diretório distribuído**; `verify-agent-conf` aprovado, original inalterado e cópia removida.
- [x] **Concluir revisão do inventário/OS do grupo atual (3/3), do risco de sobreposição dos coletores Security e da cobertura FIM efetiva do Windows `004`** — [parecer de 05/11/2026](docs/m1-inventory-security-overlap-fim004-closure-20261105.md). A sobreposição potencial **não foi mitigada** e segue vinculada à mudança `4698` (Issue #15); Manager direto e revisão independente continuam pendentes. A conferência atual foi pós-cutover, não deve ser descrita retroativamente como pré-mudança.
- [x] **Mudança Windows Security 4698 autorizada, aplicada e validada em evento real** no agente `004` em 05/11/2026: auditoria `Success`, tarefa benigna descartável, **mesmo EventID 4698 e RecordID 15301** no Security nativo e Indexer/Discover. [Relatório, preflight e rollback](docs/m1-4698-approved-cutover-real-ingestion-20261105.md). Security **20 MiB/circular** acompanhado, backup e rollback local preservados, tarefa removida; **dois coletores com risco potencial de sobreposição ainda não mitigado**, sem leitura independente do `alerts.json` do Manager. O aceite global e revisão externa continuam separados.

**Acompanhamento:** [Issue #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9) · [Três hipóteses M1](docs/m1-three-hunting-hypotheses.md).
