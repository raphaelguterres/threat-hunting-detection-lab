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

- [ ] **[Roadmap] Criar e testar cinco casos de detecção documentados**
  - Critério: cada caso possui evidência positiva, negativa, consulta/regra, severidade justificada e hipótese de triagem.
  - Casos: falhas de login, alteração de conta, PowerShell benigno, FIM e conexão de rede inesperada.

- [x] **[Roadmap] Mapear cobertura MITRE ATT&CK e tratar falsos positivos**
  - Critério: catálogo separa marcadores sintéticos de telemetria real e registra limitações e ajustes.

## Fase 4 — Investigação

- [ ] **[Roadmap] Concluir cinco estudos de caso com linha do tempo**
  - Critério: cada caso responde o que aconteceu, ativo/usuário, evidência, classificação e ação recomendada.

## Fase 5 — Resposta segura

- [ ] **[Roadmap] Criar playbooks de triagem com aprovação humana**
  - Critério: cada playbook preserva evidências, prevê contenção segura e rollback; nenhuma ação destrutiva automática.

## Fase 6 — Portfólio e publicação

- [ ] **[Roadmap] Publicar versão redigida e demonstrável do laboratório**
  - Critério: README profissional, diagramas e capturas redigidas; nenhuma credencial, IP público, token ou evidência bruta exposta.

## Convenções de Issues

- Labels: `roadmap`, `telemetry`, `detection`, `investigation`, `playbook`, `documentation` e `portfolio`.
- Em cada Issue: objetivo, escopo seguro, critérios de aceite, comandos/testes autorizados, evidências e limitações.
- Fechar uma Issue somente após anexar ou referenciar a evidência redigida correspondente.
