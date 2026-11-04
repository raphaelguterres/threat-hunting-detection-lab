# Roadmap autoral — Cyber Defense Engineering Lab

**Atualizado em 04/11/2026.** Este documento propõe evolução técnica para um **laboratório autoral de ciberdefesa**, além de instalar ferramentas. O produto público é o **repositório, suas detecções, validações e evidências sanitizadas**; a infraestrutura real permanece privada.

## Norte do projeto

Construir uma plataforma de laboratório que responda, para cada hipótese: **qual comportamento, quais fontes, qual regra, qual evidência, qual triagem, como reduzir falsos positivos e qual decisão é defensável**. Vincular cada teste a MITRE ATT&CK, telemetria verificada, critérios de aceite e cobertura real.

## Progresso por trilha

| Trilha | Objetivo técnico | Entregável público verificável | Estado |
| --- | --- | --- | --- |
| Base histórica 1–6 | VMs, agentes Windows/Linux, Wazuh, telemetria e primeiros estudos de caso | Arquitetura, casos, regras, playbooks e testes | **Concluída (6 fases)** |
| M1: Hunting + Evidence Gate | H01/H02/H03, gates, regras, rastreabilidade | Contratos de correlação, testes, auditorias, checklists | **11/17 (64,7%)** |
| M1-H03 | FIM real de arquivo + execução do mesmo binário Sysmon ID 1 em até 20 min | Evidência original sanitizada Manager → Indexer → Dashboard | **Pendente — NO-GO operacional** |
| M2: Detection as Code | Regras versionadas, validação sintática, TTP→regra→evento→caso | Matriz de cobertura, regression suite, templates de detecção | **Planejado** |
| M3: Engenharia de telemetria | Quality gates de timestamps, schemas, falhas de ingestão e retenção | Data contracts, testes de fonte, dashboard de saúde | **Planejado** |
| M4: Windows + identidade | Sysmon, Active Directory, logons, criação de contas e tarefas | Hunting packs para T1053, T1078, T1110 e persistência | **Planejado** |
| M5: Threat Hunting | Hipóteses, hunting queries, timelines e falsos positivos | Casos anonimizados com controls positivos/negativos | **Planejado** |
| M6: Incident Response | Triagem, escopo, contenção simulada, recuperação e lições | Playbooks versionados e relatórios de tabletop | **Planejado** |
| M7: SOAR / automação segura | Enriquecimento e resposta em **dry-run**, sem contenção automática | Pipelines e artefatos verificáveis com aprovações | **Planejado** |
| M8: Cloud + IAM | Fontes de auditoria CloudTrail/Azure em fixtures públicas/sintéticas | Detecções cloud e documentação sem custo obrigatório | **Planejado** |
| M9: Engenharia de segurança | Threat modeling do pipeline, SBOM, segredos, RBAC e supply chain | Threat model e política de publicação/CI | **Planejado** |
| M10: Portfólio técnico | Navegação por cenários, matriz ATT&CK, evidências, resultados | Página GitHub e landing estática de laboratório | **Planejado** |

## Critério de aceite comum

Toda fase só se declara concluída quando houver (1) objetivo técnico, (2) dados e fontes identificados, (3) teste positivo e controle negativo, (4) rastreabilidade de commit/CI, (5) limites e falsos positivos documentados, (6) evidência sanitizada e (7) plano de manutenção/rollback quando houver impacto operacional. Um teste sintético é prova de **contrato de código**, não de **detecção efetiva na VM**.

## Estrutura recomendada de repositório

```text
.github/workflows/       CI e gates não intrusivos
config/                  configurações de exemplo, sem segredos
detections/              regras versionadas, casos de uso e mapeamento TTP
tests/                   testes offline, positivos e negativos
scripts/                 auditorias somente leitura e automação controlada
docs/architecture*       redes, dados, confiança, disponibilidade
docs/m1-*                changelogs, gates e evidências de M1
cases/                   timeline e relatório por hipótese
playbooks/               triagem / incident response / rollback
diagrams/                desenhos Mermaid / fontes editáveis
.lab/                    artefatos reais privados (não versionados)
```

## H03 como primeiro caso de demonstração com qualidade enterprise

**Plano:** compilar duas variantes de um executável próprio e inofensivo; manter os arquivos somente em `.lab/` do host; quando a **mudança C** estiver aprovada e aplicada, instalar o diretório isolado local no agente `004`, adicionar uma única diretiva realtime, comprovar a configuração ativa, preparar baseline do arquivo, substituir pela segunda variante e executá-la com aprovação específica.

**Demonstração esperada (ainda não observada):** alerta FIM de mudança do mesmo arquivo, seguido de Sysmon Event ID 1 apontando a mesma imagem e host, dentro de 20 minutos, com provas no Manager, Indexer e Dashboard. Confirmar comportamento adverso por controle negativo e preservar hashes privados. É um **teste benigno de detecção**, não uma simulação de malware.

A primeira fase de preparação **já pode ser executada no host**, com `scripts/build_h03_benign_probe_host_only.ps1`. Esse comando **não instala nem executa** nada na VM Windows Server. Consultar o [plano de teste do binário H03](m1-h03-benign-binary-test-plan-20261104.md).

## Valor profissional mensurável

- **SOC:** distinguir telemetria bruta, alerta e hipótese de incidente.
- **Detection Engineering:** implementar, validar e versionar regras com falso positivo/controle negativo.
- **Threat Hunting:** construir casos com ordem, identidade do artefato, timestamps e hipótese falsificável.
- **Security Engineering:** projetar isolamento de rede, ACL, change control, backup/rollback.
- **Resposta a incidentes:** triagem fundamentada, evidências, recomendações e simulações supervisionadas.

**Regra de publicação:** nunca expor credenciais, IP público, nomes de usuários, chaves, hashes brutos privados ou eventos identificáveis. Repositório autoral não exige expor a infraestrutura. Divulgar conclusões com escopo/limites e evitar títulos enganosos como “H03 concluído” antes da evidência real.

[Arquitetura e exposição pública](architecture-network-public-exposure-20261104.md) · [Roadmap M1 atual](roadmap-progress.md) · [Contrato H03](m1-three-hunting-hypotheses.md)
