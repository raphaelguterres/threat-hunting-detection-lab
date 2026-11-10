# Threat Hunting & Detection Lab

**Comece pelo [guia do laboratório](docs/guia-do-laboratorio.md):** arquitetura,
estrutura das pastas, hipóteses H01/H02/H03, validação de eventos e publicação
no GitHub. O [painel de progresso](docs/roadmap-progress.md) reúne o estado
mais recente; os checkpoints datados registram o histórico.

<p align="center">
  <strong>Cyber Defense Engineering para transformar telemetria em decisões investigáveis.</strong><br />
  <sub>Wazuh · Windows Server · Linux · Sysmon · FIM · MITRE ATT&CK · Playbooks · Evidência reproduzível</sub>
</p>

<p align="center">
  <a href="https://github.com/raphaelguterres/threat-hunting-detection-lab/actions/workflows/validate-lab.yml"><img src="https://github.com/raphaelguterres/threat-hunting-detection-lab/actions/workflows/validate-lab.yml/badge.svg" alt="Validação do laboratório" /></a>
  <a href="docs/roadmap-progress.md"><img src="https://img.shields.io/badge/M1-15%2F17%20itens%20verificados-0A7A4A?style=flat-square" alt="M1: 15 de 17 itens verificados" /></a>
  <a href="docs/mitre-coverage.md"><img src="https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-7A1FA2?style=flat-square" alt="Cobertura MITRE ATT&CK" /></a>
  <img src="https://img.shields.io/badge/Ambiente-Isolado%20e%20sanitizado-155EEF?style=flat-square" alt="Ambiente isolado e sanitizado" />
</p>

> **Para empresas e líderes de segurança:** este repositório mostra como eu projeto um fluxo defensivo completo — do endpoint ao Dashboard — com hipóteses de hunting, controles de mudança, validação de qualidade e comunicação clara das limitações.

## Em uma frase

Eu não trato alerta como conclusão: trato como o início de uma investigação com contexto, evidência, decisão, responsável e próximo passo verificável.

## O problema que este trabalho resolve

Empresas não precisam somente de mais eventos no SIEM. Precisam saber se a visibilidade é confiável, se a detecção é acionável e se a resposta pode ser auditada sem interromper o negócio.

| Desafio operacional | Como este laboratório endereça |
| --- | --- |
| Telemetria fragmentada entre Windows e Linux | Coleta Wazuh com Sysmon, Event Channels, logs nativos e File Integrity Monitoring (FIM). |
| Alertas sem contexto | Casos de investigação com hipótese, linha do tempo, evidência, classificação e recomendação. |
| Mudanças de detecção que elevam risco | Gates de evidência, pré-check, diff mínimo, rollback e revisão humana. |
| Hunting difícil de reproduzir | Correlacionador offline, fixtures pseudonimizadas e testes de contrato versionados. |
| Portfólio que expõe o ambiente | Documentação e imagens redigidas; sem IPs públicos, credenciais ou evidência bruta. |

## Capacidades demonstradas

### Engenharia de detecção e visibilidade

- Instrumentação de endpoints **Windows Server e Linux** com Wazuh;
- Coleta de **Sysmon**, Windows Event Channels, autenticação, auditoria e FIM;
- Regras locais, catálogo de detecções, severidade e cobertura **MITRE ATT&CK**;
- Controles de qualidade: cobertura, falsos positivos, negativos e limites declarados.

### Investigação e resposta

- Cinco cenários: autenticação, alteração de conta, PowerShell, integridade de arquivo e rede;
- Estudos de caso que registram ativo, evidência, classificação e ação recomendada;
- Playbooks para autenticação, PowerShell, FIM e rede, com aprovação humana e rollback;
- Registro que separa fato observado, inferência, decisão e pendência.

### Governança operacional

- Change control para telemetria e FIM: baseline, impacto, rollback e critérios de GO/NO-GO;
- Evidência Manager → Indexer → Discover tratada como requisito separado de testes sintéticos;
- Automação local para inventário, saúde e coleta de evidências, sem abrir a rede do laboratório.

## Evidência visual

As capturas abaixo são cópias redigidas e próprias para publicação. O Dashboard atual foi verificado em **10/11/2026** com três eventos FIM do smoke H03 visíveis no Discover; a tela original não é versionada porque contém identificadores do ambiente. O resultado e os limites estão no [checkpoint de H03](docs/m1-h03-change-c-activated-20261110.md).

| Endpoint Linux: FIM com trilha de integridade | Endpoint Windows: Sysmon em operação |
| --- | --- |
| [<img src="screenshots/redacted/kali-fim-redacted.png" alt="Evento FIM redigido no Kali" width="420" />](screenshots/redacted/kali-fim-redacted.png) | [<img src="screenshots/redacted/windows-sysmon-redacted.png" alt="Sysmon redigido no Windows" width="420" />](screenshots/redacted/windows-sysmon-redacted.png) |
| Alteração de arquivo monitorado, com evidência de integridade preservada. | Telemetria de processo preparada para investigação no endpoint Windows. |

Ver [critérios de sanitização](screenshots/README.md) e a [checklist de publicação segura](docs/publication-checklist.md).

## Cenários de detecção

| Cenário | Fontes principais | Resultado investigável | Valor para o SOC |
| --- | --- | --- | --- |
| Falhas de autenticação | SSH e logs nativos | Distinguir tentativa isolada de brute force | Reduzir escalonamento desnecessário |
| Alteração de conta | Auditd | Relacionar mudança, contexto e aprovação | Rastreabilidade de identidade |
| PowerShell benigno | Sysmon Event ID 1 | Examinar comando e processo-pai | Triagem de execução no Windows |
| Alteração de integridade | FIM | Preservar alteração e hashes antes/depois | Investigar mudança não autorizada |
| Conexão privada autorizada | Sysmon Event ID 3 | Avaliar processo, porta e destino | Diferenciar comunicação esperada de anomalia |

Consulte o [catálogo de detecções](docs/detection-catalog.md), a [matriz de telemetria](docs/telemetry-matrix.md) e a [cobertura MITRE ATT&CK](docs/mitre-coverage.md).

## Arquitetura do laboratório

```text
                          rede privada e isolada

  ┌──────────────────────┐       telemetria        ┌──────────────────────┐
  │ Endpoint Windows     │ ──────────────────────► │ Wazuh                │
  │ Event Channels       │                          │ Manager · Indexer    │
  │ Sysmon · FIM         │ ◄────────────────────── │ Dashboard            │
  └──────────────────────┘        configuração     └──────────┬───────────┘
                                                                 │
  ┌──────────────────────┐       telemetria                     │ investigação
  │ Endpoint Linux       │ ─────────────────────────────────────┘
  │ Logs · Auditd · FIM  │
  └──────────────────────┘
```

O acesso de gerenciamento ocorre em rede privada; não há demonstração pública das VMs, do Manager, do Indexer ou do Dashboard administrativo. Veja a [arquitetura](docs/architecture.md) e os [limites de exposição](docs/architecture-network-public-exposure-20261104.md).

## Estado e integridade da demonstração

**Atualizado em 10/11/2026.** As seis fases do roadmap original foram concluídas como entregas documentadas. O incremento M1 de hunting por hipóteses possui **15/17 itens verificados (88,2%)**. A validação recente confirmou o fluxo FIM do smoke H03 em Manager, Indexer e Discover, mas **as correlações reais completas H01/H02/H03 e a revisão independente ainda estão pendentes**. O gate global permanece bloqueado intencionalmente.

| Marco | Estado | Como é comprovado |
| --- | --- | --- |
| Fases base do laboratório | Concluídas | Arquitetura, telemetria, casos, playbooks e material sanitizado. |
| Automação e contratos offline | Verificados | Testes reproduzíveis para regras, escopo, correlação e gates. |
| Smoke FIM H03 | Verificado ponta a ponta | Mesmo conjunto de três eventos observado em Manager, Indexer e Discover. |
| Correlações reais H01/H02/H03 | Em aberto | Exigem fonte, identidade, janela temporal e controles negativos completos. |
| Aceite independente do M1 | Em aberto | Requer revisão de terceiro e evidência sanitizada. |

CI aprovado, simulação controlada ou um evento isolado não são apresentados como aceite operacional. Acompanhe o [painel de progresso](docs/roadmap-progress.md), o [roadmap](ROADMAP.md) e o [gate de evidências](docs/m1-evidence-gate.md).

## Qualidade verificável

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

Resultado local mais recente: **282 testes executados, 278 aprovados e 4 ignorados**. Os testes exercitam contratos de configuração, escopo por sistema operacional, correlação, gates de evidência e controles de segurança. Eles não acessam ou alteram as VMs.

Para uma verificação específica da configuração:

```powershell
.\scripts\validate_lab_config.ps1
```

## Como explorar o repositório

| Se você quer avaliar… | Comece por… |
| --- | --- |
| Estratégia, arquitetura e isolamento | [Arquitetura](docs/architecture.md) · [Inventário](docs/inventory.md) |
| Cobertura técnica e telemetria | [Matriz de telemetria](docs/telemetry-matrix.md) · [MITRE ATT&CK](docs/mitre-coverage.md) |
| Qualidade das detecções | [Catálogo](docs/detection-catalog.md) · [Testes](tests/) |
| Capacidade de investigação | [Estudos de caso](docs/case-study-timelines.md) · [Registro](docs/registro-de-investigacao.md) |
| Segurança de mudança e operação | [Playbooks](playbooks/) · [Gate de evidências](docs/m1-evidence-gate.md) |
| Evolução atual | [Painel de progresso](docs/roadmap-progress.md) |

## Estrutura

```text
config/       Regras locais, Sysmon e configurações de agentes
scripts/      Validadores, correlacionador e simuladores inofensivos
docs/         Arquitetura, evidências, detecções, governança e estudos de caso
cases/        Cenários de investigação documentados
playbooks/    Triagem e resposta com aprovação humana
tests/        Contratos e validações reproduzíveis
screenshots/  Somente capturas redigidas para portfólio
automation/   Inventário, saúde e coleta local de evidência
```

## Segurança e escopo ético

Todos os eventos são gerados exclusivamente em VMs próprias, isoladas e autorizadas. Não há malware, exploração, tentativa de acesso a terceiros ou automação de contenção destrutiva. Dados sensíveis, credenciais, endereços, hashes completos e evidências brutas permanecem fora do repositório.

---

Este projeto demonstra como eu contribuo em serviços de **SOC, threat hunting, engenharia de detecção, validação de telemetria e resposta orientada por evidências**: com rigor técnico, documentação auditável e comunicação objetiva para operação e gestão.
