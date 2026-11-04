# Threat Hunting & Detection Lab — Wazuh

[![Validate lab configuration](https://github.com/raphaelguterres/threat-hunting-detection-lab/actions/workflows/validate-lab.yml/badge.svg)](https://github.com/raphaelguterres/threat-hunting-detection-lab/actions/workflows/validate-lab.yml)

Laboratório prático de **monitoramento, engenharia de detecção e investigação** com Wazuh. O ambiente usa uma VM Kali Linux como servidor Wazuh em Docker, um agente Linux e um Windows Server 2022 em rede privada isolada.

> Todos os eventos deste projeto são simulações inofensivas. Não há exploração, malware ou tentativa de acesso a sistemas de terceiros.

## Projeto principal: Segurança Defensiva

Este é o projeto principal deste repositório para demonstrar competências em **Security Operations (SOC)**, threat hunting, engenharia de detecção e resposta orientada por evidências. Ele conecta telemetria real de endpoints Windows e Linux ao Wazuh, mapeia comportamentos ao MITRE ATT&CK e documenta o processo analítico — da coleta à decisão de triagem.

O foco não é gerar alertas em massa: é provar que cada alerta pode ser investigado com contexto, hipótese, evidência, decisão e próximos passos reproduzíveis.

## M1 — Evolução de Threat Hunting (02/11/2026)

**Escopos e diagramas:** [mapa do M1, fluxo de evidências H03 e gate de teste benigno (Mermaid)](docs/m1-scope-and-h03-diagrams-20261104.md). [Pré-gate do artefato H03](docs/m1-h03-artifact-coverage-preflight-20261104.md). [Risco confirmado: diretiva realtime na pasta Startup — NO-GO para teste executável](docs/m1-h03-startup-realtime-no-go-20261104.md). **M1 11/17 (64,7%); implantação BLOCKED**, sem aprovação para alterar o laboratório.

Foi iniciado um incremento **separado dos cinco casos históricos**, com [três hipóteses de investigação](docs/m1-three-hunting-hypotheses.md): PowerShell seguido de tarefa agendada, criação de conta seguida de sessão privilegiada e alteração FIM seguida da execução do artefato. O [correlacionador Python offline](scripts/hunt_correlations.py) testa sequências com janelas temporais, chaves pseudonimizadas e controles negativos. Os testes em [fixtures sintéticas](tests/fixtures/m1-synthetic.jsonl) não representam detecções reais nem incidentes.

**Estado: implementação e validação sintética concluídas; auditoria real limitada em andamento.** O [plano de change control 4698 + revisão FIM do agente 004](docs/m1-change-control-4698-fim-agent004.md) está **preparado**, com baseline e rollback privados, mas nenhuma alteração de auditoria foi aplicada. O segundo pré-check confirmou **Security circular de 20 MB**, dois coletores `eventchannel` Security locais e uma [diretiva FIM centralizada Unix incompatível com caminho Windows](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17). A etapa posterior comprovou que ela foi distribuída pelo **único grupo `default`**, com hash igual e agente 004 sincronizado. Uma [proposta de correção OS-scoped](docs/m1-fim-os-scoped-remediation-plan.md), testes de caminhos por SO e **um guard de diferença mínima entre original e proposta** estão documentados; **a proposta de escopo Linux foi aprovada pelo verificador oficial Wazuh em cópia isolada e removida**, mas a **implantação real ainda aguarda aprovação**, assim como a ativação 4698. A [revisão read-only de 02/11](docs/m1-native-windows-wazuh-visibility-review-20261102.md) confirmou disponibilidade de fontes, uma lacuna na auditoria de criação de tarefas, ausência de vínculo H02 no recorte de 30 minutos e ausência de FIM recente do agente 004. **Nenhuma hipótese foi comprovada como incidente ou correlação operacional completa.** No Windows, execute [scripts/M1_THREAT_HUNTING.bat](scripts/M1_THREAT_HUNTING.bat) para rodar testes e demonstração sintética com um duplo clique; a opção de arquivo privado só fica disponível após normalização autorizada sob .lab. [Issue de acompanhamento](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9). Nenhuma nova simulação nas VMs ou alteração no Wazuh foi necessária.

### Segurança do M1: evidências antes de implantação

O [gate de evidências M1](docs/m1-evidence-gate.md) confere a completude declarada do inventário dos quatro agentes, revisão de impacto, backup real, rollback e aprovações, **sem acesso às VMs e sem autorizar deploy**. Consulte também a [matriz de aceitação FIM por OS](docs/m1-fim-acceptance-matrix.md), o [roteiro manual de conciliação 4/4 no Wazuh Dashboard](docs/m1-agent-inventory-operator-runbook.md) e a prévia offline do impacto do seletor Linux antes da revisão humana. Ausência de evidência retorna erro; o estado operacional permanece bloqueado até revisão independente.

## O que este laboratório demonstra

- Arquitetura manager + agentes Linux/Windows reais;
- coleta de logs e File Integrity Monitoring (FIM);
- criação de regras locais no Wazuh;
- priorização por severidade e investigação no dashboard;
- registro de evidências e recomendações de contenção.

## Estado atual

- Wazuh Manager, Indexer e Dashboard operacionais em Docker;
- agente Linux ativo, com telemetria nativa de autenticação, auditoria e FIM validada;
- agente Windows Server ativo, com coleta de Event Channels configurada;
- FIM ponta a ponta validado no Windows, incluindo hashes antes/depois;
- Sysmon instalado no Windows; ingestão dos IDs 1, 3 e 11 validada no Wazuh;
- cinco estudos de caso com linhas do tempo e controles negativos documentados;
- playbooks de autenticação, PowerShell, FIM e rede com aprovação humana e rollback;
- rede host-only isolada para gerenciamento das VMs, sem port forwarding público;
- evidências e limitações documentadas, sem apresentar simulações como incidentes reais.

Veja o [inventário](docs/inventory.md), a [arquitetura](docs/architecture.md), a [matriz de telemetria](docs/telemetry-matrix.md), o [catálogo de detecções](docs/detection-catalog.md), a [cobertura MITRE](docs/mitre-coverage.md), a [triagem de T1078/T1021](docs/mitre-triage-t1078-t1021.md), os [estudos de caso](docs/case-study-timelines.md), os [playbooks](playbooks/), a [checklist de publicação](docs/publication-checklist.md) e a [saúde operacional](docs/operational-health.md).

## Progresso e próximos marcos

A decisão [sobre o agente histórico `001`](docs/m1-legacy-agent-001-decision.md) e o [pacote de aprovação FIM](docs/m1-fim-change-approval-package.md) distinguem a conciliação técnica da autorização operacional. O grupo `default` tem quatro membros identificados, mas o `001` permanece desconectado; **não há liberação para implantar**.


O [checkpoint offline consolidado M1](docs/m1-checkpoint-offline.md) reúne os dados privados de inventário preliminar, gate e checklist sem exibir IPs, hostnames ou IDs. Execute `python scripts/m1_checkpoint_summary.py`; o resultado **nunca autoriza mudanças operacionais**.


A [revisão independente do PR M1](docs/m1-pr-review-guide.md) é organizada por módulos (inventário privado, FIM, hunting, CI e documentação). CI aprovado não equivale a code review ou autorização de mudança no Wazuh.


O [painel atualizado do roadmap](docs/roadmap-progress.md) separa as seis fases históricas concluídas do M1 ainda em andamento, lista as entregas pendentes e documenta o gate operacional **NO-GO**. A contagem de checkboxes é reproduzível localmente com `python scripts/roadmap_progress.py` e não equivale a aprovação de implantação.

## Arquitetura

```text
Internet / rede de testes
          |
  +----------------------+       +------------------------+
  | VM Wazuh             |<------| Ubuntu endpoint        |
  | manager + indexer +  | agent | logs, FIM, auditoria   |
  | dashboard            |       +------------------------+
  +----------------------+       +------------------------+
             ^                   | Windows endpoint       |
             |                   | agent + Event Channel  |
             +-------------------+ eventos de autenticação |
                                 +------------------------+
```

O ambiente implantado inclui os dois endpoints. Endereços, nomes de host e demais dados que possam identificar o ambiente não devem ser expostos em publicações externas.

## Roteiro de implantação

1. Instale o Wazuh manager/dashboard e registre ao menos um agente conforme a documentação oficial: https://documentation.wazuh.com/
2. No **manager**, copie `config/local_rules.xml` para `/var/ossec/etc/rules/local_rules.xml` e reinicie o serviço:

   ```bash
   sudo systemctl restart wazuh-manager
   ```

3. No agente Linux, crie os diretórios e copie o trecho de `config/ossec-agent-linux.xml` para o seu `/var/ossec/etc/ossec.conf` (dentro de `<ossec_config>`).
4. Reinicie o agente:

   ```bash
   sudo systemctl restart wazuh-agent
   ```

5. Execute `scripts/simular_eventos_linux.sh` como administrador no endpoint Linux.
6. No Dashboard, filtre por `rule.groups: lab` ou pelos IDs `100100` a `100103`.
7. Siga e preencha [docs/registro-de-investigacao.md](docs/registro-de-investigacao.md). O roteiro de fala está em [docs/roteiro-de-apresentacao.md](docs/roteiro-de-apresentacao.md).

Para validações reproduzíveis, use os roteiros de [Sysmon no Windows](tests/windows-sysmon-validation.md), [FIM Linux](tests/linux-fim-validation.md) e o [checklist de qualidade de detecção](tests/detection-quality-gate.md).

## Cenários demonstrados

| Cenário | Evidência coletada | Alerta | Valor demonstrado |
|---|---|---:|---|
| Autenticação | SSH nativo no Kali | 5710 / nível 5 | separar tentativa isolada de brute force |
| Alteração de conta | Auditd no Kali | 100104 / nível 8 | correlacionar mudança e aprovação |
| PowerShell benigno | Sysmon ID 1 no Windows | 92027 / nível 4 | analisar comando e processo-pai |
| Integridade de arquivo | FIM nativo no Kali | 554 e 550 | preservar hashes antes/depois |
| Conexão privada autorizada | Sysmon ID 3 no Windows | 100105 / nível 3 | validar processo, porta e destino aprovado |

## Evidências para portfólio

O repositório não versiona capturas brutas. Antes de publicar, selecione capturas redigidas conforme a [checklist de publicação](docs/publication-checklist.md): agente ativo, um alerta Sysmon, uma alteração FIM com hashes e uma linha do tempo concluída.

| Evidência redigida | Finalidade |
| --- | --- |
| ![Evento FIM redigido](screenshots/redacted/kali-fim-redacted.png) | Demonstrar que o fluxo FIM chegou ao ambiente de monitoramento sem publicar hashes, usuários ou caminhos completos. |
| ![Sysmon redigido](screenshots/redacted/windows-sysmon-redacted.png) | Demonstrar a instalação e o serviço Sysmon ativo no endpoint Windows isolado. |

## Critério de sucesso

O laboratório está pronto para apresentação quando os quatro alertas de regra local aparecem no dashboard, o FIM registra a mudança de `configuracao.conf` e você consegue responder: **o que ocorreu, em qual ativo, qual a criticidade, que evidência sustenta a conclusão e qual ação é recomendada**.

## Estrutura

```text
config/       Configuração do agente e regras do manager
scripts/      Simuladores controlados de eventos
docs/         Arquitetura, inventário, telemetria, detecções e playbooks
cases/        Estudos de caso e linhas do tempo
playbooks/    Guias de triagem e resposta com aprovação humana
evidencias/  Capturas e validações do ambiente
```

## Segurança

Todos os testes ocorrem exclusivamente nas VMs próprias e isoladas. Os simuladores não fazem exploração, não usam malware nem tentam acessar sistemas de terceiros. Qualquer contenção permanece em modo de observação ou exige aprovação humana.
