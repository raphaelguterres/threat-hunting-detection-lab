# Threat Hunting & Detection Lab — Wazuh

Laboratório prático de **monitoramento, engenharia de detecção e investigação** com Wazuh. O ambiente usa uma VM Kali Linux como servidor Wazuh em Docker, um agente Linux e um Windows Server 2022 em rede privada isolada.

> Todos os eventos deste projeto são simulações inofensivas. Não há exploração, malware ou tentativa de acesso a sistemas de terceiros.

## O que este laboratório demonstra

- Arquitetura manager + agentes Linux/Windows reais;
- coleta de logs e File Integrity Monitoring (FIM);
- criação de regras locais no Wazuh;
- priorização por severidade e investigação no dashboard;
- registro de evidências e recomendações de contenção.

## Estado atual

- Wazuh Manager, Indexer e Dashboard operacionais em Docker;
- agente Linux ativo com quatro alertas de regras locais validados;
- agente Windows Server ativo, com coleta de Event Channels configurada;
- FIM ponta a ponta validado no Windows, incluindo hashes antes/depois;
- evidências e limitações documentadas, sem apresentar simulações como incidentes reais.

Veja o [inventário](docs/inventory.md), a [arquitetura](docs/architecture.md), a [matriz de telemetria](docs/telemetry-matrix.md), o [catálogo de detecções](docs/detection-catalog.md) e a [cobertura MITRE ATT&CK](docs/mitre-coverage.md).

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

## Cenários demonstrados

| Cenário | Evidência coletada | Alerta | Valor demonstrado |
|---|---|---:|---|
| Tentativas repetidas de login | linha de log simulada | 100100 / nível 10 | exercício de triagem de autenticação |
| Execução suspeita | linha de log simulada | 100101 / nível 9 | detecção e contexto de processo/comando |
| Alteração de arquivo crítico | FIM em diretório monitorado | nativo do Wazuh | integridade e trilha de auditoria |
| Indicador de exfiltração | linha de log simulada | 100102 / nível 12 | exercício de priorização de incidente |
| Elevação indevida | linha de log simulada | 100103 / nível 11 | detecção de abuso de privilégio |

## Evidências para a entrega

Capture uma tela por item, sem expor IPs públicos, senhas ou tokens:

1. Agente como **Active** no Wazuh.
2. Regra local carregada (alerta com `rule.id` e `rule.description`).
3. Detalhe do alerta: timestamp, agente, severidade e `full_log`.
4. Evento de integridade mostrando arquivo antes/depois (ou hash, se habilitado).
5. O registro de investigação preenchido, incluindo decisão e recomendação.

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
