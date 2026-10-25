# Laboratório Wazuh — Status Atual e Próxima Etapa

**Atualizado em:** 23/10/2026 (BRT)  
**Objetivo:** construir um case study de SOC para portfólio, com telemetria real, detecções próprias, investigação e evidências reproduzíveis.

## Resumo executivo

O núcleo do laboratório está funcional. O Wazuh foi implantado em uma VM Kali Linux no VirtualBox, com Manager, Indexer e Dashboard em containers. Um agente Linux real foi registrado, recebeu configuração centralizada do Manager e enviou eventos que geraram quatro alertas personalizados confirmados diretamente no OpenSearch.

O projeto já demonstra implantação, engenharia de detecção, gestão de agente, coleta de logs, validação em índice, FIM configurado e SCA executado. A próxima fase transforma o laboratório em um cenário mais próximo de uma operação SOC corporativa: endpoint Windows Server, eventos nativos do Windows, FIM ponta a ponta, posture management e correlação com MITRE ATT&CK.

## O que foi implantado

| Componente | Estado | Detalhe |
|---|---|---|
| Hypervisor | Operacional | VirtualBox |
| Servidor Wazuh | Operacional | Kali Linux, 8 GB RAM, 2 vCPUs |
| Wazuh Manager | Operacional | Container `single-node-wazuh.manager-1` |
| Wazuh Indexer | Operacional | OpenSearch em estado `green` |
| Wazuh Dashboard | Operacional | HTTPS local com certificado autoassinado |
| Agente Linux | Operacional | Agente ativo no Manager |
| FIM Linux | Validado ponta a ponta no Kali nativo | Agente `kali-native-fim` monitorando `/opt/wazuh-lab/monitorado`; regras 554 e 550 recebidas no Manager |
| SCA Linux | Executado | Política `sca_amazon_linux_2023.yml`, avaliação concluída em 4 segundos |
| Endpoint Windows Server 2022 | Operacional | Agente ativo; cadastro histórico sem conexão preservado apenas para troubleshooting |

## Evidências técnicas confirmadas

### 1. Infraestrutura e persistência

- Stack oficial `wazuh/wazuh-docker`, release `v4.14.9`.
- Certificados do ambiente gerados localmente.
- Manager, Indexer e Dashboard iniciados e validados após reinicialização da VM.
- Índice `wazuh-alerts-4.x-2026.10.21` disponível no OpenSearch.

### 2. Engenharia de detecção

Foram criadas e carregadas regras locais no Manager:

| ID | Nome lógico | Nível | Resultado validado |
|---:|---|---:|---|
| 100100 | `LAB_BRUTE_FORCE` | 10 | Alerta indexado com agente, severidade e `full_log` |
| 100101 | `LAB_SUSPICIOUS_COMMAND` | 9 | Uma ocorrência indexada |
| 100102 | `LAB_DATA_EXFIL` | 12 | Uma ocorrência indexada |
| 100103 | `LAB_PRIVILEGE_ESCALATION` | 11 | Uma ocorrência indexada |

Os eventos foram marcados explicitamente como `LAB_`, enviados pelo agente Linux e coletados por configuração centralizada via `agent.conf`. Não foram utilizados malware, credenciais reais ou ações contra terceiros.

### 3. Investigação aplicada

Durante a implantação ocorreu uma falha de migração do índice de interface `.kibana_1`, causada por desligamento durante o boot. O diagnóstico confirmou que era um índice de interface vazio; a recuperação removeu exclusivamente esse índice e preservou os dados de segurança. Esse caso é material de troubleshooting para a apresentação.

### 4. Postura e integridade no endpoint

- O Manager distribuiu a configuração FIM via `agent.conf` e o agente confirmou o monitoramento em tempo real de `/opt/wazuh-lab/monitorado`.
- Uma avaliação SCA foi executada pelo agente com a política disponível para a imagem Linux.
- Duas mudanças controladas foram feitas no arquivo monitorado. Não foi emitido um alerta FIM no Manager durante a validação; como o alvo reside em um contêiner, o resultado é tratado corretamente como limitação de laboratório, não como alerta demonstrado.

### 5. Integração Windows Server — diagnóstico de conectividade

- A VM Windows Server e a VM Kali foram conectadas à rede interna isolada `rede-ad`.
- O Windows e o servidor Wazuh usam endereços reservados em uma rede interna isolada.
- A validação ARP do Kali recebeu três respostas do MAC da interface interna do Windows (`08:00:27:7a:0d:b0`), comprovando conectividade de camada 2 entre as VMs.
- O Manager expõe as portas Wazuh `1514/TCP`, `1514/UDP` e `1515/TCP` em todas as interfaces do Kali.
- O endpoint Windows está conectado ao Manager e aparece como **Active**. Um cadastro anterior, criado na primeira configuração e sem conexão, não é usado como evidência do endpoint atual.
- O diagnóstico avançado identificou a perda da interface interna do servidor após reinicialização das VMs. A interface e o endereçamento privado foram restaurados, a conectividade voltou a responder e o Manager confirmou o agente Windows como **Active**.

### 6. Telemetria Windows e teste FIM

- O `ossec.conf` do agente foi ampliado com `eventchannel` para `Security`, `System`, `Application` e `Microsoft-Windows-PowerShell/Operational`.
- Foi gerado um evento real no canal System (ID 501, fonte `WazuhLab`) e confirmado com `Get-WinEvent`; a execução PowerShell de teste também foi registrada visualmente.
- O caminho FIM padrão do agente inclui o Startup do Windows; o arquivo `wazuh-fim-lab.txt` foi criado e alterado nesse diretório para produzir uma mudança real de integridade.
- A validação ponta a ponta foi concluída: o Manager registrou o alerta `syscheck_integrity_changed` do agente `004`, com caminho do arquivo Windows e hashes antes/depois. A captura está em `evidencias/kali-alerts-agent004.png`.

## Arquivos principais

- [README do laboratório](../README.md)
- [Evidências reais de implantação](evidencias-reais.md)
- [Regras locais](../config/local_rules.xml)
- [Registro de investigação](registro-de-investigacao.md)
- [Roteiro de apresentação](roteiro-de-apresentacao.md)
- [Texto para LinkedIn](../PORTFOLIO_LINKEDIN.md)
- Diretório `../evidencias/` com capturas da implantação e dos alertas.

## Próxima etapa — nível avançado

### Endpoint Windows Server 2022

1. Instalar e registrar o agente Wazuh no Windows Server da rede interna.
2. Confirmar a conexão do agente Windows já registrado após o reinício e salvar a evidência do estado **Active**.
3. Coletar canais `Security`, `System`, `Microsoft-Windows-PowerShell/Operational` e `Sysmon/Operational` quando disponível.
4. Gerar eventos seguros e reais: logon/logoff, falhas de autenticação controladas, criação e alteração de arquivo monitorado e execução de PowerShell inofensiva.

### Cobertura de segurança real

1. Repetir FIM em diretório de um endpoint não conteinerizado (preferencialmente Windows Server); alterar um arquivo e investigar hash, usuário e horário.
2. Registrar resultados de Security Configuration Assessment (SCA) e priorizar pelo menos três gaps de hardening.
3. Consultar vulnerabilidades detectadas pelo Wazuh e documentar risco, evidência e recomendação.
4. Mapear cada cenário às táticas MITRE ATT&CK: `T1110` (Brute Force), `T1059` (Command and Scripting Interpreter), `T1071/T1041` (Exfiltration over C2 channel, quando aplicável) e `T1548` (Abuse Elevation Control).

### Entregável final de currículo

O case study final deve conter uma arquitetura, uma matriz MITRE, capturas de alertas nativos e personalizados, um incidente completo com linha do tempo e um relatório de recomendações. Isso posiciona o projeto como demonstração prática de SOC Tier 1/2, engenharia de detecção e hardening — não apenas como instalação de ferramenta.

## Limites e segurança

Todos os testes ocorrem nas VMs isoladas do laboratório e usam eventos inofensivos e rastreáveis. Testes de exploração, malware, persistência ofensiva ou movimentação lateral não fazem parte deste projeto.

## Conclusão até aqui

O projeto já possui uma história técnica consistente para o portfólio: infraestrutura Wazuh em Docker, agente Linux, agente Windows ativo, regras de detecção próprias, coleta de Event Channels, evento Windows confirmado localmente e alerta FIM ponta a ponta com hashes antes/depois. A expansão recomendada é Sysmon e uma matriz MITRE mais detalhada.
