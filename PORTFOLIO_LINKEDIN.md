# Case study — Laboratório de Monitoramento de Segurança com Wazuh

![Capa do projeto — Laboratório SOC com Wazuh](evidencias/capa-laboratorio-wazuh.png)

## Visão geral

Desenvolvi um laboratório de Security Operations (SOC) com Wazuh para simular, detectar e investigar eventos de segurança em endpoints. O objetivo foi demonstrar um fluxo prático de monitoração: **coleta → detecção → triagem → investigação → recomendação**.

O ambiente usa agentes para enviar telemetria a uma central Wazuh. Além de recursos nativos, implementei regras locais para traduzir indicadores relevantes em alertas priorizados e pesquisáveis.

> **Nota de segurança:** todos os eventos foram simulados em ambiente isolado e autorizado. Nenhuma atividade foi realizada contra sistemas de terceiros.

## Problema

Ter logs não é suficiente: uma equipe de segurança precisa identificar eventos relevantes, compreender o contexto e decidir a ação apropriada. Este projeto demonstra esse processo em um cenário reproduzível.

## Arquitetura

```text
+---------------------------+        +-----------------------------+
| Wazuh manager             |        | Endpoint Linux              |
| - análise de eventos      |<-------| - Wazuh agent               |
| - regras locais           |  TLS   | - logs customizados         |
| - indexação e dashboard   |        | - File Integrity Monitoring |
+---------------------------+        +-----------------------------+
                                      | Endpoint Windows Server     |
                                      | - Event Channels            |
                                      | - PowerShell telemetry      |
                                      | - FIM em Startup             |
                                      +-----------------------------+
```

## Implementação técnica

- Central Wazuh (manager, indexação e dashboard);
- agente Linux com monitoramento de log customizado;
- File Integrity Monitoring (FIM) em diretório de configuração;
- quatro regras locais, com níveis de severidade entre 9 e 12;
- script de simulação segura e repetível;
- playbook de investigação com linha do tempo e recomendações.
- endpoint Windows Server ativo (agente `004`) com coleta de `Security`, `System`, `Application` e `PowerShell Operational`;
- evento System real (ID 501, fonte `WazuhLab`) e alteração controlada de arquivo em diretório FIM do Windows.

### Evidência de implantação

O ambiente foi implantado de fato em uma VM Kali Linux usando o stack oficial Wazuh Docker single-node. Manager, indexer e dashboard foram validados em execução, o cluster de indexação atingiu estado `green` e os alertas internos foram indexados. Consulte o [registro de evidências reais](docs/evidencias-reais.md).

## Casos de uso demonstrados

| Detecção | Severidade | Como investiguei | Decisão esperada |
|---|---:|---|---|
| Falhas repetidas de autenticação | 10 | usuário, origem, volume e sucesso posterior | validar brute force e restringir origem se necessário |
| Execução suspeita | 9 | usuário, endpoint, processo e comando | validar legitimidade e correlacionar com outros alertas |
| Alteração de integridade | nativa/FIM | alerta `syscheck_integrity_changed` confirmado no agente Windows 004, com hashes antes/depois | investigar hash, usuário e horário |
| Possível exfiltração | 12 | destino, protocolo, volume e dados envolvidos | preservar evidências e aplicar contenção conforme playbook |
| Elevação de privilégio | 11 | usuário, ação e contexto | confirmar necessidade e revisar privilégios |
| Evento Windows System | nativa | `Get-WinEvent`, provider, ID e mensagem | validar origem e contexto operacional |

## Evidências visuais

As três primeiras evidências abaixo foram capturadas no ambiente real. Antes de publicar, oculte IPs públicos, nomes de usuários reais, tokens e identificadores sensíveis.

### 1. Agente ativo

![Agente Wazuh ativo](evidencias/agente-limpo-ativo.png)

*Legenda: o agente do endpoint está conectado e apto a enviar telemetria.*

### 2. Detecções no dashboard

![Alertas personalizados indexados](evidencias/contagem-alertas-personalizados.png)

*Legenda: alertas locais criados para o laboratório, priorizados por nível de risco.*

### 3. Investigação de um alerta

![Detalhe do alerta de brute force simulado](evidencias/alerta-bruteforce-confirmado.png)

*Legenda: análise do alerta usando timestamp, endpoint, usuário, regra e log original.*

### 4. FIM e postura do endpoint

![FIM configurado e SCA executado no agente](evidencias/fim-log-agente.png)

*Legenda: o agente confirma FIM em tempo real; no Windows Server, a alteração controlada gerou alerta com hashes antes/depois no Manager.*

## Resultado e aprendizados

O projeto resultou em um laboratório reproduzível para demonstrar fundamentos de SOC: visibilidade de endpoints, engenharia de detecção, priorização de alertas e investigação baseada em evidências.

Meu principal aprendizado foi que uma boa detecção precisa de contexto operacional. Uma falha de login isolada pode ser ruído; a correlação com sucesso posterior, execução suspeita ou tráfego externo é o que muda a prioridade da investigação.

## Tecnologias

`Wazuh` · `Linux` · `SIEM` · `SOC` · `Log analysis` · `File Integrity Monitoring` · `Detection engineering` · `Incident response`

## Repositório e demonstração

Inclua aqui o link do repositório público depois de remover arquivos sensíveis e inserir as capturas. Para reproduzir o laboratório, consulte o [README.md](README.md).
