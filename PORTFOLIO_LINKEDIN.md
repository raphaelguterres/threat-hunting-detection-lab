# Case study — Laboratório de Monitoramento de Segurança com Wazuh

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
- regras locais de laboratório e telemetria nativa validada;
- script de simulação segura e repetível;
- playbook de investigação com linha do tempo e recomendações.
- endpoint Windows Server ativo com coleta de `Security`, `System`, `Application`, PowerShell e Sysmon;
- Sysmon IDs 1, 3 e 11 e FIM Windows/Kali validados de ponta a ponta.

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

Use somente capturas redigidas selecionadas pela [checklist de publicação](docs/publication-checklist.md). O repositório evita incorporar capturas brutas para reduzir o risco de expor dados do laboratório.

## Resultado e aprendizados

O projeto resultou em um laboratório reproduzível para demonstrar fundamentos de SOC: visibilidade de endpoints, engenharia de detecção, priorização de alertas e investigação baseada em evidências.

Meu principal aprendizado foi que uma boa detecção precisa de contexto operacional. Uma falha de login isolada pode ser ruído; a correlação com sucesso posterior, execução suspeita ou tráfego externo é o que muda a prioridade da investigação.

## Tecnologias

`Wazuh` · `Linux` · `SIEM` · `SOC` · `Log analysis` · `File Integrity Monitoring` · `Detection engineering` · `Incident response`

## Repositório e demonstração

Repositório: [threat-hunting-detection-lab](https://github.com/raphaelguterres/threat-hunting-detection-lab). Para reproduzir o laboratório, consulte o [README.md](README.md).
