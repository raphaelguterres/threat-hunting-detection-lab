# Evidências reais de implantação — Wazuh

## Ambiente implantado

| Item | Implementação |
|---|---|
| Data de validação | 23/10/2026 (BRT) |
| Servidor Wazuh | VM Kali Linux no VirtualBox |
| Modelo | Wazuh Docker single-node, release `v4.14.9` |
| Componentes | Wazuh manager, Wazuh indexer e Wazuh dashboard |
| Recursos da VM do servidor | 8 GB de RAM, 2 vCPUs, 79 GB livres |
| Rede do servidor | NAT para atualizações + interface interna `rede-ad` |
| Endpoint Windows | Windows Server 2022 em rede privada isolada, com endereço reservado por DHCP |

## Validações realizadas

1. Docker, Docker Compose e Git foram instalados no Kali.
2. O repositório oficial `wazuh/wazuh-docker` foi obtido na versão `v4.14.9`.
3. Certificados locais foram gerados para o indexer, manager e dashboard.
4. O stack single-node foi iniciado e criou os volumes persistentes.
5. Os três containers foram validados como `Up` após reinício da VM:

   - `single-node-wazuh.indexer-1`
   - `single-node-wazuh.manager-1`
   - `single-node-wazuh.dashboard-1`

6. O OpenSearch atingiu estado `green` e o índice de alertas já continha **187 documentos** gerados pelo ambiente.
7. O dashboard respondeu em `https://localhost`; o certificado autoassinado foi aceito apenas na VM de laboratório.
8. Um agente Linux Dockerizado limpo foi registrado e confirmado como **Active** pelo Manager.
9. As quatro regras locais do case study foram copiadas para o Manager e o serviço foi reiniciado com sucesso.
10. A coleta de `/var/log/wazuh-lab/events.log` foi distribuída pelo Manager via `agent.conf`. Quatro eventos controlados foram processados e indexados: brute force (100100), comando suspeito (100101), possível exfiltração (100102) e elevação de privilégio (100103).
11. O FIM foi habilitado por configuração centralizada para `/opt/wazuh-lab/monitorado`. O log do agente confirma o diretório em monitoramento em tempo real, a varredura inicial e o início do módulo FIM.
12. O agente também executou uma avaliação SCA real com a política `sca_amazon_linux_2023.yml`; a execução foi concluída em 4 segundos.
13. A conectividade de camada 2 entre o servidor e o Windows Server foi validada com respostas ARP na rede interna isolada.
14. O Manager confirmou as portas necessárias do Wazuh. Após a restauração da interface interna e a correção da configuração do endpoint, o Windows apareceu como agente ativo. Um cadastro anterior que nunca conectou foi mantido somente como histórico de troubleshooting.
15. O agente Windows foi preparado para coletar os canais `Security`, `System`, `Application` e `Microsoft-Windows-PowerShell/Operational` via `eventchannel`. O serviço foi reiniciado e foi gerado um evento real no canal System (ID 501, fonte `WazuhLab`), confirmado pelo `Get-WinEvent`, além de uma execução PowerShell identificável.
16. Para o FIM, foi criado e alterado o arquivo `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\wazuh-fim-lab.txt`, diretório que já estava listado no bloco `<syscheck>` do agente Windows. A captura registra as duas operações `Set-Content` e `Add-Content`.
17. A validação ponta a ponta foi concluída: o `alerts.json` do Manager registrou o agente `004`, decoder `syscheck_integrity_changed`, caminho do arquivo Windows e os hashes `md5_before/md5_after`, `sha1_before/sha1_after` e `sha256_before/sha256_after`.

## Observação técnica sobre o teste FIM

Foram feitas duas alterações controladas em `configuracao.conf` e uma reinicialização do agente para solicitar nova varredura comparativa. Nesta topologia, o diretório monitorado está dentro do filesystem sobreposto de um contêiner Docker. Embora o agente tenha confirmado o monitoramento em tempo real, não houve alerta FIM correspondente no Manager durante a janela de validação.

Esse resultado foi mantido como evidência negativa, sem ser apresentado como detecção concluída. A próxima iteração transferirá o diretório monitorado para um endpoint Linux não conteinerizado ou para o Windows Server, onde a geração do alerta e os hashes poderão ser validados de ponta a ponta.

## Recuperação documentada

O primeiro boot do dashboard foi interrompido por um desligamento da VM enquanto o índice de interface `.kibana_1` ainda estava em migração. A investigação confirmou que esse índice tinha **0 documentos** e 208 bytes, enquanto os alertas estavam em `wazuh-alerts-4.x-2026.10.21`.

Foi removido exclusivamente o índice vazio de interface e o container do dashboard foi reiniciado. Os índices de alertas e telemetria foram preservados. Isso demonstra uma prática útil de troubleshooting: confirmar o alvo, separar metadados de dados de segurança e só então executar uma correção mínima.

## Capturas disponíveis

| Arquivo | O que comprova |
|---|---|
| `evidencias/certificados-wazuh.png` | Geração dos certificados do stack |
| `evidencias/wazuh-up-2.png` | Volumes e os três containers criados/iniciados |
| `evidencias/containers-pos-reinicio.png` | Persistência dos três containers após reinício |
| `evidencias/indices-opensearch.png` | Cluster em estado green e índice de alertas existente |
| `evidencias/dashboard-recuperado.png` | Dashboard Wazuh disponível em HTTPS local |
| `evidencias/agente-ativo.png` | Agente `wazuh-lab-linux` ativo, confirmado pelo Manager |
| `evidencias/regras-aplicadas-final.png` | Regras locais copiadas e reinicialização bem-sucedida do Manager |
| Captura redigida do agente Linux | Agente de reposição confirmado como Active |
| `evidencias/alerta-bruteforce-confirmado.png` | Alerta 100100 indexado, com agente, nível, descrição e `full_log` |
| `evidencias/contagem-alertas-personalizados.png` | Uma ocorrência indexada para cada regra 100101, 100102 e 100103 |
| `evidencias/servicos-validados-pos-sudo.png` | Os três serviços Wazuh e o agente recuperados após reinício do Kali |
| `evidencias/fim-log-agente.png` | FIM em tempo real configurado e avaliação SCA concluída no agente |
| `evidencias/fim-alteracao-real.png` | Alteração controlada realizada no arquivo de teste |
| `evidencias/fim-varredura-forcada.png` | Reinicialização do agente e nova tentativa de validação comparativa |
| `evidencias/diagnostico-rede-kali.png` | Endereçamento do Kali e portas Wazuh expostas pela VM de monitoramento |
| `evidencias/diagnostico-arp-windows.png` | Três respostas ARP do Windows Server na rede isolada `rede-ad` |
| Captura redigida do estado anterior | Registro do agente Windows antes da reconexão |
| Captura redigida do agente Windows | Agente Windows confirmado como `Active` no Manager |
| `evidencias/windows-folder-created.png` | Pasta de laboratório criada na VM Windows |
| `evidencias/windows-config-inspect.png` | Diretórios FIM existentes no `ossec.conf` |
| `evidencias/windows-security-config2.png` | Coleta do canal Security adicionada ao agente |
| `evidencias/windows-fim-folder.png` | Preparação do caminho de teste FIM |
| `evidencias/windows-evidence-fim-event.png` | Evento System 501 confirmado pelo `Get-WinEvent` e operações de criação/alteração do arquivo FIM |
| `evidencias/kali-alerts-agent004.png` | Manager registrando o alerta FIM do agente Windows 004 com hashes antes/depois |

## Próxima etapa do case study

O núcleo do case study está concluído: os agentes Linux e Windows estão ativos, eventos controlados foram coletados, as regras locais geraram alertas e os documentos foram indexados. Sysmon IDs 1 e 11 já foram confirmados no Manager e o FIM foi validado no Kali nativo com controle negativo. A próxima expansão é completar os casos nativos de autenticação, alteração de conta, PowerShell e rede, além das respectivas investigações ponta a ponta.
