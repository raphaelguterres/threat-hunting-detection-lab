# Telemetria Windows — execução do laboratório

## Objetivo

Demonstrar coleta de Event Channels, execução PowerShell e FIM em um Windows Server monitorado pelo Wazuh.

## Configuração aplicada

O agente Windows está ativo no Manager. O `ossec.conf` recebeu coletores `eventchannel` para:

- `Security`
- `System`
- `Application`
- `Microsoft-Windows-PowerShell/Operational`

O serviço `WazuhSvc` foi reiniciado depois da alteração.

## Eventos reproduzíveis

1. Um evento real foi criado no log `System` com `eventcreate`, fonte `WazuhLab`, ID `501` e mensagem `WAZUH_LAB_SYSTEM`.
2. O evento foi confirmado no próprio endpoint com `Get-WinEvent`.
3. Uma execução PowerShell com marcador `WAZUH-LAB-PowerShell-Event` foi realizada.
4. O arquivo `wazuh-fim-lab.txt` foi criado e alterado em `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`, diretório já monitorado pelo syscheck padrão do agente.

## Evidência

Veja `evidencias/windows-evidence-fim-event.png`. A imagem mostra o ID 501, provider `WazuhLab`, timestamp e a sequência de criação/alteração do arquivo FIM.

## Validação no Manager

Na Kali, consultar o agente e os alertas com privilégios administrativos:

```bash
sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
sudo docker exec single-node-wazuh.manager-1 sh -c "grep '004' /var/ossec/logs/alerts/alerts.json | tail -n 30"
```

O teste ponta a ponta foi confirmado: o Manager exibiu o agente `004` e o `alerts.json` registrou `syscheck_integrity_changed`, incluindo os hashes antes/depois do arquivo Windows.

## Conclusão desta etapa

O laboratório já demonstra um fluxo real de endpoint Windows: agente ativo, configuração de coleta, reinício do serviço, evento nativo confirmado no Event Viewer/PowerShell e alteração controlada em caminho monitorado pelo FIM. Isso é suficiente para apresentar implantação e geração de telemetria no portfólio.

### Próximas melhorias (opcionais)

1. Capturar o mesmo alerta pelo Dashboard para enriquecer a apresentação visual.
2. Ativar Sysmon para ampliar a cobertura de processos, rede e criação de processos.
3. Mapear os eventos nativos a técnicas MITRE ATT&CK.
