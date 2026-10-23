# Post para LinkedIn — laboratório SOC com Wazuh

🚨 **SOC Lab com Wazuh: Windows Telemetry, FIM e Detection Engineering**

Construí um laboratório de monitoramento de segurança com Wazuh, VirtualBox, Kali Linux e Windows Server para praticar um fluxo real de SOC:

✅ Wazuh Manager, Indexer e Dashboard em Docker  
✅ Agente Windows ativo e integrado ao Manager  
✅ Coleta de Security, System, Application e PowerShell Operational  
✅ Evento real controlado no Windows, confirmado com `Get-WinEvent`  
✅ File Integrity Monitoring com criação e alteração de arquivo  
✅ Alerta `syscheck_integrity_changed` recebido no Manager  
✅ Comparação de hashes antes/depois da alteração  
✅ Regras próprias para brute force, comandos suspeitos, exfiltração e elevação de privilégio  

O projeto foi executado em ambiente isolado e autorizado, sem malware ou testes contra terceiros.

O principal aprendizado foi entender que monitoramento não termina na coleta do log: é preciso gerar evidência, investigar contexto, validar o alerta e documentar a decisão.

🔗 Case study completo no GitHub: https://github.com/raphaelguterres/artigo-seguranca/issues/1

#Wazuh #SOC #SIEM #CyberSecurity #BlueTeam #WindowsServer #FIM #DetectionEngineering #IncidentResponse #MITREATTACK
