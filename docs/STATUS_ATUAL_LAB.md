# Status atual — Threat Hunting Detection Lab

Atualizado em 24/10/2026.

## Ambiente validado

| Componente | Estado | Evidência |
| --- | --- | --- |
| VM Windows Server | Online; sessão `Administrator` observada | Verificação pelo VirtualBox no health check mais recente |
| VM Kali / Wazuh | Online; sessão `kali` observada | Verificação pelo VirtualBox no health check mais recente |
| Sysmon no Windows | Instalado e ativo | `Sysmon64` com estado `Running` |
| Configuração Sysmon | Aplicada | Arquivo de configuração validado pelo Sysmon (schema 4.90) |
| Coleta Sysmon no agente Wazuh | Configurada e agente online | Canal `Microsoft-Windows-Sysmon/Operational` presente no `ossec.conf`; agente conectou ao Manager após a reinicialização |
| Evento Sysmon de validação local | Gerado | Sysmon Event ID 11 confirmou criação de arquivo pelo `wazuh-agent.exe` após ativar a coleta |
| FIM Windows → Wazuh | Funcionando | Evento `syscheck_integrity_changed` recebido no Kali para o arquivo de teste |
| Guest Additions | Instalados nas duas VMs | Propriedades do VirtualBox confirmam os componentes e versões instalados |

## Entregas concluídas no repositório

- Estrutura inicial do laboratório, roadmap e documentação de implantação.
- Configuração segura do Sysmon: `config/windows/sysmon-lab.xml`.
- Bloco de coleta de eventos Sysmon para o Wazuh: `config/windows/wazuh-sysmon-eventchannel.xml`.
- Plano de implantação e roteiro de validação: `docs/sysmon-deployment.md` e `tests/windows-sysmon-validation.md`.
- Matriz de cobertura MITRE ATT&CK: `docs/mitre-coverage.md`.
- Roadmap e issues do GitHub criados; a etapa atual é a Issue #2, **Windows telemetry / Sysmon**.
- Orquestrador local para inventário, saúde e coleta de evidências: `automation/orchestrate.ps1`.
- Inventário saneado das conexões: `artifacts/connection-inventory.md`.

## Etapa Windows / Sysmon concluída

O Sysmon gera telemetria localmente, o coletor foi adicionado ao `ossec.conf` e o agente Windows está online no Manager. O Manager registrou 36 alertas do canal `Microsoft-Windows-Sysmon/Operational` para o agente `004`, incluindo IDs 1 e 11. A evidência foi consultada em `alerts.json` em 24/10/2026.

O bloco ativo no agente é:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
  <only-future-events>yes</only-future-events>
</localfile>
```

O ID 11 foi confirmado localmente e no Manager; o ID 1 também foi recebido no Manager. A Issue #2 pode ser encerrada. A próxima etapa do roadmap é validar FIM Linux fora do filesystem de contêiner.

## Observações operacionais

- Os Guest Additions foram confirmados pelas propriedades das duas VMs. O clipboard bidirecional permanece um recurso auxiliar, não um requisito de coleta ou validação.
- Uma interface host-only isolada foi adicionada às duas VMs sem alterar o NAT nem a rede interna. O WinRM HTTP do Windows responde nessa rede, mas a execução remota permanece bloqueada até haver autenticação segura; SSH ainda não está exposto no Kali.
- Capturas locais de validação não fazem parte do repositório e permanecem não rastreadas.
- Os modos `Health` e `Collect-Evidence` do orquestrador passaram usando somente consultas locais ao VirtualBox. A validação ponta a ponta permanece bloqueada até existir um canal de gerenciamento já autorizado e autenticado, ou até que a configuração seja comprovada no console local do Windows.
- O orquestrador distingue uma VM em execução (`PASS`) de uma VM desligada (`FAIL`), em vez de confundir uma consulta VirtualBox bem-sucedida com uma VM saudável.
