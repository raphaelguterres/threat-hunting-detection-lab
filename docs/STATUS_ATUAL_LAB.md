# Status atual — Threat Hunting Detection Lab

Atualizado em 23/10/2026.

## Ambiente validado

| Componente | Estado | Evidência |
| --- | --- | --- |
| VM Windows Server | Online; sessão `Administrator` observada | Verificação pelo VirtualBox no health check mais recente |
| VM Kali / Wazuh | Online; sessão `kali` observada | Verificação pelo VirtualBox no health check mais recente |
| Sysmon no Windows | Instalado e ativo | `Sysmon64` com estado `Running` |
| Configuração Sysmon | Aplicada | Arquivo de configuração validado pelo Sysmon (schema 4.90) |
| FIM Windows → Wazuh | Funcionando | Evento `syscheck_integrity_changed` recebido no Kali para o arquivo de teste |

## Entregas concluídas no repositório

- Estrutura inicial do laboratório, roadmap e documentação de implantação.
- Configuração segura do Sysmon: `config/windows/sysmon-lab.xml`.
- Bloco de coleta de eventos Sysmon para o Wazuh: `config/windows/wazuh-sysmon-eventchannel.xml`.
- Plano de implantação e roteiro de validação: `docs/sysmon-deployment.md` e `tests/windows-sysmon-validation.md`.
- Matriz de cobertura MITRE ATT&CK: `docs/mitre-coverage.md`.
- Roadmap e issues do GitHub criados; a etapa atual é a Issue #2, **Windows telemetry / Sysmon**.
- Orquestrador local para inventário, saúde e coleta de evidências: `automation/orchestrate.ps1`.
- Inventário saneado das conexões: `artifacts/connection-inventory.md`.

## Ponto pendente para encerrar a etapa atual

O Sysmon já gera telemetria localmente, mas ainda falta confirmar a ingestão de seus eventos pelo Wazuh.

O ajuste necessário é adicionar ao `ossec.conf` do agente Windows o bloco abaixo, dentro de `<ossec_config>`, e reiniciar somente o serviço `WazuhSvc`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
  <only-future-events>yes</only-future-events>
</localfile>
```

Depois, gerar eventos benignos de validação para os IDs Sysmon 1 (criação de processo) e 11 (criação de arquivo), e confirmar sua chegada ao Wazuh. Somente após essa evidência a Issue #2 deve ser fechada.

## Observações operacionais

- O clipboard bidirecional foi configurado no VirtualBox, mas ainda não foi possível confirmar a publicação da versão dos Guest Additions pelas propriedades da VM. Isso não bloqueou a instalação nem a validação do Sysmon e do FIM.
- Uma interface host-only isolada foi adicionada às duas VMs sem alterar o NAT nem a rede interna. O WinRM HTTP do Windows responde nessa rede, mas a execução remota permanece bloqueada até haver autenticação segura; SSH ainda não está exposto no Kali.
- Capturas locais de validação não fazem parte do repositório e permanecem não rastreadas.
- Os modos `Health` e `Collect-Evidence` do orquestrador passaram usando somente consultas locais ao VirtualBox. A validação ponta a ponta permanece bloqueada até existir um canal de gerenciamento já autorizado e autenticado, ou até que a configuração seja comprovada no console local do Windows.
- O orquestrador distingue uma VM em execução (`PASS`) de uma VM desligada (`FAIL`), em vez de confundir uma consulta VirtualBox bem-sucedida com uma VM saudável.
