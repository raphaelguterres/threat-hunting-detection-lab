# Sysmon no endpoint Windows de laboratório

## Objetivo

Adicionar telemetria de criação de processo, conexão de rede e criação de arquivo ao Windows Server isolado. A configuração inicial é deliberadamente pequena para medir volume e confirmar a coleta antes de criar regras de detecção.

## Arquivos do repositório

- `config/windows/sysmon-lab.xml`: configuração mínima de Sysmon.
- `config/windows/wazuh-sysmon-eventchannel.xml`: bloco de coleta do Wazuh.

## Pré-requisitos e segurança

- Executar somente no Windows Server da rede privada do laboratório.
- Antes de instalar, verificar se já há uma instalação Sysmon ativa e não manter duas instalações concorrentes.
- Baixar o binário exclusivamente da página oficial Microsoft Sysinternals.
- Conferir o esquema suportado pela versão baixada com `Sysmon64.exe -s`. Se necessário, ajustar `schemaversion` no XML antes de instalar.
- Criar snapshot da VM antes da mudança e registrar data, responsável e versão do binário.

## Procedimento

1. Copiar `sysmon-lab.xml` para uma pasta administrativa local, por exemplo `C:\Sysmon\sysmon-lab.xml`.
2. Em PowerShell elevado, instalar usando o XML:

   ```powershell
   .\Sysmon64.exe -accepteula -i C:\Sysmon\sysmon-lab.xml
   ```

3. Confirmar localmente eventos no Event Viewer em `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`.
4. Adicionar o bloco de `wazuh-sysmon-eventchannel.xml` ao `ossec.conf` do agente Windows ou à configuração centralizada do grupo de laboratório.
5. Reiniciar somente o serviço Wazuh Agent e confirmar que ele volta ao estado Active.
6. Executar o roteiro em `tests/windows-sysmon-validation.md` e guardar apenas capturas redigidas em `screenshots/`.

## Eventos esperados

| Evento Sysmon | Uso no laboratório | O que validar |
|---:|---|---|
| 1 — Process Create | PowerShell e processos benignos | Imagem, linha de comando, processo-pai e SHA-256. |
| 3 — Network Connect | Conexão autorizada entre VMs | Processo, origem, destino e porta. |
| 11 — File Create | Arquivo de teste | Caminho, processo e horário. |

## Rollback

Interromper a coleta no Wazuh removendo o bloco do `eventchannel` e reiniciando o agente. A remoção do Sysmon é uma mudança administrativa separada e deve ser feita apenas se a coleta não puder ser ajustada; preservar antes os eventos necessários para investigação.

## Fontes oficiais

- [Microsoft Sysinternals — Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [Microsoft Learn — habilitar e configurar Sysmon](https://learn.microsoft.com/windows/security/operating-system-security/sysmon/how-to-enable-sysmon)
- [Wazuh — coleta local por eventchannel](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
