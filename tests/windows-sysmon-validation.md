# Validação da telemetria Sysmon

## Pré-condições

- Sysmon instalado com `config/windows/sysmon-lab.xml` no Windows Server isolado.
- Wazuh Agent em estado Active.
- Canal `Microsoft-Windows-Sysmon/Operational` configurado no agente.
- Horários do endpoint e do servidor sincronizados.

## Teste 1 — Criação de processo

1. Abrir uma nova janela PowerShell no endpoint e executar `Write-Output WAZUH-LAB-PS`.
2. Confirmar localmente um evento Sysmon ID 1.
3. Localizar no Wazuh o evento do canal Sysmon e registrar horário, imagem, linha de comando e processo-pai.

**Aprovação:** a regra 100106 do Wazuh contém imagem, linha de comando, usuário e processo-pai. O marcador é inofensivo e não deve ser classificado como malicioso.

## Teste 2 — Criação de arquivo

1. Criar um arquivo de texto em diretório de teste não crítico.
2. Confirmar localmente um evento Sysmon ID 11.
3. Localizar o evento no Wazuh e comparar caminho e horário.

**Aprovação:** o evento chega ao Wazuh com caminho e processo associados.

## Teste 3 — Conexão de rede autorizada

1. Definir antes um serviço autorizado na rede privada do laboratório e documentar destino e porta.
2. Realizar uma única conexão de teste para esse serviço.
3. Confirmar localmente um evento Sysmon ID 3 e localizar a cópia no Wazuh.

**Aprovação:** processo, origem, destino, porta e horário permitem reconstruir a conexão. Não utilizar destinos externos ou não autorizados.

## Evidências e encerramento

Para cada teste, registrar resultado positivo ou negativo, consulta usada no Wazuh, captura redigida e qualquer impacto de volume. Abrir ajuste de configuração se a coleta gerar ruído desproporcional.

## Registro da operação atual

O Sysmon foi confirmado instalado e em execução no Windows. Os IDs 1 e 11 chegaram ao Manager e a conexão controlada do Edge validou o ID 3 em 25/10/2026. O único teste pendente desta matriz é a execução PowerShell identificada pelo marcador `WAZUH-LAB-PS`.

O orquestrador local pode ser usado para verificar o estado das VMs sem abrir rede:

```powershell
.\automation\orchestrate.ps1 -Mode Health
.\automation\orchestrate.ps1 -Mode Validate-Sysmon -WhatIf
```
