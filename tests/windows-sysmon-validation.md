# Validação da telemetria Sysmon

## Pré-condições

- Sysmon instalado com `config/windows/sysmon-lab.xml` no Windows Server isolado.
- Wazuh Agent em estado Active.
- Canal `Microsoft-Windows-Sysmon/Operational` configurado no agente.
- Horários do endpoint e do servidor sincronizados.

## Teste 1 — Criação de processo

1. Abrir uma nova janela PowerShell no endpoint e executar um comando inofensivo, como `Get-Date`.
2. Confirmar localmente um evento Sysmon ID 1.
3. Localizar no Wazuh o evento do canal Sysmon e registrar horário, imagem, linha de comando e processo-pai.

**Aprovação:** o evento no Wazuh corresponde ao evento local e não é tratado como alerta malicioso apenas pela existência de PowerShell.

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
