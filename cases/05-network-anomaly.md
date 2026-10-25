# Caso 05 — Conexão de rede inesperada

## Estado

Validado em 25/10/2026 no Windows isolado. Uma recarga controlada do painel HTTPS privado do Wazuh gerou eventos Sysmon ID 3 do `msedge.exe`, recebidos pelo Manager pela regra local `100105` (nível 3). Um período ocioso de 20 segundos não acrescentou eventos à contagem.

## Dependência

Sysmon deve estar instalado somente no Windows Server isolado e o canal `Microsoft-Windows-Sysmon/Operational` deve ser coletado pelo agente Wazuh.

## Hipótese

Uma conexão pode exigir investigação quando combina processo incomum, destino não aprovado, porta inesperada e ausência de mudança autorizada. Um endereço ou porta isolado não é evidência suficiente.

## Critério de conclusão

O evento validado contém processo (`msedge.exe`), protocolo TCP e porta HTTPS; destino e origem permanecem redigidos por serem dados internos do laboratório. A navegação foi autorizada e não representa atividade maliciosa.

## Triagem e falsos positivos

Navegadores podem abrir mais de uma conexão para carregar uma página. Portanto, uma sequência curta de eventos do mesmo processo durante uma única navegação é falso positivo esperado. A investigação deve confirmar processo, destino aprovado, porta, horário e existência de ação autorizada antes de elevar severidade.
