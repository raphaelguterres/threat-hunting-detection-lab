# Caso 05 — Conexão de rede inesperada

## Estado

Planejado. Não há ainda telemetria de rede de processo validada no Windows.

## Dependência

Instalar Sysmon apenas no Windows Server isolado, coletar `Microsoft-Windows-Sysmon/Operational` e validar um evento de conexão inofensivo antes de escrever qualquer regra de detecção.

## Hipótese

Uma conexão pode exigir investigação quando combina processo incomum, destino não aprovado, porta inesperada e ausência de mudança autorizada. Um endereço ou porta isolado não é evidência suficiente.

## Critério de conclusão

Documentar origem, destino, porta, processo, usuário, horário, evidência positiva, falso positivo esperado e decisão de triagem.
