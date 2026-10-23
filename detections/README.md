# Detecções

As regras locais já validadas permanecem em [`../config/local_rules.xml`](../config/local_rules.xml). Novas regras específicas devem ficar em `windows/` ou `linux/` com uma referência cruzada para o teste correspondente.

Não adicionar regras baseadas em Sysmon antes de validar a coleta do canal `Microsoft-Windows-Sysmon/Operational`.
