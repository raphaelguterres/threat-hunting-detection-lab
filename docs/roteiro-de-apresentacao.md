# Roteiro de apresentação — 6 a 8 minutos

## 1. Contexto (40 segundos)

“Montei um laboratório de monitoramento de segurança com Wazuh para coletar eventos de endpoints, detectar comportamentos relevantes e documentar a investigação. O foco não é apenas gerar alertas; é demonstrar como eu chego a uma decisão.”

## 2. Arquitetura (50 segundos)

Mostre o desenho do README. Explique que o manager centraliza análise e visualização, enquanto os agentes enviam telemetria dos endpoints. Aponte o agente como **Active**.

## 3. Engenharia de detecção (1 minuto)

Abra `config/local_rules.xml` e diga:

“Além das regras nativas, criei quatro regras locais com IDs reservados ao laboratório. Cada uma traduz uma evidência em uma severidade e em grupos pesquisáveis: autenticação, execução, elevação de privilégio e possível perda de dados.”

## 4. Demonstração dos alertas (3 minutos)

Execute o simulador e, no Dashboard, filtre `rule.groups: lab`. Para cada alerta, responda em voz alta:

1. **O que aconteceu?**
2. **Em qual endpoint/usuário?**
3. **Por que a severidade faz sentido?**
4. **Que evidência eu validaria em seguida?**

Reserve alguns segundos para mostrar o evento de FIM. Esse é o contraste importante: a alteração vem de monitoramento de integridade, não da regra local.

## 5. Investigação (1 minuto)

Abra o registro preenchido e apresente a linha do tempo. Demonstre que um alerta de brute force isolado pode ser ruído, mas ganha prioridade se houver login bem-sucedido, execução suspeita ou tráfego externo no mesmo período.

## 6. Encerramento (30 segundos)

“O resultado foi um fluxo reproduzível: coletar, detectar, priorizar, investigar e recomendar uma ação. Em produção, eu integraria os alertas críticos ao processo de resposta a incidentes e revisaria as regras com base nos falsos positivos.”

## Perguntas que você já estará pronto para responder

- **Por que usar regra local?** Para adaptar a detecção ao contexto da organização e transformar sinais relevantes em alertas pesquisáveis.
- **Como reduzir falsos positivos?** Com limiares, listas de exceção justificadas, correlação e revisão periódica das regras.
- **O que faria diante de severidade 12?** Validaria imediatamente a evidência, preservaria logs, restringiria o risco conforme playbook e escalonaria para resposta a incidentes.
- **Como provar que o agente está funcionando?** Status Active, último keep-alive e eventos com o hostname do endpoint no Dashboard.
