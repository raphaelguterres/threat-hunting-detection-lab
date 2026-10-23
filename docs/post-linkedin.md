# Post pronto para LinkedIn

## Versão principal

Concluí um laboratório de monitoramento de segurança com **Wazuh** para colocar em prática um fluxo que faz parte da rotina de um SOC: coletar eventos, detectar comportamentos relevantes, investigar evidências e recomendar uma resposta.

No projeto, configurei a monitoração de um endpoint Linux, utilizei o File Integrity Monitoring (FIM) e criei regras locais para detectar cenários simulados de:

- falhas repetidas de autenticação;
- execução suspeita;
- alteração de arquivo monitorado;
- possível exfiltração de dados;
- elevação de privilégio.

O foco não foi apenas fazer alertas aparecerem no dashboard. Para cada cenário, documentei o que observar: ativo envolvido, usuário, origem, severidade, log original, correlação com outros eventos e ação recomendada.

Esse exercício reforçou para mim que detecção sem contexto gera ruído. O valor está em transformar o evento em uma decisão de segurança baseada em evidências.

Todos os eventos foram simulados em um ambiente isolado e autorizado.

Estou aberto a feedbacks de profissionais da área sobre regras, triagem e boas práticas de investigação.

#Wazuh #CyberSecurity #SOC #SIEM #BlueTeam #InfoSec #Linux #SecurityOperations

---

## Texto curto para o destaque do projeto

Laboratório prático de SOC com Wazuh: coleta de logs de endpoint, regras de detecção próprias, File Integrity Monitoring e investigação documentada de cenários simulados de autenticação, execução suspeita, privilégio e possível exfiltração.

---

## Ordem recomendada do carrossel/imagens

1. Use `evidencias/capa-laboratorio-wazuh.png` como capa e aplique o título: **Laboratório SOC com Wazuh**.
2. Diagrama simples da arquitetura.
3. Dashboard com alertas filtrados.
4. Detalhe de um alerta, com campos importantes destacados.
5. Evento de FIM e conclusão: **detectar → investigar → responder**.
