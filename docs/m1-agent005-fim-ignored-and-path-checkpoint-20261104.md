# M1 — agente Linux 005: FIM efetivo exibido, exclusões e existência dos caminhos

**Checkpoint:** 04/11/2026, aproximadamente 22h52–22h55 BRT. **Escopo:** `M1-FIM-OS-SCOPE` (mudança A), diagnóstico read-only do agente `005`. **Decisão:** `NO-GO` para implantação; `DEPLOYMENT_GATE=BLOCKED`.

## Evidência visual autenticada no Dashboard

O operador abriu a página e a aba **Ignored** manualmente. A inspeção remota obteve a tela `Endpoints → kali-native-fim (005) → Configuration → Integrity monitoring` no Wazuh 4.14.9, com grupo `default`, sem operações de edição.

| Aba | Dado observado | Interpretação |
| --- | --- | --- |
| **General** | FIM `enabled`; frequência `43200` segundos; `scan on start=yes` | O Syscheck está habilitado para o agente exibido |
| **Monitored** | Sete diretórios: `/bin`, `/boot`, `/etc`, `/opt/wazuh-lab/monitorado`, `/sbin`, `/usr/bin`, `/usr/sbin` | FIM local padrão e diretiva de grupo presentes na **configuração exibida** |
| **Monitored**, item `/opt/wazuh-lab/monitorado` | `realtime=yes`, `whodata=no`; MD5/SHA1/SHA256 `yes` | O destino Linux de laboratório está declarado como realtime |
| **Ignored**, paths | 12 entradas, todas dentro de `/etc`: `/etc/mtab`, `/etc/hosts.deny`, `/etc/mail/statistics`, `/etc/random-seed`, `/etc/random.seed`, `/etc/adjtime`, `/etc/httpd/logs`, `/etc/utmpx`, `/etc/wtmpx`, `/etc/cups/certs`, `/etc/dumpdates`, `/etc/svc/volatile` | **Nenhuma exclusão de caminho para `/opt/wazuh-lab/monitorado`** |
| **Ignored**, Sregex | Padrões para extensões de arquivo `.log` e `.swp` | Evitar esses nomes nos futuros controles positivos; filtro **não corresponde ao caminho do diretório** |
| **Existência física, leitura de host 005** | `test -d /opt/wazuh-lab/monitorado` retornou exit **0** | O caminho existe no filesystem Kali nativo |
| **Existência física, contêiner 002** | `docker exec wazuh-lab-agent-clean test -d /opt/wazuh-lab/monitorado` retornou exit **0** | O mesmo caminho existe no filesystem do agente Linux containerizado |
| **Parser ativo Manager** | `verify-agent-conf: OK` | Configuração central **ativa** aceita pelo parser |
| **Eventos FIM reais e ingestão por agente** | **Não observados neste checkpoint** | **Não afirmar validação ponta a ponta** |

A tela **Configuration** apresentada pelo Wazuh é a visão de configuração do agente, que pode **combinar parâmetros locais e de grupo**. A atribuição da diretiva `/opt/wazuh-lab/monitorado` à configuração central está corroborada pela leitura independente de `default/agent.conf` no Manager. **Esta consulta não equivale à leitura privilegiada do arquivo local `/var/ossec/etc/ossec.conf` do Kali nativo**, que segue inacessível à conta SSH remota atual. O Dashboard permite revisar diretórios e exclusões exibidos, mas não prova distribuição após uma futura mudança nem eficácia de alerta.

## Ponto de atenção adicional: relógios

Uma comparação read-only delimitada por leituras do relógio UTC do host Windows antes e depois da consulta Kali indicou **aproximadamente +22 segundos do Kali em relação ao host**, sem atraso perceptível na chamada. Não foram coletadas outras fontes de tempo para investigar a origem do desvio. Os timestamps brutos ficam exclusivamente na saída privada do diagnóstico. **Não alterar o relógio** nesta mudança A sem escopo próprio. Confirmar sincronismo e timezone de Manager, Indexer e agentes antes da coleta de evidências com correlação temporal, especialmente H03.

## Decisão e próximos gates

- **Concluído tecnicamente neste checkpoint:** visualização de **General + Monitored + Ignored do agente 005**, exclusões relevantes, diretiva de grupo realtime e existência física do caminho em **005 e 002**.
- **Concluído anteriormente:** inventário de três agentes `002/004/005` no grupo `default`; SHA/backup real de `default/agent.conf` com rollback isolado; parser da candidata `os="^Linux"` `OK` em arquivo temporário e CI 3/3 no SHA anterior.
- **Pendente de atestado:** owner revisa os registros, impacto do bloco inteiro (**FIM + `localfile` Unix**), precedente local, backup/rollback e requisitos de aprovação.
- **Pendente técnico:** confirmar sincronização mais recente dos três agentes por método autorizado; investigar o desvio de relógio de ~22 s; pós-change requer FIM Linux real, preservação do Windows 004 e ingestão Manager→Indexer→Dashboard.
- **Controle de acesso:** leitura direta do `ossec.conf` local Kali 005 não permitida à conta SSH. Não contornar acesso; se necessária, revisão manual com operador autorizado.
- **Mudança A NÃO aplicada**. Aceitação dos riscos da exceção individual A registrada na [Issue #31](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/31#issuecomment-6647042764), distinta da autorização operacional final.
- **Janela condicional:** 05/11/2026 18h–19h BRT, sem execução automática. M1 mantém **11/17**.

**Evidência bruta privada:** capturas de tela do Wazuh e imagens auxiliares `.lab/wazuh-agent005-*`; não versionar nem publicar screenshots com identificadores, horários e caminhos específicos do ambiente.

### Referências

- [Mudança A — parser e CI](m1-change-a-parser-ci-20261104.md)
- [Mudança A — exceção individual ratificada](m1-change-a-solo-owner-review-exception-20261104.md)
- [Pacote de aprovação Linux](m1-fim-change-approval-package.md)
- [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17)
