# M1/H03 — leitura da configuração FIM ativa no agente Windows 004

**Data:** 04/11/2026. **Método:** inspeção somente leitura no Wazuh Dashboard (Endpoints → agente Windows → Configuration → Integrity monitoring → Monitored), confirmada por consulta `agent_control -i 004` no Manager e leitura de `/var/ossec/etc/shared/default/agent.conf`. **Nenhuma configuração alterada.**

## Evidências verificadas

| Fonte | Observação | Interpretação |
| --- | --- | --- |
| Dashboard do endpoint | Breadcrumb **Endpoints → Windows Server → Configuration → Integrity monitoring → Monitored** | Tela de configuração do **agente**, não a lista do grupo `default` |
| Manager: `agent_control -i 004` | Agente `004` ativo, Windows Server 2022, Wazuh v4.14.9; nome de endpoint da tela correspondente ao do Manager | Identidade do endpoint confirmada em duas fontes |
| Dashboard: aba General (captura fornecida pelo operador) | FIM `enabled`, frequência `43200` s, `scan on start=yes` | Syscheck habilitado; varredura periódica 12 h |
| Dashboard: aba Monitored (consulta remota) | Item selecionado `C:\opt\wazuh-lab\monitorado` com `realtime=yes` e `whodata=no`; verificações MD5/SHA-1/SHA-256 habilitadas | **Configurado**, mas a tela não comprova existência da pasta, eventos gerados ou cobertura operacional |
| Manager: grupo `default` | `<agent_config><localfile>...Unix syslog...</localfile><syscheck><directories realtime="yes">/opt/wazuh-lab/monitorado</directories></syscheck></agent_config>` | **Origem identificada:** diretiva Linux compartilhada e exibida pelo Windows com caminho normalizado como `C:\opt\...`. Não confundir com diretório dedicado ao H03 |
| Inventário privado anterior | Seis diretivas FIM locais no agente: cinco periódicas e uma realtime na pasta Startup | Startup permanece **NO-GO** para executar binário por risco de autorun |
| Novo diretório isolado proposto | `C:\SecurityLab\H03` não existe na última verificação local | Sem prova de que esteja monitorado; não implantar fora do change control |
| Wazuh Dashboard: aba Ignored | Ainda **não inspecionada** nesta rodada | Exceções do FIM ativas permanecem pendentes |

## Conclusão técnica

Foi possível observar pela primeira vez nesta sequência a **configuração FIM exibida para o agente 004 no Dashboard**, e verificar via Manager que o item `C:\opt\wazuh-lab\monitorado` é originário da **diretiva UnixStyle do grupo default**. Isso esclarece a aparente inconsistência entre o XML local e a lista de Monitored: **não representa uma pasta de teste Windows aprovada**.

O agente estar `Active`, o FIM estar `enabled` e o diretório aparecer com `realtime=yes` **não demonstram** que este caminho exista nem que alterações reais de arquivos serão detectadas. A validação por alertas FIM e Sysmon, a existência real da pasta, exclusões e a avaliação do diretório isolado continuam pendentes.

**Decisão:** `ACTIVE_AGENT004_FIM_DASHBOARD_VIEW=OBSERVED`; `CROSS_OS_CENTRAL_DIRECTIVE_CONFIRMED=YES`; `H03_SAFE_REALTIME_ROOT=UNVERIFIED`; `H03_REAL_PAIR=INCONCLUSIVE`; `DEPLOYMENT_GATE=BLOCKED`.

## Procedimento de segurança para continuar

1. Consultar a aba **Ignored** do mesmo agente para verificar as exclusões reais, sem clicar em Edit.
2. Conferir na própria VM se o caminho `C:\opt\wazuh-lab\monitorado` existe; ainda que exista, não utilizá-lo como destino de binário H03 sem review de escopo.
3. Manter a proposta de pasta segura `C:\SecurityLab\H03`, com ACL restrita, Config local 004, backup, janela, rollback e aprovação da execução separados.
4. Quando mudança C estiver formalmente liberada, só então implantar a pasta e sua diretiva e exigir evento FIM de arquivo real seguido de Sysmon Event ID 1 do mesmo objeto em até 20 min.
5. Não editar a diretiva Linux compartilhada em `default` como parte da mudança C; sua correção com seletor `os="^Linux"` pertence à mudança A e ao seu gate independente.

**Evidência privada:** screenshot remoto da aba Monitored preservado em `.lab/fim-monitored-before-20261104.png` no host; não versionar imagem bruta com hostname/caminhos locais. [Pacote da mudança C](m1-change-c-approval-cutover-package-20261104.md) · [Plano H03](m1-h03-benign-binary-test-plan-20261104.md) · [Arquitetura](architecture-network-public-exposure-20261104.md).
