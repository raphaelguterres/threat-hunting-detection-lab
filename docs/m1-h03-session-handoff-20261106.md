# Encerramento da sessão — H03 / M1 — 06/11/2026

**Hora de referência:** aproximadamente 02h55 BRT (o relógio local do Windows Server guest usa outro fuso).  
**Estado:** `READONLY_COMPLETE` · `H03_CHANGE_C=NO_GO` · `DEPLOYMENT_APPROVED=false` · `M1=15/17 (88,2%)`.

## O que foi efetivamente verificado nesta sessão

- As duas VMs, **Kali** e **WindowsServer**, estavam `running` no VirtualBox após serem abertas pelo proprietário. Nenhuma foi ligada, suspensa ou reiniciada pelo assistente.
- No Kali, a consulta remota autorizada `docker ps` mostrou os contêineres **Wazuh Manager, Indexer e Dashboard em execução**. `agent_control -l` mostrou **agentes 002, 004 e 005 ativos**. Isso não comprova ingestão de eventos específicos.
- No Windows Server **agente 004**, o script preexistente e somente leitura `H03_LOCAL_CENTRAL_SCOPE_READONLY_20261104.ps1` foi executado novamente. Foram observadas **6 diretivas FIM locais / 6 paths**, **1 diretiva recebida centralmente / 1 path Unix**, **1 seletor de OS**, sem sobreposição exata local/central. `syscheck disabled=no`, `frequency=43200` segundos. `merged.mg` presente.
- **`C:\SecurityLab\H03` não existe e não consta nos caminhos FIM locais ou recebidos.** Não foi consultada a API da configuração efetivamente ativa neste checkpoint; distribuição de uma diretiva não significa cobertura real do alvo.
- O teste executável H03 **não foi realizado** e o arquivo FIM inerte anterior (`.m1probe`) **não é prova** de execução do mesmo executável.
- Foi preservada uma captura de tela privada com hash SHA-256, registrada no snapshot `.lab/m1-session-h03-handoff-20261106-private.json`. A evidência bruta e caminhos/identificadores internos além do necessário **não foram publicados**.

## Pacote de preparação já disponível

A [preparação da mudança C](m1-h03-change-c-readiness-20261106.md) define diretório NTFS isolado, modelo de DACL mínima, backup/rollback, escopo FIM único e critérios de parada. O [gate offline](../scripts/m1_h03_change_c_offline_diff_gate.py) aceita somente uma nova diretiva `realtime=yes` para a pasta H03 no `ossec.conf` local do `004`, preservando os demais campos. **14 testes focados e suíte de 281 testes (4 ignorados) passaram em 06/11**; [CI #184](https://github.com/raphaelguterres/threat-hunting-detection-lab/actions/runs/42170726720) tinha **3/3 jobs aprovados** antes desta documentação final.

Os resultados de ACL anteriores são **simulações em memória**, não a DACL efetiva do alvo ainda inexistente. A janela condicional de Change C **04/11 18h–19h BRT expirou**; a ratificação dos riscos de autoavaliação para Change C **não é revisão independente do M1**.

## Próximo ponto de retomada — 07/11/2026

1. **Revalidar antes de qualquer mudança**: VM e operador disponíveis, baseline `ossec.conf` atual, configuração Syscheck ativa, hashes, backup DPAPI acessível com perfil correto, relógios, estado do serviço, exclusões FIM e recursos do agente `004`.
2. **Avaliar GO/NO-GO de Change C** sob janela operacional nova e autorização específica. Antes de reiniciar `WazuhSvc`, o diretório isolado deve **existir e possuir ACL mínima efetiva verificada**, sem herança/escrita ampla. Aplicar, se autorizado, somente a diretiva nova e validar diff, parser, recuperação, agente e índice.
3. **Testar primeiro FIM com arquivo inerte** e confirmar Manager/Indexer/Discover por fonte autorizada. **Um teste posterior com binário benigno requer aprovação separada**, no mesmo caminho/host, FIM antes da execução Sysmon EID1, janela máxima de 20min e controle negativo.
4. Não marcar H03, H02 ou H01 como correlação real completa sem correspondências por identidade. **H02 recente segue sem `4720`; H01 tem regra/critério diagnosticado mas alerta ponta a ponta pendente.** Manter o PR #25 sem merge e o gate final bloqueado até revisão independente.

**Esta sessão executou apenas verificações read-only e registro de evidências. Nenhuma VM, ACL, regra, `ossec.conf`, conta, política, serviço, contêiner ou arquivo de teste foi alterado.** O andamento do checklist M1 permanece **15/17 — 88,2%**, não um indicador de prontidão para produção.
