# M1/H03 — checkpoint read-only da mudança C: configuração, baseline e ACL

**Data:** 04/11/2026 (BRT). **Escopo:** Windows Server 2022, agente Wazuh `004`, proposta de diretório FIM realtime isolado. **Decisão:** **NO-GO operacional**; somente inspeção de configuração e permissões existentes. Nenhuma pasta de teste, arquivo de prova, regra ou política foi criada ou alterada.

## Evidências verificadas no ambiente

| Item | Leitura observada | Limite da conclusão |
| --- | --- | --- |
| Agente `004` no Manager | `synchronized`; parser oficial `verify-agent-conf` do `default/agent.conf` retornou `OK` | Sincronização + sintaxe não comprovam cobertura FIM efetiva de artefato |
| FIM em `ossec.conf` local | 6 caminhos; 1 realtime, 5 periódicos | Diretivas locais não provam precedência após configuração central |
| Único realtime local | Diretório Startup do Menu Iniciar para todos os usuários | **NO-GO** para `.exe` descartável devido ao risco de inicialização automática |
| Central recebida no agente | 1 diretiva FIM, sem seletor `os` não vazio | Diretiva central UnixStyle do grupo `default` continua sem segregação Linux; mudança A separada |
| `shared/merged.mg` | Arquivo presente | Presença não certifica a configuração FIM final aplicada |
| Proposta `C:\SecurityLab\H03` | Diretório e pai `C:\SecurityLab` **não existem** | Não há FIM sobre o alvo nem ACL efetiva do diretório de teste |
| ACL existente em `C:\` | 2 ACEs amplas de permissão de criação/acréscimo: `CreateFiles` e `AppendData` com herança para pastas; uma marcada `InheritOnly` | São permissões da **raiz**, não prova de permissões efetivas de uma pasta futura |
| `WazuhSvc` | `Running`, conta `LocalSystem` | Antes de mudar ACL, validar que o serviço preserva leitura e monitoramento no escopo novo |
| Estado de mudança | Sem alteração operacional, sem teste H03, sem habilitação de `4698` | `DEPLOYMENT_GATE=BLOCKED` |

**Baseline privado:** foram calculados SHA-256 para `ossec.conf`, `shared/agent.conf` e `shared/merged.mg` **sem expor hashes ao Git**. A saída visual está preservada em `.lab/change-c-acl-hash-private.png` e os estados agregados em `.lab/m1-change-prep/H03_CHANGE_C_BASELINE_SUMMARY_PRIVATE_20261104.json`. A gravação direta da VM na pasta compartilhada falhou com erro de I/O. A captura privada é referência para nova conferência; **não substitui um manifesto de hashes verificado por máquina e aprovado pelo operador**. Não foram alteradas ACLs para contornar a falha de exportação.

## Análise de risco da mudança C

| Risco | Implicação | Tratamento exigido na mudança aprovada |
| --- | --- | --- |
| Herança de ACEs amplas a partir de `C:\` | A pasta futura pode herdar capacidades de criação que não se deseja para testes executáveis | Projetar ACLs restritas e inspecionar ACL **efetiva após a criação autorizada**, antes de qualquer artefato |
| Conta de serviço `LocalSystem` | Restringir demais a ACL pode impedir a leitura por Wazuh | Garantir acesso apropriado a `SYSTEM`, administradores e operador autorizado, com menor privilégio; sem `Everyone`/`Users` com escrita ampla |
| Diretiva central compartilhada | Uma alteração no grupo `default` pode atingir outros agentes; precedência sobre configuração local em conflitos | Definir forma de escopo restrita ao `004` e comparar local/central/mesclada em cópia isolada, com revisão |
| Realtime e custo | Diretório de alto churn ou aplicação de política incorreta pode elevar EPS, CPU ou número de alertas | Limitar a pasta exclusiva, monitorar baseline e definir gatilhos de parada |
| Diretório inexistente | Wazuh ignora caminho realtime inexistente até novo restart que o descubra | Em janela aprovada, verificar a **existência do diretório antes de aplicar e reiniciar** o agente, sem realizar restart antecipado |
| Falha de rollback | Configuração parcial ou diretório/artefato abandonado podem afetar próximos testes | Backup verificável, restauração isolada, limpeza e rollback da mudança C independentes de A e B |
| Confusão de telemetria | Sysmon ID 1 e alerta FIM próximos podem ser de objetos diferentes | Mesmo artefato/ativo, FIM anterior, até 20 minutos, originais, hash, controle negativo e revisão humana |

## Proposta de política mínima de acesso (somente desenho)

- Pasta dedicada, no **disco local**, sem associação a Startup, serviços, tarefas agendadas, logon ou caminhos do sistema. Nunca usar UNC/mapeamento de rede para FIM Windows.
- Após aprovação de criação e antes de qualquer teste, verificar herança de ACLs e propor **SACL/DACL sem escrita ampla**. `SYSTEM` e `Administrators` mantêm acesso administrativo adequado; somente operador de laboratório designado pode modificar o artefato, sem permissões abrangentes a usuários genéricos.
- Definir proprietário, aprovações, escopo dos usuários, tratamento de herança, reparse points, rollback/remoção e coleta dos logs. **Não aplicar comandos ACL neste checkpoint**.
- Preparar a configuração FIM nova em **cópia isolada**, evitando modificar as seis diretivas existentes por acidente; conferir impacto da precedência de `agent.conf` sobre `ossec.conf`, os grupos e os parâmetros de verificação FIM.
- Obter autorização humana distinta para (a) criar diretório e ajustar ACL, (b) alterar o escopo FIM e reiniciar o agente, (c) colocar, modificar e executar **um** binário benigno descartável; registrar janela, limites e reversão.

## Decisões e gates

`WIN004_SYNC=PASS` · `DEFAULT_AGENT_CONF_PARSER=PASS` · `LOCAL_FIM_PATHS=6` · `LOCAL_REALTIME=1_STARTUP` · `CENTRAL_FIM_NODES=1` · `CENTRAL_OS_SELECTOR=ABSENT` · `NEW_H03_ROOT_EXISTS=NO` · `NEW_H03_ROOT_EFFECTIVE_ACL=UNVERIFIED` · `CONFIG_HASH_BASELINE=CAPTURED_PRIVATE_NOT_MACHINE_ATTESTED` · `CHANGE_C=NOT_APPROVED` · `H03=INCONCLUSIVE` · `DEPLOYMENT_GATE=BLOCKED`.

**Próximo gate:** revisor independente deve avaliar o plano de ACLs e a forma exata de segmentação do agente antes de qualquer mudança. A avaliação só vira **GO** quando houver aprovação explícita, baseline completo, janela e rollback testado; nenhum código executável de prova deve ser introduzido antes disso. M1 permanece **11/17 (64,7%)**.

### Referências

- [Proposta de mudança C](m1-h03-isolated-realtime-change-proposal-20261104.md)
- [Descoberta: Startup = NO-GO](m1-h03-startup-realtime-no-go-20261104.md)
- [Fluxos e diagramas do M1](m1-scope-and-h03-diagrams-20261104.md)
- [FIM — Wazuh: configurações e precedência](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/how-to-configure-fim.html)
- [FIM realtime — Wazuh: diretório precisa existir antes do restart](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/basic-settings.html)
- [Configuração centralizada — Wazuh](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html)
