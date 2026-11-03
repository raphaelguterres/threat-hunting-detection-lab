# M1 — Conciliação manual de agentes e decisão de mudança FIM

> **Estado de referência: NO-GO.** Este roteiro documenta uma revisão **somente leitura** pelo operador no Wazuh Dashboard autorizado. Nenhum passo executa consultas alternativas, mudanças de grupo ou deployment.
>
> Consulta oficial: [Wazuh — Listing agents using the dashboard](https://documentation.wazuh.com/current/user-manual/agent/agent-management/listing/wazuh-dashboard.html), [Grouping agents](https://documentation.wazuh.com/current/user-manual/agent/agent-management/grouping-agents.html).

## 1. Coleta autorizada, quatro membros do default

1. Entrar no Dashboard com a sessão e as permissões já autorizadas. Navegar para **Agents management → Summary**; identificar os membros atribuídos a `default`. Em **Agents management → Groups**, revisar associação e detalhes visíveis. **Não usar Dev Tools, API, SSH ou CLI como contorno** de consultas individuais anteriormente bloqueadas.
2. Registrar para cada um dos **quatro** agentes reais: ID, string do SO e versão, status, sincronização, timestamp de observação com fuso, grupos **na ordem atribuída** e referência privada da captura. Não presumir IDs pelo total do grupo. Reconferir o agente `004` como Windows no console.
3. Se o Dashboard não mostrar o SO, a sincronização ou a **ordem** dos grupos, marcar o campo como `NÃO VERIFICADO`. **Não inferir ordem alfabética como prioridade**. Solicitar ao responsável pelo ambiente confirmação por meio autorizado, sem mudar permissões para acessar o dado.
4. As capturas ficam somente na pasta privada `.lab/`, sem hostname, IP, nomes de pessoas, tokens ou conteúdo de logs. Publicar exclusivamente contagens e estado dos controles. Os quatro registros precisam ser coletados em até **30 minutos** entre o primeiro e último (política local M1); cada observação precisa ter fuso explícito e no máximo 24h de idade.

## 2. Evidência privada e prévia offline

Preparar `.lab/m1-agent-inventory.csv` (nunca versionar) com cabeçalho exato:

```csv
id,os,groups,status,sync,observed_at,evidence_ref
```

**Preencher quatro linhas reais.** Em `groups`, separar nomes por `;`, respeitando a ordem do Dashboard. `observed_at` em ISO 8601 com fuso, por exemplo `2026-11-03T15:00:00-03:00` **somente como exemplo de formato, não como evidência real**. `evidence_ref` é a referência privada da captura, sem dados de rede.

Conferir sem alterações:

```powershell
python scripts/m1_import_authorized_inventory.py --csv .lab/m1-agent-inventory.csv
python scripts/m1_fim_impact_preview.py --csv .lab/m1-agent-inventory.csv
```

O primeiro valida **estrutura**, não autenticidade. O segundo exibe **somente contagens hipotéticas** de Linux/não Linux e possíveis problemas multigrupo. Nenhuma ferramenta confirma a seleção real do Wazuh. Se os registros forem aprovados manualmente, `--apply` altera **somente** o manifesto privado, invalida revisões dependentes e ainda retorna `DEPLOYMENT_GATE=BLOCKED`:

```powershell
python scripts/m1_import_authorized_inventory.py --csv .lab/m1-agent-inventory.csv --apply
python scripts/m1_evidence_gate.py --manifest .lab/m1-evidence.json --stage prechange
```

## 3. Revisão da precedência

No Wazuh, um agente pode pertencer a múltiplos grupos, e o **último grupo atribuído tem maior prioridade** quando configurações entram em conflito. Para **cada membro** do `default`:

- Confirmar a ordem dos grupos e identificar se há configuração centralizada FIM/log em mais de um grupo; revisar precedência conforme a documentação oficial
- Comparar o escopo local vs. central sem supor substituição; preservar os **seis caminhos FIM locais previamente observados** no Windows `004`
- Classificar se `os="^Linux"` excluiria a diretiva Unix do Windows e manteria a telemetria adequada nos Linux, anotando as limitações; a prévia regex não constitui demonstração de distribuição
- Revisor independente registra `group_precedence_review` e `os_impact_review` somente após examinar os quatro agentes e os conflitos

## 4. Decisão formal de mudança: NO-GO até todos os gates

| Gate | Estado atual | Critério de liberação |
| --- | --- | --- |
| Baseline e parser ativo | PASS somente leitura | Hash baseline e parser preservados antes da mudança |
| Inventário individual `default` 4/4 | **PENDENTE** | Quatro registros reais, atuais, revisados e coerentes |
| Precedência e impacto por OS | **PENDENTE** | Grupos ordenados e conflitos avaliados por agente |
| Backup real DPAPI, integridade e restauração isolada | PASS **somente no sandbox local** | Procedimento operacional com owner, gid, mode, hash e responsabilidade aprovado |
| Revisão independente de código | **PENDENTE** | PRs #24/#25 revisados formalmente; CI verde não substitui aprovação |
| Janela, autorização e plano de parada | **PENDENTE** | Mudança FIM especificamente autorizada pelo responsável |
| Distribuição e FIM ponta a ponta | **NÃO EXECUTADO** | Após mudança aprovada: agente → Manager → Indexer → Discover com evidência real |

**Decisão vigente: `NO-GO` / `DEPLOYMENT_GATE=BLOCKED`.** Não realizar merge em nome de revisão inexistente. A auditoria Windows `4698` depende de change request separado. Não reiniciar agentes preventivamente. Antes de qualquer mudança, realizar novamente os checkpoints de baseline e avaliação de rollback.

## 5. Próxima atualização do repositório

Ao concluir a conferência dos quatro agentes no console, atualizar **somente status agregados e evidências sanitizadas** nas Issues [#17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17) e [#9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9). Evidências individualizadas permanecem privadas. O revisor deve apontar divergências e exigir nova coleta, se necessário. [Matriz de aceitação FIM](m1-fim-acceptance-matrix.md).
