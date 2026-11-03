# M1 — Gate de evidências FIM por OS (fail-closed)

**Estado inicial:** `BLOCKED`. Este gate é **somente leitura**, não altera regras, grupos, o Manager, o agente ou a política de auditoria Windows. Ele não é mecanismo de aprovação nem executor de deployment.

## Por que existe

Os quatro membros do grupo `default` precisam ser reconciliados individualmente antes de restringir uma diretiva Linux da configuração centralizada. A validação sintática `verify-agent-conf` feita em cópia isolada e testes com arquivos sintéticos **não** provam que a distribuição para todos os agentes é segura.

## Fluxo técnico

1. Obter inventário pelo **console autorizado** do Wazuh: quatro IDs distintos, OS/versão, grupos (incluindo `default`), status de sincronização e referência à evidência privada. Consultas previamente bloqueadas por controles de acesso **não devem ser contornadas**.
2. Registrar a revisão de impacto `os="^Linux"`, o hash da baseline e o resultado do verificador oficial em cópia isolada.
3. Obter evidência de **backup real** preservando ownership/permissões, ensaio autorizado de restauração isolada sobre cópia real, aprovação de mudança e janela de execução.
4. Executar o validador local. Saída `EVIDENCE_COMPLETENESS=REVIEW_READY` indica **somente completude declarada** e exige validação humana independente; `DEPLOYMENT_GATE=BLOCKED` é sempre exibido. Nenhum status dessa ferramenta autoriza aplicar a configuração.
5. Se e somente se houver aprovação específica externa ao script, seguir procedimento controlado com backup e rollback. Para `--stage postchange`, incluir sincronização e evidência FIM real Windows/Linux → Manager → Indexer → Discover, sem declarar êxito a partir de contagens históricas.

## Operação privada

Crie um manifesto JSON privado em `.lab/` (pasta ignorada por Git). Campos requeridos:

- `schema_version: 1`, `change_id: "M1-FIM-OS-SCOPE"`.
- `agents`: lista de quatro objetos contendo `id`, `os`, `groups` (lista em ordem de prioridade observada, inclui `default`), `status: "active"`, `sync: "synced"`, `observed_at` (ISO 8601 com fuso, coleta das últimas 24h) e `evidence_ref`. O ID `004` deve ser revalidado como Windows.
- `checks`: objetos para `inventory_review`, `os_impact_review`, `group_precedence_review`, `baseline_integrity`, `parser_staging`, `backup_integrity_real`, `rollback_rehearsal_real`, `change_approval`, `approved_window`; cada objeto com `status: "verified"` e `evidence_ref` indicando uma referência a evidência privada revisada.
- Para validação após mudança, acrescente `agents_resynced`, `windows_fim`, `linux_fim`, `manager_ingestion`, `indexer_ingestion`, `discover_visibility` com o mesmo formato.

Comandos:

```powershell
python scripts/m1_evidence_gate.py --manifest .lab/m1-evidence.json --stage prechange
python scripts/m1_evidence_gate.py --manifest .lab/m1-evidence.json --stage postchange
python -m unittest discover -s tests -p test_m1_evidence_gate.py -v
```

Arquivos UTF-8 com ou sem BOM do Windows PowerShell são aceitos; chaves JSON duplicadas e constantes não finitas são rejeitadas. Sem manifesto, manifesto fora de `.lab`, campos ausentes, dados incorretos, OS ambíguo ou evidência não confirmada: saída **BLOCKED** e código **2**. Um manifesto estruturalmente completo gera código 0 **apenas para a checagem de completude**, mas o deployment permanece bloqueado para aprovação independente. Não usar esse código como gatilho de mudanças.

**Atenção:** um `evidence_ref` preenchido não garante autenticidade por si só. O responsável deve verificar a fonte no console autorizado. Esta ferramenta não faz atestado criptográfico nem controle de acesso.

## Evidências já existentes e limites

- 73/73 testes anteriores passaram no host remoto antes desta melhoria; a nova suíte contém **25 testes do gate**, com validação de recência a cada execução e rejeição de agente inativo; a suíte geral está em **119/119 PASS** no checkpoint de 03/11/2026. Inclui JSON UTF-8 com BOM do Windows PowerShell, proteção contra chaves JSON duplicadas, valores não finitos, schema booleano, campos de aprovação vazios e tentativa de traversal fora das pastas permitidas. O CI executa agora a **suíte completa** em Ubuntu e Windows, além dos testes individuais.
- Configuração local do agente 004: seis diretórios FIM existentes; um em tempo real, cinco por varredura.
- 102 documentos FIM históricos do agente 004 no Indexer, mas zero na janela previamente analisada; isso **não demonstra a cobertura atual**.
- O primeiro ensaio de restauração de 02/11 usou fixtures **sintéticas**, não o Manager.
- Em checkpoint posterior de 02/11, a configuração central **real** foi copiada por operação somente leitura para backup privado criptografado via DPAPI do usuário Windows. Integridade da baseline e do original no Manager: PASS. Foi executado **ensaio de restauração isolada dos bytes reais**, com controle negativo de corrupção, verificação SHA-256 e descarte da pasta temporária: PASS. **Isso não comprova restauração operacional no Manager**, que ainda exige validação autorizada de owner/permissões/distribuição e aprovação humana. O backup DPAPI depende do mesmo perfil Windows e não é portável por padrão.
- A auditoria Windows Security `4698` é outro change request e não deve ser alterada por esse gate.

## Rastreabilidade

- [Checkpoint M1 — PR #24](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/24) (aguardando revisão e incorporação à `main`)
- [Plano FIM por SO](m1-fim-os-scoped-remediation-plan.md)
- [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17)
- [Issue #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9)

## Importacao segura de inventario autorizado (CSV privado)

Quando o operador obtiver o inventario **pelo console Wazuh autorizado**, pode preparar um arquivo local ignorado pelo Git chamado `.lab/m1-agent-inventory.csv`. O CSV usa exatamente as colunas:

```csv
id,os,groups,status,sync,observed_at,evidence_ref
```

Registre **quatro linhas reais** com IDs distintos, SO e versao observados, os grupos separados por ponto e virgula (incluindo `default`), estado `active`, sync `synced`, timestamp ISO 8601 com fuso observado nas **ultimas 24 horas** (maximo 5 minutos no futuro por desvio de relogio) e uma referencia privada da evidencia. O ID `004` precisa ser reconfirmado no console como Windows. **Nao inventar linhas nem usar fixtures sinteticas como evidencia real.** Nao registrar hostname, IP, usuario ou credenciais.

Teste sem alterar arquivos:

```powershell
python scripts/m1_import_authorized_inventory.py --csv .lab/m1-agent-inventory.csv
```

Somente depois de revisar os quatro dados reais, importe para o manifesto privado:

```powershell
python scripts/m1_import_authorized_inventory.py --csv .lab/m1-agent-inventory.csv --apply
python scripts/m1_evidence_gate.py --manifest .lab/m1-evidence.json --stage prechange
```

O gate revalida `status=active` e o timestamp `observed_at` de cada agente a cada execução (máximo 24 horas, tolerância de cinco minutos futuros), evitando que um manifesto previamente importado permaneça pronto indefinidamente. O importador recusa manifesto pré-existente malformado (JSON duplicado, schema ambíguo), sem sobrescrever o original. Nunca consulta VMs, nunca publica dados, nunca altera `agent.conf`, e sempre informa `DEPLOYMENT_GATE=BLOCKED`; a etapa de escrita exige `--apply` e permanece apenas em `.lab`. Quando o inventario muda, revisoes de inventario/impacto, aprovacao, janela e comprovacoes pos-mudanca anteriores sao **invalidada(s)**. O CSV e o manifesto nao autenticam por si mesmos a observacao; a verificacao independente continua obrigatoria.
## Revisão de precedência de grupos e aceitação por SO

Segundo a documentação oficial do Wazuh, o atributo `os` em `agent_config` aplica uma expressão regular sobre o sistema operacional declarado pelo agente. A própria documentação utiliza `os="^Linux"` como exemplo. Isso confirma **suporte do seletor**, não o impacto nos quatro membros atuais:
https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html

Um mesmo agente pode participar de vários grupos. A **ordem de atribuição importa**, porque a configuração do último grupo tem precedência quando há conflito. O `group_precedence_review` é obrigatório antes da mudança, **mesmo se o operador observar apenas o grupo default**: deve deixar registrada essa observação e a ausência/presença de conflitos. Fonte:
https://documentation.wazuh.com/current/user-manual/agent/agent-management/grouping-agents.html

Na evidência privada, conferir para cada agente: ID, string real do SO, versão, lista **ordenada** de grupos, status `active`, `synced`, horário da consulta (com fuso), qual bloco FIM se aplica e como a configuração compartilhada interage com a configuração local. Se houver vários grupos, confrontar a precedência efetiva de configurações. A mera contagem de membros do `default` não comprova esse gate. Mudança na lista ou na ordem dos grupos invalida a revisão anterior.

A documentação informa que os agentes **recarregam automaticamente** a configuração centralizada quando a recebem; não planejar restart automático como etapa obrigatória. Conferir sincronização e logs pertinentes depois de uma mudança **especificamente aprovada**. Não enviar comandos de inventário por caminhos alternativos depois do bloqueio de segurança anterior, nem realizar a mudança nesta etapa.

## Prévia offline de impacto do seletor Linux

Depois de obter quatro linhas **reais e autorizadas** no CSV privado `.lab/m1-agent-inventory.csv`, o analista pode conferir o efeito **hipotético** do regex `^Linux` sem conexão ao Manager:

```powershell
python scripts/m1_fim_impact_preview.py --csv .lab/m1-agent-inventory.csv
```

O relatório imprime somente contagens agregadas: possíveis correspondências Linux, exclusões não Linux, quantidade de agentes com múltiplos grupos e aqueles em que `default` não é o último grupo. Para gerar um relatório **privado** sem sobrescrever arquivos existentes:

```powershell
python scripts/m1_fim_impact_preview.py --csv .lab/m1-agent-inventory.csv --output .lab/m1-impact-aggregate.json
```

Mesmo com todas as linhas válidas, o resultado informa `DEPLOYMENT_GATE=BLOCKED` e `WAZUH_RUNTIME_SELECTION_CONFIRMED=false`. **Não é prova de match em runtime, nem substitui revisão da ordem de grupos, aprovação e teste pós-mudança.** O importador CSV e a prévia nunca executam comandos no Wazuh.

Ver os critérios completos em [Matriz de aceitação FIM por OS](m1-fim-acceptance-matrix.md).
