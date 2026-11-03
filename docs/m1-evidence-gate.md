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
- `agents`: lista de quatro objetos contendo `id`, `os`, `groups` (inclui `default`), `sync: "synced"` e `evidence_ref`. O ID `004` deve ser revalidado como Windows.
- `checks`: objetos para `inventory_review`, `os_impact_review`, `baseline_integrity`, `parser_staging`, `backup_integrity_real`, `rollback_rehearsal_real`, `change_approval`, `approved_window`; cada objeto com `status: "verified"` e `evidence_ref` indicando uma referência a evidência privada revisada.
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

- 73/73 testes anteriores passaram no host remoto antes desta melhoria; a nova suíte contém **21 testes adicionais**, totalizando **94/94 PASS** em 02/11/2026. Inclui JSON UTF-8 com BOM do Windows PowerShell, proteção contra chaves JSON duplicadas, valores não finitos, schema booleano, campos de aprovação vazios e tentativa de traversal fora das pastas permitidas. O CI executa agora a **suíte completa** em Ubuntu e Windows, além dos testes individuais.
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
