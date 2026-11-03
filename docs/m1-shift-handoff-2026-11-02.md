# M1 — Handoff de fim de jornada (02/11/2026)

> **Fase:** Threat Hunting M1, preparação de mudança FIM por sistema operacional. **Status técnico:** *em andamento*. **Deploy:** não autorizado. Este documento é público e deliberadamente não contém dados privados do laboratório.

## Decisões e entregas desta jornada

| Frente | Evidência | Decisão |
| --- | --- | --- |
| Integração SOC | Fase anterior com fluxo Manager → Indexer → Discover e provas históricas documentadas | Não confundir integração histórica com FIM atual do M1 |
| Correlação H01/H02/H03 | Motor offline, controles negativos e fixtures sintéticos | Hipóteses ainda não comprovadas integralmente com eventos reais |
| Configuração FIM compartilhada | Grupo `default` com **4 membros**; existe **1 agente não atribuído** | IDs/OS de todos os quatro membros ainda não reconciliados individualmente |
| Proposta por OS | `os="^Linux"` validado pelo parser Wazuh em cópia isolada | Não implantado |
| Windows Server, agente `004` | Sincronização, integridade e parser PASS; seis diretórios FIM locais | Não equivale à comprovação de FIM recente ponta a ponta |
| Indexer | 102 documentos FIM históricos de `004`, zero na janela recente consultada anteriormente | Não declarar H03 validada |
| Recuperação e rollback | Backup **real** da configuração central obtido em modo leitura e protegido por DPAPI; hash e restauração **isolada dos bytes** verificados, com controle negativo de corrupção | Não representa restauração operacional no Manager; permissões/owner/distribuição ainda precisam de procedimento autorizado |
| Qualidade automatizada | **94/94 testes locais PASS**; suíte completa adicionada à matriz Ubuntu/Windows do CI no PR #25 | Aguardar resultado dos checks referentes ao último SHA antes de merge |
| Segurança operacional | Gate de evidências fail-closed e manifest privado inicial com dados explicitamente não verificados | `DEPLOYMENT_GATE=BLOCKED` |

## Pull requests

- [PR #24 — checkpoint técnico e auditoria](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/24). Documento público sanitizado; submissão à revisão técnica realizada.
- [PR #25 — gate de evidências e contratos](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/25). Verificador Python read-only, regressões de segurança, CI Ubuntu/Windows, README e documentação.

**Ambos ficam abertos até revisão independente e checks atuais aprovados.** Código e documentação não alteram o Manager por si sós. CodeRabbit marcado como `SKIPPED` nos últimos checkpoints consultados, não como aprovação.

## Primeiro bloco da próxima sessão

1. Conferir status CI e revisão formal dos PRs; somente incorporar à `main` após aprovação combinada.
2. Consultar no **console autorizado** os quatro integrantes do `default`: ID, sistema/versão, grupo, estado, sincronização e horário da evidência. Manter o agente sem grupo fora dessa lista. Não contornar consultas ou proteções anteriores.
3. Reconciliar inventário 4/4 com o relatório privado e revisar impacto da diretiva Linux em cada endpoint; não inferir OS a partir do papel da VM.
4. Revisar backup real e plano de restauração com metadados de proprietário/grupo/permissões; obter janela e aprovação específicas. DPAPI é vinculado ao perfil Windows que realizou o backup.
5. Somente após aprovações, executar mudança mínima com rollback preparado, observar sincronização e verificar FIM no endpoint → Manager → Indexer → Discover com eventos benignos autorizados.
6. Validar H01/H02/H03 em eventos reais conforme playbooks; preparar timelines, falsos positivos e revisão independente antes de encerrar M1.

## Critérios de não encerramento do M1

- Inventário incompleto; associação ID/OS não comprovada;
- Sem aprovação independente ou sem janela de mudança;
- Apenas sintaxe aprovada, arquivos sintéticos ou contagens históricas, sem evidência FIM real e recente;
- Restauração local dos bytes comprovada, mas não recuperação operacional;
- Hipóteses H01/H02/H03 sem correlação e triagem real end-to-end.

**Separação de mudanças:** ativação da auditoria Windows Security `4698` tem change control próprio e não deve ser executada como efeito colateral da revisão FIM.

[Roadmap](../ROADMAP.md) · [Issue #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9) · [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17)

## Adendo final — 02/11/2026, sessão noturna

- PR #25 evoluiu para **110/110 testes locais PASS** (73 existentes + 21 testes de gate + 16 testes de importação CSV).
- CI do último commit de PR #25: **GitHub Actions run #43 SUCCESS**, com suíte integral nos runners Ubuntu e Windows.
- Foi implementado importador offline de inventário `scripts/m1_import_authorized_inventory.py` (disponível no PR #25), que consome CSV coletado **pelo operador no console autorizado**, em arquivos privados `.lab`, e verifica membros, OS, grupo, sync, timestamp com fuso e evidência observada nas últimas 24 horas. O padrão valida sem escrever; `--apply` exige solicitação explícita, sem alterar configurações Wazuh.
- Alterações do inventário invalidam revisões, aprovações, janela e evidência pós-mudança anteriores dependentes. Modelos privados usam apenas `UNVERIFIED` e permanecem bloqueados até coleta real; nenhuma consulta protegida foi contornada.
- Permanece **`DEPLOYMENT_GATE=BLOCKED`**, sem implantação ativa e sem merge. Os PRs requerem revisão humana independente, e o M1 precisa do inventário real 4/4 e comprovação FIM ponta a ponta.

**Carga horária:** registrar somente minutos efetivamente apontados no diário privado; o marco M1 não deve ser encerrado por cumprimento de meta horária.
