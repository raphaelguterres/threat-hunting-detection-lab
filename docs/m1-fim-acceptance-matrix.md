# M1 — Matriz de aceitação FIM por sistema operacional

> **Estado:** pendente de evidências e autorização. Não é um procedimento de implantação automática.
>
> **Escopo:** grupo Wazuh `default` (contagem observada: quatro agentes). Um agente sem grupo foi observado separadamente e **não faz parte** desta avaliação do `default`.

## Objetivo e limites

Evitar que diretivas centralizadas Linux sejam indevidamente distribuídas para o Windows Server `004` e, simultaneamente, preservar a telemetria FIM dos agentes Linux. A alternativa mínima proposta usa `<agent_config os="^Linux">` no bloco Linux **existente**. O parser Wazuh aceitou a proposta em cópia isolada; **não houve implantação**.

A validação de `os="^Linux"` por expressão regular no inventário é uma **prévia**, não prova de como os agentes receberão a configuração real.

## Matriz de gates

| Gate | Critério verificável | Evidência aceita | Bloqueio |
| --- | --- | --- | --- |
| 0 — baseline | Configuração ativa no Manager com parser OK e hash correspondente ao snapshot privado | Resultado datado e inventário de metadados originais | Hash divergente ou erro de parser |
| 1 — inventário 4/4 | IDs distintos, OS/versão, grupos ordenados, status ativo, sincronização, evidências com horário/fuso | Console Wazuh **autorizado**, transcrição privada/revisão humana | ID ou OS presumido, agente sem sincronização, captura antiga |
| 2 — precedência e impacto | Avaliar para cada membro todos os grupos, sua ordem, conflitos e coexistência de FIM central/local | Matriz individual privada e revisor independente | Conflito de grupo sem resolução documentada |
| 3 — backup/rollback | Backup real conferido; proprietário/grupo/permissões registrados; plano de restauração operacional testável | Backup privado, hash/metadata, teste isolado e procedimento de recuperação | Apenas fixture sintética ou recuperação de bytes sem owner/mode |
| 4 — controle de mudança | Diff mínimo aprovado, janela autorizada, responsável, plano de parada e rollback | Aprovação específica externa ao script, com data e escopo | Ausência de autorização, CI apenas verde |
| 5 — mudança | Somente após gates anteriores e aprovação, aplicar bloco revisado com rollback disponível | Registro de execução autorizada | Mudança não aprovada ou desvio do diff |
| 6 — pós-mudança | Config sincronizada, Windows sem diretiva Linux, Linux mantendo FIM, evidência recente até Discover | Endpoint → Manager → Indexer → Discover, timestamps e mesma trilha do artefato benigno autorizado | Perda de telemetria, alertas ausentes, falsos positivos não triados |
| 7 — fechamento | Revisão independente, evidências sanitizadas, hipóteses H01/H02/H03 avaliadas com dados reais | Relatório técnico, revisão, PR/issue rastreáveis | Evidência sintética ou contagem histórica isolada |

**Ordem obrigatória:** 0–4 antes de qualquer mudança operacional, 5 somente em janela aprovada, 6–7 depois. O gate automatizado é sempre **não autorizador** e imprime `DEPLOYMENT_GATE=BLOCKED`.

## Aquisição autorizada e privacidade

No console Wazuh autorizado, filtrar `default` e registrar **cada um dos quatro membros** com ID, OS completo, versão, grupos **na ordem**, status, sync e timestamp com fuso. O agente Windows `004` exige confirmação no console. Não inventar integrantes a partir da quantidade; não usar APIs/CLI alternativas para contornar um bloqueio anterior. Não publicar IP, hostname, usuário, credenciais, hashes privados ou logs brutos.

A evidência do inventário perde atualidade após **24 horas**, e o validador também tolera no máximo cinco minutos de diferença futura de relógio.

### Ferramentas locais (não conectam ao Manager)

A primeira linha do CSV privado `.lab/m1-agent-inventory.csv` deve ser:

```csv
id,os,groups,status,sync,observed_at,evidence_ref
```

Depois de o operador conferir quatro linhas **reais**:

```powershell
python scripts/m1_import_authorized_inventory.py --csv .lab/m1-agent-inventory.csv
python scripts/m1_fim_impact_preview.py --csv .lab/m1-agent-inventory.csv
```

A primeira operação valida estrutura. A segunda mostra apenas contagens agregadas: possíveis correspondências Linux, exclusões não Linux, quantos agentes têm múltiplos grupos e quantos têm `default` fora da última posição. Os resultados são **estimativas de seletor**, não evidências de deploy.

Somente após revisão do operador, atualizar o manifesto privado:

```powershell
python scripts/m1_import_authorized_inventory.py --csv .lab/m1-agent-inventory.csv --apply
python scripts/m1_evidence_gate.py --manifest .lab/m1-evidence.json --stage prechange
```

Importação altera somente o manifesto local, invalida aprovações dependentes quando há mudança no inventário e nunca aplica `agent.conf`.

## Critérios de parada e recuperação

Interromper diante de divergência da baseline, inventário incompleto, grupos em conflito, restauração não recuperável, falta de aprovação, erro do parser, sync falha, efeito não previsto no Windows, Linux sem cobertura FIM, ou ausência de evidência Manager → Indexer → Discover.

O backup real protegido por DPAPI teve **restauração isolada de bytes** e hash aprovados, mas isso **não substitui** verificação de ownership, permissões e distribuição na recuperação operacional. DPAPI depende do perfil Windows que protegeu o backup.

O change control da auditoria Windows `4698` é **separado**; não habilitar `auditpol` como parte desta mudança FIM.

## Referências e rastreabilidade

- [Configuração centralizada Wazuh](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html)
- [Grupos de agentes e precedência](https://documentation.wazuh.com/current/user-manual/agent/agent-management/grouping-agents.html)
- [Plano FIM por OS](m1-fim-os-scoped-remediation-plan.md)
- [Gate de evidências M1](m1-evidence-gate.md)
- [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17)
- [Issue #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9)

A conclusão da matriz depende das evidências privadas conferidas por operador, e não da simples existência de campos `verified` em JSON.
