# M1 — autorização limitada do proprietário para continuar o laboratório

**Registro:** 05/11/2026, com solicitação expressa do proprietário: alterar o gate que bloqueava a continuidade do projeto. O cenário é o laboratório **local e isolado**; não inclui ambiente de produção.

## Problema e correção

`scripts/m1_evidence_gate.py` imprimia `DEPLOYMENT_GATE=BLOCKED` **incondicionalmente**, mesmo quando o objetivo era apenas avançar no trabalho documental/offline. Misturava **aceite final da mudança A** com **autorização limitada para trabalhar na próxima etapa**.

Adicionamos `--owner-continuation`, que valida uma declaração privada de risco do proprietário, dentro de `.lab/`. Somente quando **todos** os outros controles forem válidos e faltar **exatamente `manager_ingestion`**, e a exceção ainda estiver válida (máximo 48h), o retorno fica:

```text
EVIDENCE_COMPLETENESS=INCOMPLETE
MISSING_OR_UNVERIFIED=manager_ingestion
DEPLOYMENT_GATE=OWNER_SCOPED_LAB_CONTINUATION
PROJECT_CONTINUATION_GATE=OPEN
CHANGE_A_FINAL_ACCEPTANCE=PENDING_MANAGER_AND_REVIEW
PRODUCTION_DEPLOYMENT_GATE=BLOCKED
LIVE_CONFIGURATION_CHANGE_GATE=BLOCKED
MANUAL_INDEPENDENT_APPROVAL_REQUIRED=true
```

**Isso é um GO de continuidade restrita, não um GO de mudança de infraestrutura e não prova novos alertas do Manager.** A revisão independente continua exigida para a aprovação final, mas não impede trabalho offline e diagnósticos autorizados somente leitura.

## Uso no computador autorizado

```powershell
python scripts/m1_evidence_gate.py --manifest .lab/m1-evidence.json --stage postchange --owner-continuation .lab/m1-owner-scoped-continuation-20261105-private.json
```

No Windows também existe o atalho read-only `scripts/M1_CONTINUAR_LAB.bat`. Ele **somente executa o verificador**, não inicia VMs, não modifica arquivos nem instala nada.

Para comparar o **gate estrito** de aceite final:

```powershell
python scripts/m1_evidence_gate.py --manifest .lab/m1-evidence.json --stage postchange
```

Até o Manager ser atestado, o gate estrito continuará `BLOCKED`, com retorno 2. Ele não é usado para decidir se podemos continuar escrevendo código, testes offline e documentação.

## Condições e limites

- Proprietário autorizou em conversa; `authorized_by=project_owner_in_chat` é **declaração auditável, não assinatura criptográfica nem autenticação independente**.
- Exceção original privada: `.lab/m1-owner-scoped-continuation-20261105-private.json`, com validade até **06/11/2026 às 14h38 BRT**.
- A exceção **não libera** `manager_ingestion`, não atualiza seu status para `verified`, não suprime outros controles e não aceita inventário desatualizado.
- Não funciona com manifestos sintéticos (`--fixture`), arquivo fora de `.lab/`, exceção inválida/expirada, perda do rollback ou qualquer outra pendência além da explicitamente permitida.
- Ações **autorizadas por este GO:** codificação, documentação, CI, testes locais offline e verificações somente leitura previamente autorizadas.
- **Não** autoriza alteração em `agent.conf`, regras, auditoria 4698, testes ativos, reinicialização, deploy em produção ou merge automático.
- Toda mudança ativa futura precisa de janela e GO próprios. A ausência de revisão independente ainda bloqueia o aceite final, conforme política registrada.

## Como encerrar o bloqueio definitivo

1. Confrontar por acesso autorizado os eventos no log local do Manager com os **9 documentos reais** já confirmados em Indexer/Discover dos agentes `002`, `004` e `005`.
2. Registrar a evidência sanitizada em documentos públicos e manter logs e hashes privados em `.lab/`.
3. Solicitar a outra pessoa a revisão independente do PR #25, sem autoaprovação disfarçada.
4. Atualizar o manifesto privado **somente quando houver prova direta**, executar novamente o gate estrito e decidir sobre o aceite final.

**Referências:** [evidências FIM dos três agentes](m1-change-a-three-agent-fim-evidence-20261105.md) · [revisão técnica](m1-change-a-formal-evidence-review-20261105.md) · [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17).

**Teste do mecanismo:** `tests/test_m1_owner_continuation.py` cobre continuação permitida, bloqueio por expiração, escopo extra, outros gaps e flags indevidas. Os testes anteriores do gate estrito permanecem intactos.
