# CASE-004 — Alteração de integridade de arquivo

## Situação

**Estado:** FIM Windows observado ponta a ponta; estudo aguarda evidência redigida consolidada.

## Hipótese de investigação

Uma alteração em arquivo monitorado pode ser manutenção aprovada ou modificação indevida. O caso deve correlacionar caminho, hashes, horário e responsável.

## Evidência exigida

- Evento `syscheck_integrity_changed` do agente Windows.
- Caminho e hashes antes/depois, redigidos quando necessário.
- Registro da alteração de teste autorizada.

## Linha do tempo

| Horário | Evento | Fonte | Observação |
| --- | --- | --- | --- |
| Observado | Arquivo de teste alterado | Wazuh FIM | Evidência bruta permanece local |

## Classificação e ação

Verificar se a mudança foi aprovada. Se não for, preservar o artefato e recomendar revisão do proprietário do arquivo antes de qualquer contenção.
