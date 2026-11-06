# Registro de falsos positivos e exceções

Use este registro para documentar decisões de triagem sem transformar supressões temporárias em regras permanentes.

| Data | Regra/caso | Tipo de evidência | Decisão | Causa e contexto | Ajuste/exceção | Responsável | Expiração e reteste |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 25/10/2026 | `100100`–`100103` | Marcadores sintéticos `LAB_*` | Simulação autorizada | Linhas de teste identificadas por execução controlada | Não suprimir a regra; classificar pelo marcador e preservar a evidência | Laboratório | Revisar a cada novo roteiro |
| 25/10/2026 | FIM Kali nativo | Controle fora do escopo | Benigno esperado | Arquivo criado fora do diretório monitorado não gerou alerta | Nenhum | Laboratório | Reexecutar se o escopo FIM mudar |
| 26/10/2026 | SSH `5715` / `T1078`, `T1021` | Sucesso SSH + sessões PAM no Kali | Benigno esperado | Chave do orquestrador coincidiu com o log; origem host-only e janela de manutenção documentadas | Nenhum; manter os alertas visíveis | Laboratório | Retriar se conta, chave, origem, volume ou sequência mudar |

## Revisão M1 — 05/11/2026: falsos candidatos de CORRELAÇÃO, não falsos alertas de origem

As linhas abaixo representam **decisões de triagem e revisão de tuning**, **não** métricas de falsos positivos reais produzidos por detecções H01/H02/H03. O motor permanece offline e nenhuma regra/supressão Wazuh foi editada. [Parecer com evidências, recortes e ATT&CK](m1-hunting-tuning-fp-attack-review-20261105.md).

| Data | Hipótese/caso | Evidência real observada | Potencial falsa conclusão | Decisão de tuning / supressão | Reteste e responsável |
| --- | --- | --- | --- | --- | --- |
| 05/11 | **H01 — PowerShell → tarefa criada** | `110120` ocorreu **1h02m23s antes** de `110100`; criação `4698` não confirmada | Confundir `schtasks /create` com tarefa registrada, ou ignorar ordem e janela de 15 min | **Não abrir par nem criar supressão**; exigir evento `4698` real + mesmo ativo/ator + ordem. Nenhuma mudança de regra | Operador SOC; reavaliar após change `4698` aprovado, com Security 20 MiB e sobreposição de coletores avaliados |
| 05/11 | **H02 — conta criada → privilégios** | Um `4720` com SID real; **zero** `4624/4672` do **mesmo SID** em 30 min | Atribuir logon de outra conta à conta recém-criada | **Não correlacionar por contagens nem suprimir `4720/4672`**; manter junção SID e Logon ID. Nenhuma mudança de regra | Operador SOC; reavaliar com evento real de mesma identidade ou nova janela autorizada |
| 05/11 | **H03 — FIM → execução** | **9 eventos FIM reais** de arquivos inertes de laboratório (002/004/005), sem execução do mesmo artefato confirmada | Chamar FIM benigno de execução/comprometimento ou falso alerta de FIM | **Classificar alteração como verdadeira e benigna**, exigir Sysmon 1 do mesmo arquivo para H03; não suprimir alertas FIM. Nenhuma mudança de regra | Operador SOC; reavaliar quando houver Sysmon 1 do mesmo artefato verificado, mantendo contexto de autorização |

**Controles:** H01 tem um contraexemplo temporal real; H02 tem um contraexemplo real de junção por identidade; H03 **não** teve experimento negativo independente e isso **não** deve ser interpretado como prova de ausência de execução. **Taxa de FP não calculada** e nenhuma alteração de severidade ou filtragem aplicada.

## Regras de uso

1. Um marcador `LAB_*` comprova somente o pipeline e deve ser classificado como simulação autorizada.
2. Exceções exigem proprietário, justificativa, data de expiração e reteste antes de renovação.
3. Nunca criar supressão permanente com base apenas em nome de processo, usuário ou origem sem contexto de mudança aprovada.
