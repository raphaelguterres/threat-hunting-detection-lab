# Registro de falsos positivos e exceções

Use este registro para documentar decisões de triagem sem transformar supressões temporárias em regras permanentes.

| Data | Regra/caso | Tipo de evidência | Decisão | Causa e contexto | Ajuste/exceção | Responsável | Expiração e reteste |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 25/10/2026 | `100100`–`100103` | Marcadores sintéticos `LAB_*` | Simulação autorizada | Linhas de teste identificadas por execução controlada | Não suprimir a regra; classificar pelo marcador e preservar a evidência | Laboratório | Revisar a cada novo roteiro |
| 25/10/2026 | FIM Kali nativo | Controle fora do escopo | Benigno esperado | Arquivo criado fora do diretório monitorado não gerou alerta | Nenhum | Laboratório | Reexecutar se o escopo FIM mudar |
| 26/10/2026 | SSH `5715` / `T1078`, `T1021` | Sucesso SSH + sessões PAM no Kali | Benigno esperado | Chave do orquestrador coincidiu com o log; origem host-only e janela de manutenção documentadas | Nenhum; manter os alertas visíveis | Laboratório | Retriar se conta, chave, origem, volume ou sequência mudar |

## Regras de uso

1. Um marcador `LAB_*` comprova somente o pipeline e deve ser classificado como simulação autorizada.
2. Exceções exigem proprietário, justificativa, data de expiração e reteste antes de renovação.
3. Nunca criar supressão permanente com base apenas em nome de processo, usuário ou origem sem contexto de mudança aprovada.
