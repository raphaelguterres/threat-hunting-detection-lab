# M1 — conciliação FIM: configuração local versus alertas indexados

**Checkpoint:** 03/11/2026. Auditoria somente leitura de resultados já preservados. Nenhum evento de teste gerado, alteração operacional ou exportação bruta.

## Evidências de procedência distinta

| Evidência | Resultado | Limite |
| --- | --- | --- |
| Auditoria privada de configuração do Windows `004` (02/11) | `FIM_DISABLED=no`, 6 diretórios locais, 5 agendados, 1 realtime e 23 regras de registry | Configuração não equivale a produção de alerta para arquivo |
| Verificação de cobertura (02/11) | Os 6 diretórios existiam; frequência de varredura 43.200 segundos; amostra de log tinha 5 menções a scan e 0 erros FIM capturados pelo filtro | Não confirma ausência de erros fora do recorte nem sucesso de todas as etapas da ingestão |
| Discover autenticado (03/11, últimas 24h) | 488 registros com `agent.id:004 and syscheck.path:*`; 126 sem `syscheck.value_type`; 0 para `agent.id:004 and syscheck.path:* and not syscheck.path:HKEY*` | Janela móvel; a segunda consulta inclui registros de Registro, e a terceira exige confirmação do mapeamento/cobertura do campo |

## Interpretação

Há configuração local FIM existente e telemetria Syscheck de Registro indexada, mas não foi demonstrado alerta recente de **arquivo** para o agente 004. Não há base para afirmar quebra do FIM, nem validar H03 (arquivo modificado → execução do mesmo artefato via Sysmon ID 1).

## Próximo gate somente leitura

1. No Discover autenticado, preservar o filtro `agent.id:004 and syscheck.path:* and not syscheck.path:HKEY*` e ampliar para **Last 7 days**; registrar total, fuso e horário de consulta. Não misturar com o resultado de 24 horas.
2. Se houver resultados, conferir privadamente se `syscheck.path` é um caminho de arquivo Windows, a identidade do endpoint, timestamps e o tipo de modificação. Verificar os documentos originais antes de normalizar aliases.
3. Se continuar zero, verificar mapeamento DQL e revisar cobertura dos seis diretórios e scan em fonte autorizada; não criar alteração de arquivo ou forçar novo scan sem aprovação específica.
4. Correlacionar com evento Sysmon 1 somente depois de identificar um **mesmo artefato** e uma ordem temporal compatível (até 20 minutos). Candidato não é incidente confirmado.

**Estado:** `H03=INCONCLUSIVE`; `DEPLOYMENT_GATE=BLOCKED`; aprovação independente e evidência operacional ainda ausentes.
