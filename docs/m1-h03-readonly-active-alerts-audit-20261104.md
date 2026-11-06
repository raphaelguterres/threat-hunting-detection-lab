# M1/H03 — auditoria sanitizada do arquivo de alertas ativo (04/11/2026)

**Captura:** 04/11/2026 às 15:44:46 BRT. **Origem:** Wazuh Manager 4.14.9, `/var/ossec/logs/alerts/alerts.json`, filtrado pelo agente `004`. **Modo:** leitura em streaming; somente contagens e timestamps normalizados são exibidos, sem exportar logs brutos, nomes de host, usuário, caminho, hash ou dados de eventos.

## Resultado da coleta reproduzível

| Campo | Valor |
| --- | ---: |
| Alertas do agente 004 no arquivo ativo | **623** |
| Documentos com objeto `syscheck` | **0** |
| Eventos FIM de arquivo (regras 550/553/554) | **0** |
| Eventos FIM de Registro (regras 594/597/598/750/751/752) | **0** |
| Eventos de canal Sysmon | **318** |
| Sysmon Event ID 1 | **176** |
| Eventos de canal Security | **278** |
| JSON inválido / timestamp inválido | **0 / 0** |

**Janela dos registros do agente `004` nesse arquivo:** 2026-11-04T00:04:04.793Z até 2026-11-04T18:43:35.696Z. Trata-se apenas do **arquivo de alertas ativo** e de seu conteúdo no instante da leitura, não de todos os registros do dia, da rotação histórica ou do Indexer.

## Reprodutibilidade

O novo script [`scripts/m1_h03_readonly_manager_alert_audit.py`](../scripts/m1_h03_readonly_manager_alert_audit.py) percorre o arquivo JSONL em streaming e imprime exclusivamente agregados. Pode ser aplicado a uma cópia autorizada de `alerts.json`, por exemplo:

```powershell
python scripts/m1_h03_readonly_manager_alert_audit.py --input .lab/alerts.json --agent-id 004
```

No checkpoint real, **o código** do script foi enviado via stdin do PowerShell remoto para o Python no contêiner Manager; **os eventos não foram copiados para o host ou para o Git**. Para repetir, operador com SSH autenticado pode usar as variáveis privadas `WAZUH_SSH_KEY` e `WAZUH_SSH_TARGET` (não registrar seus valores):

```powershell
$source = Get-Content 'scripts/m1_h03_readonly_manager_alert_audit.py' -Raw -Encoding UTF8
$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($source))
$remote = "printf %s $b64 | base64 -d | docker exec -i single-node-wazuh.manager-1 /var/ossec/framework/python/bin/python3 - --input /var/ossec/logs/alerts/alerts.json --agent-id 004"
ssh -T -i $env:WAZUH_SSH_KEY $env:WAZUH_SSH_TARGET $remote
```

**Atenção:** o script não produz uma conclusão de incidente nem acessa Indexer, Dashboard, configurações ou VMs diretamente. O arquivo pode crescer, rotacionar e mudar enquanto é lido. Não comparar suas contagens com Discover sem igualar janela, fonte e fuso.

## Interpretação e decisão

- A presença de **176 eventos Sysmon ID 1** confirma visibilidade de eventos de processo **no recorte do arquivo ativo**, mas não a execução de um binário previamente alterado.
- **Zero FIM de arquivo** no recorte não prova FIM desativado: o agente 004 está ativo, a configuração local contém cinco caminhos periódicos e um realtime, uma varredura Syscheck foi registrada hoje e o Indexer já exibiu alertas FIM de Registro em outra janela.
- O arquivo `archives.json` anteriormente encontrado não está atualizado e `logall_json=no`; não substituir a falta de dados por inferências ou testes não autorizados.
- **H03 continua INCONCLUSIVE.** Para o próximo gate: selecionar previamente **um executável descartável e benigno**, confirmar a diretiva local que cobre seu caminho e as exclusões, determinar realtime versus periodicidade de 12 horas, verificar que Sysmon ID 1 coleta a imagem correspondente e obter autorização expressa antes de qualquer escrita/execução de teste.
- A mudança Linux OS-scoped e a auditoria Windows 4698 têm gates **independentes**; não estão autorizadas por este checkpoint.

**Estado final:** `TEST_APPROVED=NO`; `H03_REAL_PAIR=INCONCLUSIVE`; `DEPLOYMENT_GATE=BLOCKED`. O script teve quatro testes unitários sintéticos aprovados antes do registro; resultados de CI devem ser verificados separadamente.

[Diagramas e escopos do M1/H03](m1-scope-and-h03-diagrams-20261104.md) · [Pré-gate do artefato](m1-h03-artifact-coverage-preflight-20261104.md)
