# M1 — checkpoint consolidado offline (sem consulta ao Wazuh)

**Finalidade:** obter, com um único comando, a contagem de checkboxes do [roadmap](roadmap-progress.md), o estado da triagem preliminar do Dashboard e a completude sintática do manifesto privado. Essa ferramenta **não coleta agentes**, não se conecta ao Manager, Indexer, Dashboard ou GitHub, não lê logs operacionais e **nunca autoriza implantação**.

## Executar no diretório do repositório

```powershell
python scripts/m1_checkpoint_summary.py
python scripts/m1_checkpoint_summary.py --format json
```

O comando lê **somente** estes dois arquivos privados já existentes sob `.lab/`:

- `.lab/m1-dashboard-observations-20261103.json`: observações da lista geral fornecida pelo operador. Aceita agentes desconectados e campos desconhecidos, sem transformá-los em confirmação de membros do grupo `default`.
- `.lab/m1-evidence.json`: manifesto de revisão de mudança do M1. O campo `manifest_missing_fields` conta **faltas de evidência e controles**, não falhas do Manager. Mesmo `DOCUMENT_COMPLETE_UNATTESTED` **não é aprovação humana**.

O caminho de ambos pode ser substituído via `--snapshot` e `--manifest`, porém **somente dentro da pasta privada ignorada pelo Git**, sem links simbólicos; arquivos inválidos ou ausentes ficam marcados como `UNAVAILABLE_OR_INVALID`. Não mostrar o conteúdo desses arquivos em PRs, relatórios públicos ou logs de CI.

O relatório apresenta apenas contagens agregadas e estados: agentes observados, ativos/desconectados, membros de grupo desconhecidos, sincronização e último keepalive desconhecidos, checklist e exigências faltantes no manifesto. **Nunca imprime IDs, IPs, hostnames, arquivos, referências individuais ou timestamps.** Em particular:

- `MANAGER_RUNTIME=NOT_CHECKED_BY_THIS_SCRIPT`: não substitui o checkpoint remoto somente leitura nem comprova saúde atual de agentes
- `GITHUB_REVIEWS=NOT_CHECKED_BY_THIS_SCRIPT`: não substitui aprovação formal independente do PR
- `OBSERVATION_STATE=PRELIMINARY_UNATTESTED`: snapshots privados não autenticam as capturas recebidas
- `OPERATIONAL_DEPLOYMENT_GATE=BLOCKED`: valor fixo, inclusive com todos os campos preenchidos

## Próximo requisito real

Operador autorizado deve abrir **Agents management → Groups → default** e confirmar os IDs de seus membros, depois verificar a data do último *keep-alive* do agente desconectado e a sincronização / precedência de grupos. Nenhum campo ausente deve ser preenchido por estimativa. Com esses dados, atualizar a documentação privada e submeter as decisões de mudança FIM e 4698 em trilhas separadas.

Os testes em `tests/test_m1_checkpoint_summary.py` usam diretórios temporários e evidências **sintéticas**; passar no CI prova o contrato do script, não que o ambiente produtivo esteja pronto.
