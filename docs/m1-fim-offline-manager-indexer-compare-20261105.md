# M1 — conciliação offline do Manager com o Indexer (FIM 002/004/005)

**Criado em 05/11/2026. Modo de operação:** leitura **somente de arquivos locais fornecidos pelo operador**, sem rede, API, SSH, Docker, VM, edição de configurações ou coleta ativa de alertas. Esta ferramenta é a preparação offline da única lacuna técnica da mudança A: `manager_ingestion`.

## Por que existe

O Discover mostrou **9 documentos FIM reais**, três por agente (002, 004 e 005; `added`, `modified`, `deleted`). Isso comprova Indexer/Discover, mas não uma segunda leitura do `alerts.json` do Manager. Esta ferramenta compara **exportações já autorizadas** usando a mesma identidade de evento, em vez de presumir correspondência por contagem.

**Não foi feita exportação direta do Manager nesta entrega.** O acesso aos registros locais do Manager já havia sido restringido e **não foi contornado**; nenhum arquivo `alerts.json` foi copiado, nem foram produzidos resultados reais de correspondência com Manager. O modo sintético é exclusivo de testes de contrato.

## Arquivos esperados (todos em `.lab/`, ignorada pelo Git)

| Arquivo privado, nome de exemplo | Formato |
| --- | --- |
| `.lab/m1-manager-authorized-export.jsonl` | **Uma linha JSON por alerta real**, exportada do Manager pela interface autorizada: campos `id`, `timestamp` com fuso explícito, `agent.id`, `rule.id`, `syscheck.path` e `syscheck.event` |
| `.lab/m1-indexer-authorized-export.jsonl` | **Uma linha JSON por documento indexado**, com os mesmos campos. Aceita formato `{"_source":{...}}` de exportação do Indexer |
| `.lab/m1-probe-scope-private.json` | Objeto JSON com chaves `002`, `004`, `005` apontando para **os caminhos completos e exatos dos três arquivos descartáveis originais**; não publicar |

Esses arquivos **não existem automaticamente**: é preciso exportá-los por procedimento e permissão legítimos. Não use arquivos ou IDs fictícios para reivindicar aprovação do Manager. O comparador recusa diretórios fora de `.lab/`, links simbólicos e fontes acima de 2 MiB por arquivo. As exportações devem conter o `id` real do **mesmo evento** em ambas as fontes; se o Indexer não fornecer `_source.id` correspondente, o resultado será inconclusivo, não PASS.

Exemplo de **estrutura** da identificação de escopo, com placeholders apenas para orientação (não copiar como evidência):

```json
{
  "002": "CAMINHO_REAL_DO_ARQUIVO_LINUX_002",
  "004": "CAMINHO_REAL_DO_ARQUIVO_WINDOWS_004",
  "005": "CAMINHO_REAL_DO_ARQUIVO_LINUX_005"
}
```

## Execução no PC Windows

Após o operador salvar as **três fontes reais** no diretório privado, executar na raiz do projeto:

```powershell
.\scripts\M1_COMPARAR_EXPORTS_FIM.bat
```

Ou, para escolher nomes diferentes de arquivos:

```powershell
python scripts/m1_fim_offline_source_match.py --manager .lab/m1-manager-authorized-export.jsonl --indexer .lab/m1-indexer-authorized-export.jsonl --scope .lab/m1-probe-scope-private.json
```

A ferramenta recusa JSONL malformado, chaves duplicadas, ids duplicados, `NaN`, timestamps sem fuso, operação inesperada no artefato, divergência de ID, regra, agente ou arquivo, diferença de tempo superior a 90 segundos, e conjuntos diferentes dos **9 eventos/3 por agente**. Não imprime nomes de host, caminhos, IDs, hashes ou linhas brutas, mesmo quando falha; retorna **código 2** para dados incompletos, acesso negado ou mismatch.

### Exemplos de saída sanitizada

- `comparison=MATCHED_PRIVATE_EXPORTS`: nove coincidências reais nos arquivos fornecidos, mas **ainda não constitui atestado independente** do Manager.
- `comparison=MISMATCH_OR_INCOMPLETE`: não há coincidência completa no recorte fornecido, sem afirmar falha geral do Wazuh.
- `OFFLINE_FIM_MATCH=INPUT_REJECTED`: entrada ausente, inválida ou fora do escopo.

O resultado inclui sempre `input_provenance=operator_supplied_not_independently_attested`, `independent_manager_attestation=false`, `independent_reviewer_verified=false` e `no_live_actions=true`. **Não atualizar `manager_ingestion` para `verified` automaticamente com essa saída**, nem mudar `DEPLOYMENT_GATE` de aceite final.

## Testes e garantias

`python -m unittest discover -s tests -p test_m1_fim_offline_source_match.py -v` exercita 11 cenários, incluindo match 9/9 sintético, ID divergente, artefato errado, relógio/regra incompatível, escopo, chaves duplicadas, timestamps sem timezone, ausência de eventos e proteção da saída. Fixtures para CI são geradas temporariamente e claramente rotuladas `synthetic`, não são evidência real.

**Continuar com o GO limitado do proprietário:** [autorização de continuidade](m1-owner-scoped-continuation-go-20261105.md). **Não** autoriza consulta por canal bloqueado, alterações ativas, nova simulação, deploy ou merge. Para aceite final ainda são necessários exportação direta autorizada do Manager e parecer de outro revisor habilitado.

**Referências:** [evidências reais Indexer/Discover](m1-change-a-three-agent-fim-evidence-20261105.md) · [revisão técnica](m1-change-a-formal-evidence-review-20261105.md) · [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17).
