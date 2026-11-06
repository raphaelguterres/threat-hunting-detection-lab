# M1 — FIM em três agentes: evidência pós-mudança A (05/11/2026)

**Checkpoint: 14h15 BRT.** O teste benigno pós-change nos três agentes resultou em **nove documentos FIM reais indexados e visíveis no Wazuh Discover** (3 por agente). Isso sustenta a cobertura de **Indexer → Dashboard**, **não** atesta por si só a leitura independente do `alerts.json` no Manager ou revisão independente formal.

## Governança e janelas

- O teste Linux `002` foi autorizado para a janela 13h18min53s–13h48min53s BRT.
- Os testes Windows `004` e Kali nativo `005` foram executados sob outra janela de teste registrada em `.lab/`, das **13h55min48s às 14h25min48s BRT**, com aprovação de proprietário, escopo de arquivos inertes e limites operacionais.
- Nova autorização explícita do proprietário recebida posteriormente, com janela adicional **14h12min43s–14h42min43s BRT**. **Não foram repetidos testes ativos** nessa janela: as ações `004` e `005` já haviam sido concluídas. Esta sessão consolidou evidências e verificou limpeza/integridade em modo somente leitura.
- Nenhuma autorização aqui se estende para `auditpol 4698`, alterações B/C, executáveis H03, malware, mudança de regras, reinício de VMs/serviços ou merge automático.

## Evidências FIM reais

| Agente | Sistema | Teste de arquivo descartável | Documentos no Discover `wazuh-alerts-*` | Resultado |
| --- | --- | --- | ---: | --- |
| `002` | Linux em contêiner de laboratório | Criar, alterar, excluir; limpeza confirmada | **3** (`added`, `modified`, `deleted`) | **Indexer + Discover comprovados** |
| `004` | Windows Server | Criar, alterar e excluir artefato inerte em diretório já monitorado; diário e limpeza locais | **3** (`added`, `modified`, `deleted`) | **Indexer + Discover comprovados** |
| `005` | Kali Linux nativo | Executado **localmente com autenticação sudo legítima** no diretório monitorado; criar, alterar e excluir, limpeza confirmada | **3** (`added`, `modified`, `deleted`) | **Indexer + Discover comprovados** |
| **Total** | | | **9** | **Cobertura FIM observada em 3/3 agentes** |

Para `004`, o relatório privado `.lab/m1-fim004-windows-discover-20261105-private.json` e as telas de Discover individuais vinculam os eventos ao mesmo artefato. Para `005`, a consulta do Discover foi feita por `agent.id: 005` e fragmento exato do nome do arquivo de teste, retornando **três hits**. Os horários exibidos no Dashboard têm convenção diferente do host BRT (diferença observada de ~2h); o relógio do guest havia mostrado desvio adicional de ~22 s. A identidade do arquivo e a sequência de ações são os correlatos, não o horário isolado.

## Verificações posteriores

- Após o teste `005`, o arquivo descartável não estava mais no caminho monitorado, confirmado por verificação de existência. Os três agentes permaneciam **Active**; hash da configuração A central permaneceu igual à candidata aprovada.
- Evidências completas (nomes dos artefatos, capturas, datas, identificadores e registros de autorização) permanecem **privadas em `.lab/`**. Não incluir paths privados, IPs, nomes de host ou alertas brutos no GitHub.
- **Manager — verificação independente do log local ainda NÃO confirmada**. O metadado `manager.name` nos alertas indexados não substitui essa conferência.
- **Revisão formal independente/segregação de funções ainda pendente**; `DEPLOYMENT_GATE=BLOCKED` é uma proteção intencional do gate, não um sinal de que o teste FIM falhou.

## Próximos procedimentos

1. Revisar, por **interface e permissão já autorizadas**, os alertas pós-change no log do Manager, comparando mesma identidade de evento e agente com os três conjuntos do Indexer/Discover, sem contornar bloqueio de acesso.
2. Consolidar a matriz 002/004/005 com a evidência privada e revisão humana; atualizar o manifesto privado **apenas para critérios verdadeiramente comprovados**, sem forçar `REVIEW_READY`.
3. Obter revisão independente do PR e da evidência, concluir os critérios formais de aceite da mudança A, e somente então decidir sobre encerramento de issue e merge. Não remover backup/rollback prematuramente.

**Roadmap M1 ainda 11/17:** o incremento de threat hunting inclui entregas independentes da validação FIM da mudança A.

Referências: [relatório FIM 002](m1-change-a-benign-fim-test-20261105.md) · [matriz de aceitação](m1-fim-acceptance-matrix.md) · [Issue #17](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17).
