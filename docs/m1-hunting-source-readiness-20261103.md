# M1 — prontidão das fontes e investigação H01/H02/H03

**Checkpoint:** 03/11/2026. **Escopo:** somente a evidência real previamente examinada no laboratório autorizado, sem coleta de novos eventos, sem replay/simulação, sem alteração em VMs. **Estado:** `NO-GO` para declarar qualquer hipótese validada ponta a ponta.

Esta matriz não é o resultado de uma consulta atual aos eventos do Manager/Indexer. Ela reúne fatos observados em **recortes anteriores**, que podem estar defasados. Uma ausência no recorte **não** equivale à ausência do comportamento no ambiente. As capturas e referências individuais devem permanecer em `.lab/` privado.

## Nova coleta real do Windows Server — 03/11 (~20h25 BRT)

Foi realizada uma [nova auditoria agregada, somente leitura](m1-native-telemetry-checkpoint-20261103.md) na janela **02/11 00:00 UTC a 04/11 00:00 UTC** (limite final futuro). Contagens observadas: **4698=0**, **4720=0**, **4672=289**, **4624=295**, **Sysmon ID 1 ≥2.000** (consulta limitada a 2.000). A correlação local H02 não encontrou criação de conta nem par 4624/4672 vinculado à mesma conta: **fonte inicial insuficiente na janela**, não declaração de ausência de ameaça. A auditoria `Other Object Access Events` permaneceu desabilitada.

A tela de Discover estava indisponível com `Wazuh dashboard server is not ready yet`, e **não houve nova validação de um par FIM→execução H03**. O status `RUNNING` do contêiner não equivale a disponibilidade da aplicação. As capturas individuais da VM ficaram na área privada `.lab/`, sem exportar eventos brutos.

## Critérios gerais de evidência

O correlacionador offline lê **exatamente sete campos** normalizados e pseudonimizados, com fonte permitida e timestamp com fuso. Identidades ambíguas ou marcadores como `UNKNOWN`, `UNVERIFIED`, `PENDING`, `TBD`, `placeholder`, `NULL`, `N/A` e caracteres de controle/Unicode invisíveis agora são recusados, inclusive nos campos usados para unir pares. A ausência de identidade verificável deve ser relatada como **lacuna**, não convertida em valor compartilhado. Um par candidato **nunca** confirma automaticamente incidente, intenção maliciosa ou causalidade.

| Hipótese | Fontes A → B exigidas | Última evidência real revisada | Estado de cobertura no recorte | Próxima comprovação autorizada |
| --- | --- | --- | --- | --- |
| **H01 — PowerShell → tarefa realmente criada** | Sysmon Event ID 1 ou regra 110100 confirmada → **Security 4698** (mesmo ativo/ator, até 15 min) | Regra 110120 de `schtasks /create` ocorreu **antes** de 110100 em uma amostra histórica, fora da sequência/janela. O Windows apresentava `Other Object Access Events = No Auditing` e nenhum 4698 no recorte de 02/11 | **Fonte B de criação confirmada não estabelecida; correlação real H01 não validada** | Aprovar **separadamente** mudança auditpol/retention na [Issue #15](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15); após autorização, conferir 4698 verdadeiro, identidade da tarefa e actor/host, e validar ingestão |
| **H02 — conta local criada → logon privilegiado** | **Security 4720** → **Security 4672**, com associação verificável ao 4624/Logon ID e conta recém-criada (até 30 min) | Um 4720 na leitura histórica; nenhum 4624/4672 vinculado ao mesmo SID nos 30 minutos seguintes do recorte revisto | **Incompleto/inconclusivo; não transformar 4672 de outra conta em candidato** | Conferir no Wazuh/Windows as fontes, as identidades e Logon ID sob acesso autorizado; se não houver o evento complementar, manter sem candidato na amostra e registrar cobertura temporal |
| **H03 — alteração FIM → execução do mesmo arquivo** | Wazuh FIM com arquivo/hash → Sysmon Event ID 1 com **mesmo artefato** e mesmo ativo (até 20 min) | Indexer tinha 102 registros FIM **históricos** do Windows 004, mas zero na janela 31/10–03/11 anteriormente consultada. O agente Kali 005 exibe FIM realtime de laboratório; Windows 004 exibe uma diretiva Unix indevida | **Não há par real atribuído e validado no recorte**; a presença da diretiva FIM não prova um alerta | Validar a cobertura real de um arquivo autorizado e a trilha **endpoint → Manager → Indexer → Discover** após correção FIM aprovada; comparar caminho normalizado, hash e execução sem gerar atividade não autorizada |

## Procedimento de análise, sem mutações

1. Confirmar a **janela temporal exata** e o fuso na fonte original. Registrar início/fim, filtros utilizados e limitações da consulta; **não misturar evidências de janelas diferentes**.
2. Para cada hipótese, inspecionar **as duas fontes necessárias** em interface/canal **já autorizado**. Capturas em `.lab/`, sem publicar hostnames, IPs, SIDs, nomes de conta ou valores de comandos.
3. Apenas depois de confirmar a relação real entre identidades, normalizar aliases estáveis. Caso conta, ator, arquivo ou host estejam indefinidos, **não inserir placeholders** nem fabricar a junção.
4. Executar, a partir da raiz do repositório, `python scripts/hunt_correlations.py --input .lab/m1-normalized-events.jsonl` **apenas quando o arquivo privado tiver sido preenchido com dados reais auditados**. O motor não acessa rede, VMs ou dados brutos.
5. Para cada par retornado, conferir a telemetria original, causalidade possível, explicações benignas, falso positivo e autorização de mudanças. Os estados `triage_candidate`, `no_candidate_in_supplied_sample` e `insufficient_source_coverage` **não são decisões de incidente**.
6. Publicar somente um parecer sanitizado: `verified`, `partial`, `inconclusive` ou `not_tested`, citando a referência privada sem reproduzir seu conteúdo. Se apenas um lado da hipótese existe, o estado correto é **insuficiência de fonte**, não resultado negativo definitivo.

## Controles negativos obrigatórios

- **H01:** 110120 isolado não satisfaz 4698; não correlacionar se o evento B preceder o A ou se os atores/hosts divergirem.
- **H02:** usar conta-alvo real (4720) e prova do logon correspondente; um 4672 genérico do administrador não atribui automaticamente privilégio à conta recém-criada.
- **H03:** exigir o **mesmo artefato**, não apenas nomes parecidos; outro host, mudança fora da janela ou execução anterior não geram candidato.

## Onde estão as próximas dependências

- [Issue #9 — Threat Hunting](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9): aceitação das hipóteses com dados reais
- [Issue #15 — auditoria 4698](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15): autorização separada, retenção e rollback
- [Issue #17 — FIM por OS](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17): correção mínima Linux ainda não aplicada
- [Issue #27 — agente legado 001](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/27): decisão formal pendente
- [Guia original das três hipóteses](m1-three-hunting-hypotheses.md): critérios de junção e exemplos sintéticos

**Decisão de hoje:** o motor offline foi reforçado e testado; **nenhuma hipótese H01/H02/H03 recebeu validação real nova nesta rodada**. O gate de implantação FIM permanece `BLOCKED`.
