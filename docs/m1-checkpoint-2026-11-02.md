# M1 — Checkpoint técnico e pendências (02/11/2026)

> **Status: em andamento; mudança FIM não implantada.** Este relatório distingue testes offline, validação sintática no Manager e evidências operacionais. Dados sensíveis e artefatos privados não foram publicados.

## Resumo executivo

O laboratório Wazuh 4.14.9 possui histórico de telemetria e investigação documentada. No incremento M1, foram preparados três cenários de hunting (H01, H02, H03), comparadores offline de configuração FIM e um plano de mudança controlada para o grupo `default`. O objetivo imediato é reconciliar o inventário de todos os agentes e garantir que uma diretiva Linux não seja aplicada indiscriminadamente ao Windows.

## Evidências confirmadas

| Controle | Evidência / conclusão | Limite |
| --- | --- | --- |
| Testes Python do repositório | **73/73 PASS**, `unittest discover` executado em 02/11, exit 0 | Testes offline, não demonstram produção |
| Escopo FIM por OS | 15 testes PASS | Validador de fixtures |
| Guarda de diff mínimo | 21 testes PASS | Não substitui revisão de configuração ativa |
| Validação Wazuh da proposta | `verify-agent-conf` PASS sobre **cópia temporária isolada**, com original preservado e cópia removida | Sintaxe somente; **sem deploy** |
| Grupo distribuidor | `default` com **4 agentes** na consulta read-only | OS de todos os membros ainda não reconciliado |
| Agente Windows `004` | Sincronização PASS; parser/base intactos; configuração local FIM contém **6 diretórios existentes** (5 agendados, 1 realtime) | Não demonstra cobertura atual para cada artefato |
| Telemetria FIM no Indexer | **102** documentos históricos com `syscheck.path` para agente `004`; **0** na janela 31/10 00:00Z–03/11 00:00Z | Sem evidência FIM recente nessa janela, não concluir H03 |
| Auditoria Windows `4698` | Subcategoria relevante permaneceu sem habilitação; Security circular de 20 MB, 2 coletores Security eventchannel | Alteração separada, pendente de aprovação |
| Ensaio de backup/restauração | Em **arquivos XML sintéticos**, cópia e restauração conferidas por hash, exit 0 | **Não** comprova backup ou rollback da configuração real |

### Limites de interpretação

Os números do Indexer refletem somente índices e janelas consultados. A inexistência de evento recente não significa ausência de atividade nem falha comprovada de FIM. A proposta `os="^Linux"` foi aceita sintaticamente; ela não foi distribuída aos agentes. O ensaio de restauração utilizou apenas fixtures sintéticas em diretório temporário local.

## Gates obrigatórios antes da mudança FIM

- [ ] Reconciliar os **4 IDs** do grupo `default`: OS/versão, grupos, status, sincronização e impacto; usar somente acesso autorizado, sem contornar proteções.
- [ ] Revisar a seleção por OS e confirmar efeito esperado em cada endpoint Windows/Linux.
- [ ] Preparar e aprovar backup **real** com preservação de permissões; validar restauração em ambiente isolado e estabelecer rollback.
- [ ] Obter aprovação específica e janela para modificar `agent.conf` compartilhado.
- [ ] Após implantação autorizada, verificar distribuição, sincronização e FIM em endpoints reais com evento benigno aprovado e caminho/artefato correspondente no Manager → Indexer → Discover.
- [ ] Prosseguir nas três hipóteses H01–H03 com correlação em evidência real, timelines, falsos positivos e revisão independente antes de encerrar M1.

**Gate atual:** `DEPLOYMENT_GATE=BLOCKED`. Não há evidência suficiente para declarar inventário completo, deploy, pós-validação ou milestone M1 encerrado.

## Próximos passos

1. Completar inventário pelo console autorizado Wazuh e registrar dados sanitizados.
2. Fazer revisão humana do diff mínimo da configuração central e impacto nos quatro agentes.
3. Planejar janela, backup real, aprovação e critérios objetivos de parada/rollback.
4. Só então executar mudança e validar fim a fim, documentando evidências reais.

## Rastreabilidade

- [Roadmap M1](../ROADMAP.md)
- [Plano de segregação FIM por OS](m1-fim-os-scoped-remediation-plan.md)
- [Revisão de visibilidade Security/Sysmon/FIM](m1-native-windows-wazuh-visibility-review-20261102.md)
- [Change control da auditoria 4698 e FIM 004](m1-change-control-4698-fim-agent004.md)
- [Issue #17 — FIM central](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/17)
- [Issue #9 — hipóteses M1](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9)

Este resumo não contém logs brutos, arquivos de configuração reais, credenciais, endereços privados ou hashes de ativos.


## Atualização posterior — 02/11/2026, 22h49 BRT

- Implantado **somente no host de trabalho** um gate privado que retorna código **2** enquanto a mudança está bloqueada, evitando falso sucesso de automações.
- Criado o [PR #25](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/25) com validador de evidências fail-closed, documentação e 14 novos testes; **87/87 testes locais aprovados**. A publicação do código não autoriza alteração no Manager.
- Realizada **aquisição somente leitura** do arquivo central real em backup privado protegido por **DPAPI do usuário Windows**. SHA-256 conferido com a baseline já validada, e bytes recuperados por descriptografia em memória com hash idêntico. A configuração no Manager foi relida e permaneceu intacta.
- **Limite:** a restauração operacional de permissões/owner/distribuição não foi executada; inventário individual dos quatro agentes, aprovação e janela seguem pendentes. `DEPLOYMENT_GATE=BLOCKED`.
