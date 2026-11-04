# M1/H03 — exceção de revisão independente: laboratório individual

**Data da solicitação:** 04/11/2026, BRT. **Registro de governança:** [Issue #29 — exceção de autoavaliação](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/29).
**Mudança:** **C** — somente Windows Server / Wazuh agente `004`, proposta de FIM realtime em diretório de laboratório isolado.
**Modelo de trabalho:** proprietário e mantenedor individual, sem segundo revisor disponível.
**Status de governança:** `SOLO_EXCEPTION_REQUESTED_BY_OWNER=true`, `INDEPENDENT_REVIEW_PERFORMED=false`, `RISK_ACCEPTANCE_OF_SPECIFIC_TERMS=PENDING_RATIFICATION`, `CHANGE_C_EXECUTION=NO_GO`.

## Fundamentação

O proprietário declarou expressamente nesta conversa: **“vamos ter que fazer independente, o projeto é independente”**, após solicitar a preparação de uma **exceção formal de laboratório pessoal com aceitação explícita de risco e sem simular revisão independente**.

A exceção tem finalidade legítima: permitir a avaliação pelo próprio proprietário de um laboratório isolado sem afirmar que houve aprovação de terceiro. Ela **não deve ser registrada como review GitHub `APPROVED` de um revisor inexistente**, nem marcada como `HUMAN_REVIEW_VERIFIED=true` na trilha que ainda exige pessoa distinta.

## Riscos residuais que o proprietário deve aceitar expressamente

1. **Erro não detectado pela autoavaliação:** a mesma pessoa pode deixar passar falhas de configuração, seleção do diretório, permissões, impactar o agente ou produzir evidências insuficientes.
2. **Falha de segurança na ACL:** herança, permissões amplas, proprietário errado ou comportamento de reparse points podem permitir gravação indevida.
3. **Impacto de disponibilidade e telemetria:** uma diretiva realtime ou um reinício fora da janela pode interromper coleta, aumentar volume de eventos ou gerar falhas no Wazuh.
4. **Risco de recuperação:** o backup DPAPI `CurrentUser` depende do perfil da conta que o criou; a restauração foi validada apenas em memória, não aplicada ao arquivo ativo.
5. **Resultados incorretos do H03:** ausência de FIM de arquivo, erro de timestamps ou Sysmon ID 1 de outro binário pode gerar falso sucesso ou falso negativo.

**Aceitação formal proposta ao proprietário:**
> Como proprietário e único mantenedor do laboratório SOC, aceito explicitamente os cinco riscos residuais documentados acima e autorizo substituir **apenas na Mudança C** a revisão independente por uma autoavaliação formal com controles compensatórios. Reconheço que nenhuma revisão independente ocorreu. Mantenho todos os requisitos técnicos, de backup, janela, rollback e validação da configuração ativa. Não autorizo nesta exceção criar/alterar/executar o binário H03, modificar outros agentes, nem liberar automaticamente a implantação.

**Essa declaração só será considerada ratificada** quando o proprietário a confirmar explicitamente em registro verificável, após ter acesso à lista de riscos. O pedido de operar individualmente, isoladamente, não significa que cada risco detalhado já foi aceito.

## Controles compensatórios obrigatórios (não dispensáveis)

| ID | Controle | Evidência necessária | Estado |
| --- | --- | --- | --- |
| SC-01 | Escopo restrito ao agente `004` e pasta sem autorun | Diff mínimo local, inventário Windows e validação central/local | **Parcial** |
| SC-02 | Verificação da configuração Syscheck **ativa** | Dashboard autenticado ou API `GET /agents/004/config/syscheck/syscheck`, consulta read-only; comparar antes/depois | **Pendente** |
| SC-03 | Baseline e backup seguro | DPAPI do `ossec.conf`, hash original/recuperado, ACL do backup, confirmação da conta | **Concluído para o arquivo local** |
| SC-04 | Teste de recuperação isolada | Descriptografia em memória, SHA256 igual e corrupção rejeitada | **Concluído**; restauração operacional não ensaiada |
| SC-05 | Política ACL mínima | DACL proposta protegida de herança, SYSTEM + Administrators + operador SID real, sem escrita genérica | **Simulada e aprovada**; alvo inexistente |
| SC-06 | Gate de contrato | Testes locais e CI validado na versão que será implantada; bloqueio para falhas | **Testes locais anteriores aprovados; revalidar no cutover** |
| SC-07 | Janela e condições de parada | Autorização condicional do proprietário para 04/11/2026 18h–19h BRT; sem início automático | **Autorização condicional registrada** |
| SC-08 | Autoavaliação documentada e riscos específicos | Checklist assinado pelo próprio proprietário, com aceitação expressa acima | **Pendente ratificação** |
| SC-09 | Rollback restrito, monitoramento e limpeza | Checksum antes/depois, rollback aprovado da configuração local, saúde WazuhSvc | **Plano documentado; execução ainda não autorizada** |
| SC-10 | Separação de mudanças | Mudanças A/Linux e B/4698 fora do escopo; teste binário H03 fora da autorização | **Exigência mantida** |

## Como registrar a autoavaliação, sem falsificar review

- Registre a aceitação do risco como **comentário do proprietário** na Issue #9 ou nesta issue de exceção, com timestamp e referência a este documento.
- Na PR da mudança C, mantenha os checks de CI, testes e diff real; um comentário do próprio autor deve ser chamado **SELF-REVIEW**, nunca `independent approval`.
- Atribua o modelo `SOLO_OWNER_WAIVER` **apenas à mudança C** quando a aceitação for ratificada, sem transformar o registro em aprovação de um revisor inexistente.
- Não definir `MANUAL_INDEPENDENT_APPROVAL_REQUIRED=false` no validador M1 de `M1-FIM-OS-SCOPE`; aquele gate é de outra mudança e segue `BLOCKED`.

## Resultado esperado após ratificação

A exceção **resolve somente a falta de segunda pessoa na governança da Mudança C**, sob responsabilidade consciente do proprietário. Não libera o deploy sem configuração Syscheck ativa atestada, confirmação do SID/ACL no destino, backup e janela válidos no instante da mudança, integridade de configuração e critérios de parada. O primeiro teste de binário H03 requer autorização específica **à parte**.

**Decisão atual:** `OWNER_CONDITIONAL_CHANGE_APPROVAL=RECORDED` · `SOLO_EXCEPTION_REQUESTED=YES` · `RISK_ACCEPTANCE_RATIFIED=NO` · `INDEPENDENT_REVIEW=NOT_PERFORMED` · `H03_BINARY_TEST_APPROVAL=NO` · `DEPLOYMENT_GATE=BLOCKED`.

Referências: [pacote de aprovação da mudança C](m1-change-c-approval-cutover-package-20261104.md), [runbook de ACL/FIM](m1-h03-three-gates-acl-fim-sequence-20261104.md), [Issue H03 #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9).
