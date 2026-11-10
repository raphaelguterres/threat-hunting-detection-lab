# M1 — Retomada remota e reconciliação read-only — 10/11/2026

**Escopo:** Windows host, VirtualBox, Wazuh 4.14.9 e contratos offline do projeto. Não houve instalação, alteração de auditoria, modificação de FIM, restart, replay, execução de artefato H03, merge ou encerramento de M1 nesta retomada.

## Evidências obtidas hoje

- Desktop Commander conectado ao host Windows; VMs Kali e WindowsServer observadas `running` no VirtualBox. Isso **não** comprova saúde interna dos guests.
- A interface host-only do host e a interface Kali compartilham a rede privada. O operador confirmou ping Kali → host com **2/2 respostas**; o host confirmou ping host → Kali com **2/2 respostas**.
- Após aquecimento dos serviços, SSH passou a responder; `docker ps` reportou Manager, Indexer e Dashboard em execução.
- As portas do host para o Kali `22`, `443`, `9200`, `55000`, `1514` e `1515` responderam. Uma consulta HTTP sem autenticação no Indexer retornou `401`, confirmando resposta protegida, **não** resultado de busca ou ingestão.
- `agent_control -l` no Manager listou `002`, `004` e `005` como `Active` após uma leitura transitória na qual `002` estava `Pending`. Agente `003` continua `Never connected`. Status de grupo/sincronização de **hoje** não foi novamente atestado pela API nessa coleta.
- O painel M1 produzido por `scripts/roadmap_progress.py` permanece em **15/17 (88,2%)**, com dois itens abertos; esse percentual **não** é um nível de segurança ou de prontidão para deploy.
- O prechange `scripts/m1_evidence_gate.py` informou `EVIDENCE_SOURCE=PRIVATE_UNATTESTED`, `EVIDENCE_COMPLETENESS=INCOMPLETE`, três observações de frescor de agentes pendentes e `DEPLOYMENT_GATE=BLOCKED`.
- Suíte local: **277 testes aprovados, 4 ignorados e 197 subtestes aprovados**. Recorte de contratos H01/H02/H03: **50 testes e 29 subtestes aprovados**. Parser PowerShell dos dois scripts locais novos: zero erros. `git diff --check` sem erros de patch (aviso de LF/CRLF).
- O trabalho local anterior do Codex (dois Markdown modificados e cinco arquivos não rastreados) foi preservado; **nenhum** dos scripts novos foi invocado nesta retomada.

## H03 / Change C

- O preflight e a verificação DPAPI de 10/11 foram reportados na documentação local anterior; **não foram reexecutados** durante esta retomada. O alvo `C:\SecurityLab\H03` permanecia ausente na última observação documentada; não há comprovação de cobertura FIM realtime ou correlação FIM → Sysmon ID 1 do mesmo executável.
- O executor ainda não rastreado `scripts/M1_H03_CHANGE_C_PREPARE.ps1` possui janela embutida de **10/11 18:21:52–18:51:52 UTC**, expirada antes da leitura desta sessão. É um script **com efeitos sobre NTFS** (criação de diretórios protegidos), não um verificador read-only. **Não executar/reaproveitar uma janela expirada.**
- Não foi autorizada nova janela restrita C1/C2/C3 nesta retomada. Uma nova decisão de mudança deve renovar aprovação, instante, baseline, SIDs efetivos, backup e plano de rollback. A autoavaliação formal de Change C **não** equivale a revisão independente do M1.
- A execução de binário benigno H03 continua uma aprovação **separada**, depois da confirmação operacional de FIM. Nenhuma hipótese H01/H02/H03 foi encerrada como correlação ponta a ponta real.

## Decisão

`PROJECT_READONLY_CONTINUATION=PASS` · `CHANGE_C=NOT_EXECUTED` · `M1=15/17` · `DEPLOYMENT_GATE=BLOCKED` · `INDEPENDENT_M1_REVIEW=NOT_VERIFIED`.

**Evidências privadas:** snapshots e diagnóstico de rede de 10/11 permanecem apenas na pasta ignorada `.lab/`. Não publicar conteúdo de endpoint, IPs internos, hashes privados, identidades, credenciais ou capturas integrais.

**Sequência para encerrar os dois itens restantes:** (1) nova autorização e controles da Change C, cobertura ativa e ensaio benigno autorizado para H03; (2) completar associações reais de H01/H02/H03 com origem → Manager → Indexer → Discover e controles negativos; (3) obter revisão independente documentada do M1, sem simular aprovação.
