# M1/H03 — decisão de segurança sobre o único FIM realtime do Windows 004

**Checkpoint:** 04/11/2026, ~16h27–16h31 BRT. **Escopo:** VM Windows Server 2022, agente Wazuh `004`, consultas locais read-only e classificação offline. **Conclusão:** `H03_REALTIME_CANDIDATE=NO_GO`. Não houve criação/edição/execução de artefato H03 nem mudança de configuração, serviço, política ou índice.

## Identificação direta no agente 004

Em PowerShell dentro da VM, foi lido o XML local `ossec.conf` sem alterá-lo. O único nó `syscheck/directories` com `realtime="yes"` aponta para a pasta **Startup do Menu Iniciar de todos os usuários**, sob `%PROGRAMDATA%`. O diretório foi confirmado existente na VM via expansão da variável + `Test-Path=True`. O canal `Microsoft-Windows-Sysmon/Operational` retornou `IsEnabled=True`.

As exclusões locais visíveis incluíam um `desktop.ini` da pasta Startup e padrões de extensões de documentos/logs; nenhuma conclusão completa sobre a precedência ou outros filtros é inferida a partir dessa leitura. **Não foi executado nenhum teste com arquivo `.exe`**.

Inventário anterior (02/11) apontava os outros **5 diretórios FIM locais como periódicos, associados a caminhos do Windows**, com frequência de `43200` segundos. Esses diretórios não foram aprovados como locais para escrita/executável de teste.

## Decisão de segurança e escopo

**Pasta Startup = NO-GO para artefato executável de teste.** Qualquer executável colocado nessa pasta pode iniciar automaticamente em um logon posterior; mesmo uma amostra benigna pode produzir persistência involuntária. Não usar essa pasta para satisfazer H03 e não reutilizar os diretórios críticos do sistema operacional.

O mecanismo de correlação H03 requer alerta de **arquivo** do FIM **anterior** a evento Sysmon ID 1 da execução do **mesmo arquivo**, mesmo host e no máximo 20 minutos, com revisão de originais e controle negativo. O fato de o canal Sysmon estar habilitado e já existirem eventos ID 1 no Manager não é prova de tal par. Também não presume que criar um arquivo em uma diretiva agendada de 12 horas gerará evento na janela exigida.

### Filtro offline preventivo

Foi adicionado `scripts/m1_h03_candidate_safety_gate.py`, um classificador **fail-closed** de raízes e candidatos de caminho Windows que:
- bloqueia pastas de inicialização automática, pastas de Windows/Program Files, caminhos não absolutos, artefatos fora da raiz e diretórios raiz de volume;
- retorna no máximo `REVIEW_REQUIRED`, **nunca** `GO`, mesmo para um caminho aparentemente seguro;
- não lê a VM, não interpreta a configuração mesclada do agente e não publica nomes/caminhos fornecidos;
- exige confirmação posterior de cobertura/exclusões, risco, revisão humana e change control.

```powershell
python scripts/m1_h03_candidate_safety_gate.py --root '%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup' --candidate '%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup\probe.exe' --mode realtime
```

Resultado sanitizado esperado: `status=NO_GO`, `reason=autostart_startup_folder`, `test_approved=false`. Esse comando **não cria** o candidato citado. Os testes do novo classificador, somados ao auditor JSONL H03, retornaram **11 passed** no checkpoint.

## Alternativa recomendada (NÃO aplicada)

Propor um **diretório isolado de laboratório, não vinculado a inicialização automática** (ex.: `C:\SecurityLab\H03\`), cujo caminho e ACLs sejam avaliados privadamente. Esse caminho **não está comprovado como monitorado hoje**. A adição de um nó FIM realtime para ele (ou outra configuração equivalente) seria uma **mudança nova**, com proposta isolada, comparação de config local+central, avaliação de carga, backups, rollback, revisão independente, aprovação expressa e janela própria. Só após isso escolher a cópia descartável de um executável inofensivo, controlar seu hash, alterar o artefato conforme plano aprovado e correlacionar com Sysmon.

Alternativa agendada: aceitar janela de até **12 horas** e **não** concluir a correlação H03 de 20 minutos sem timestamps originais compatíveis; não forçar scan nem mudar frequência sem aprovação.

## Gates e pendências

| Gate | Status |
| --- | --- |
| Único path realtime do 004 identificado | **CONFIRMADO: Startup (risco de autorun)** |
| Existência do diretório realtime | **CONFIRMADA** |
| Canal Sysmon Operational habilitado | **CONFIRMADO** |
| Executável benigno adequado e coberto por FIM realtime | **NÃO IDENTIFICADO — NO-GO** |
| Diretório isolado com FIM aprovado | **NÃO CONFIGURADO/UNVERIFIED** |
| Mudança de FIM e teste H03 autorizados | **NÃO** |
| Par real FIM de arquivo + Sysmon ID 1 validado | **INCONCLUSIVE** |
| M1 e implantação | **11/17; DEPLOYMENT_GATE=BLOCKED** |

**Rastreabilidade:** [plano de H03](m1-h03-artifact-coverage-preflight-20261104.md), [mapa e diagramas](m1-scope-and-h03-diagrams-20261104.md), [reconciliação FIM 004](m1-agent004-effective-fim-reconciliation-20261104.md), [contrato de evidências H03](m1-three-hunting-hypotheses.md), [Issue #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9).

**Privacidade:** os prints brutos da console e qualquer informação de caminho obtida diretamente da VM permanecem privados em `.lab/`. Este documento não inclui dados brutos, credenciais ou nomes de usuário.
