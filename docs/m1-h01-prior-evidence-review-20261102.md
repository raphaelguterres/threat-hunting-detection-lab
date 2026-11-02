# H01 — Revisão retrospectiva dos seis alertas do Wazuh

**Revisão:** 02/11/2026. **Estado:** hipótese H01 **não corroborada nesta amostra delimitada** — não é uma análise exaustiva de todos os eventos do ambiente.

## Procedência e escopo

Usei somente os seis eventos originais de identidade (ID do alerta, regra, agente e timestamp) armazenados na pasta privada do projeto irmão [Detection Engineering Blue Team](https://github.com/raphaelguterres/detection-engineering-blue-team), cuja [Fase 3 foi comprovada](https://github.com/raphaelguterres/detection-engineering-blue-team/blob/main/docs/phase3-final-three-stage-six-event-acceptance-20261102.md). O arquivo privado contém apenas campos de identidade, não comandos, usuários ou processo-pai.

| Evento observado | Regra Wazuh | Timestamp UTC |
| --- | --- | --- |
| Atividade relacionada a schtasks | 110120 | 2026-11-01 23:19:52.407Z |
| Atividade PowerShell | 110100 | 2026-11-02 00:22:15.606Z |

**Intervalo: 3.743,199 segundos (1h02min23s).** O evento associado a schtasks ocorre **antes** do PowerShell, e não depois dentro de 15 minutos, como exigiria H01.

**Conclusão específica:** os dois alertas observados não podem compor **um par temporal H01**. Isso **não** prova inexistência de outros pares, ausência de ataque nem tarefa criada: a regra de schtasks pode registrar mais do que uma criação efetiva; os eventos resumidos não identificam ator, processo pai, ação nem autorização.

## Distinção entre as três hipóteses

- **H01:** esta amostra limitada não apresenta sequência temporal válida. Precisamos de uma consulta de caça a ameaças mais ampla e do conteúdo original para avaliar H01.
- **H02:** a amostra não comprova evento de conta criada (auditoria 4720) correlacionado a logon privilegiado (4672 com contexto do 4624); comando/tentativa de conta não substitui esses eventos.
- **H03:** a amostra não possui o par FIM + Sysmon processo com correspondência de arquivo. Não é possível concluir pela proximidade de tempo.

O aceite da Fase 3 comprova transmissão e identidade dos alertas nos três estágios. **Ele não comprova nenhuma dessas três correlações investigativas.**

## Reprodução offline — somente leitura

No Windows principal, com os repositórios como pastas irmãs em Downloads, execute na raiz do Threat Hunting Lab:

    python scripts/audit_h01_existing_evidence.py

O script lê **apenas** o arquivo privado previamente capturado no projeto Detection Engineering, limita o escopo a uma amostra pequena e imprime somente **quantidades, ordem temporal e intervalo**. Nenhum evento novo é gerado e nenhum registro bruto é impresso. Ele falha de forma controlada quando a evidência privada não existe.

Para testar a lógica sem usar dados reais:

    python scripts/audit_h01_existing_evidence.py --input tests/fixtures/m1-phase3-h01-synthetic.jsonl --fixture

A fixture contém seis registros **totalmente sintéticos** e **não é evidência operacional**.

## Critérios de aceite futuro

1. Consultar eventos originais em modo somente leitura e confirmar **mesmo ativo e ator**, sem inferir usuário a partir de uma regra.
2. Confirmar **criação real de tarefa** (eventos de auditoria ou artefato equivalente) depois do PowerShell no intervalo permitido.
3. Revisar linha de comando, processo-pai, tarefa resultante e ticket/janela de mudança.
4. Executar controles negativos de alteração autorizada, ordem invertida, usuário distinto e janela vencida.
5. Publicar apenas decisão agregada e sanitizada. Um par temporal não é incidente confirmado.

A [Issue M1 #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9) segue aberta para três investigações adicionais com telemetria real, revisão de falsos positivos e estudos de caso.