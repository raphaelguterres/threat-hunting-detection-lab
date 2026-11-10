# H02 — criação de conta e logon privilegiado em teste controlado

Em 10/11/2026, o operador criou uma conta local temporária e entrou no Windows Server do laboratório com ela. O Wazuh recebeu cinco registros do canal Security do mesmo agente: um evento de criação de conta (4720), dois de logon interativo (4624, tipo 2) e dois de atribuição de privilégios especiais (4672).

| Verificação | Resultado |
| --- | --- |
| Controle positivo | Duas cadeias 4720 → 4624 → 4672. Cada uma tem o mesmo SID nos três registros e um Logon ID em comum entre 4624 e 4672. Os dois logons ocorreram cerca de 144 e 148 segundos após a criação, dentro da janela de 30 minutos. |
| Controle negativo | Zero correspondências em duas comparações que cruzaram o 4624 de uma sessão com o 4672 da outra. O host, o SID e a janela temporal foram preservados. O Logon ID era diferente. |
| Wazuh | Os cinco registros coincidiram no Manager e no Indexer. A consulta pelos mesmos registros exibiu cinco resultados no Discover. |
| Windows Security | Os cinco registros foram conferidos diretamente no log da VM. Record ID, tipo, host, hora nativa e SID coincidiram com os alertas, assim como o Logon ID para os eventos 4624 e 4672. |
| Conta temporária | Remoção ainda sem confirmação. |

As duas cadeias correspondem a dois identificadores de logon nos registros. O resultado comprova a associação dos eventos no Wazuh dentro da janela da hipótese. A atividade foi um teste administrativo autorizado.
