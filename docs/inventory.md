# Inventário do laboratório

| Ativo | Papel | Estado validado | Observações |
|---|---|---|---|
| VM Kali Linux | Servidor Wazuh | Operacional | Manager, Indexer e Dashboard em Docker single-node. |
| Wazuh Manager | Correlação e regras | Operacional | Regras locais `100100` a `100103` carregadas. |
| Wazuh Indexer | Armazenamento de alertas | Operacional | Cluster validado em estado `green`. |
| Wazuh Dashboard | Visualização e triagem | Operacional | HTTPS local com certificado autoassinado. |
| Endpoint Linux | Agente Wazuh | Active | Coleta do log de laboratório, FIM configurado e SCA executado. |
| Windows Server 2022 | Agente Wazuh | Active | Event Channels configurados; FIM validado ponta a ponta. |

## Controle de versões e recuperação

- Stack: `wazuh/wazuh-docker` release `v4.14.9`.
- Antes de mudanças estruturais, registrar snapshot das VMs e estado dos contêineres.
- Sincronizar horário (NTP) antes de comparar linhas do tempo.
- O detalhe histórico e as evidências estão em [evidencias-reais.md](evidencias-reais.md).
