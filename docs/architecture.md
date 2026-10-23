# Arquitetura do laboratório

## Topologia validada

```text
                         rede privada isolada
┌──────────────────┐                              ┌────────────────────┐
│ Linux endpoint   │                              │ Windows Server 2022│
│ Wazuh Agent      │                              │ Wazuh Agent        │
│ logs + FIM       │                              │ Event Channels+FIM │
└────────┬─────────┘                              └─────────┬──────────┘
         └───────────────────┬──────────────────────────────┘
                             ▼
              ┌─────────────────────────────────┐
              │ Kali Linux VM                    │
              │ Wazuh Manager / Indexer / UI     │
              │ Docker single-node               │
              └───────────────┬─────────────────┘
                              ▼
                   Alertas, evidências e triagem
```

## Decisões de segurança

- A rede de testes é isolada; o tráfego de gerenciamento é separado dos testes sempre que possível.
- O dashboard usa HTTPS local com certificado autoassinado apenas no ambiente de laboratório.
- Automação de contenção não está habilitada. Recomendações são registradas em playbooks e dependem de aprovação humana.
- Capturas destinadas ao portfólio precisam omitir IPs públicos, credenciais, chaves, tokens e dados pessoais.

## Limitação conhecida

O teste FIM do endpoint Linux foi feito em filesystem sobreposto de contêiner. O agente indicou monitoramento, mas não houve alerta no Manager durante a janela de validação. Esse resultado é tratado como evidência negativa; o FIM validado ponta a ponta é o do Windows Server.
