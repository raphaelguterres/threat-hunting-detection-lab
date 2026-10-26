# Checklist de publicação redigida

Use esta lista antes de anexar qualquer captura ao README, portfólio ou rede social. Nenhuma captura bruta da VM é versionada neste repositório.

## Seleção mínima

- [ ] Tela do Wazuh mostrando agente ativo, sem nome de usuário pessoal, endereço interno ou identificador desnecessário.
- [ ] Evento Sysmon com processo e severidade, sem linha de comando sensível.
- [ ] Evento FIM com caminho de laboratório e hashes, sem dados de produção.
- [ ] Linha do tempo de um estudo de caso, usando somente os documentos redigidos deste repositório.
- [ ] Diagrama da arquitetura sem IPs, chaves, credenciais, tokens ou nomes pessoais.

## Revisão antes de publicar

1. Ocultar IPs, hostnames que identifiquem o ambiente, nomes de pessoas, e-mails, sessões, IDs de agente e qualquer segredo.
2. Cortar barras do navegador, histórico, área de trabalho e notificações que não sejam parte da evidência.
3. Conferir que a legenda descreve uma simulação autorizada, não um incidente real.
4. Preferir campos mínimos: data, tipo de evento, regra, severidade e conclusão.
5. Manter a captura original somente fora do repositório público.

## Pacote recomendado

Para uma apresentação curta, usar quatro peças: arquitetura, agente ativo, uma evidência Sysmon/FIM e o fechamento da linha do tempo. A ordem e a fala estão em [roteiro-de-apresentacao.md](roteiro-de-apresentacao.md).
