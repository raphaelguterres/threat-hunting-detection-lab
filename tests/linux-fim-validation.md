# Validação FIM Linux fora de contêiner

## Objetivo

Comprovar que um agente Linux instalado no sistema convidado — e não dentro de um filesystem de contêiner do Wazuh — envia alterações FIM ao manager com os hashes esperados.

## Pré-condições

- A VM Linux está online e possui um agente Wazuh registrado e ativo.
- O diretório `/opt/wazuh-lab/monitorado` pertence ao filesystem do convidado Linux.
- O bloco `syscheck` de `config/ossec-agent-linux.xml` foi revisado e aplicado somente uma vez no `ossec.conf` do agente Linux.
- Há acesso autenticado ao endpoint ou console local; não habilitar SSH, firewall ou port forwarding apenas para este teste sem aprovação.

## Backup e rollback

1. Antes de alterar `ossec.conf`, criar uma cópia com timestamp no mesmo host.
2. Após o teste, manter o arquivo de evidência até a captura ser redigida.
3. Para reverter a coleta, remover apenas o bloco referente a `/opt/wazuh-lab/monitorado`, restaurar o backup se necessário e reiniciar somente o agente Wazuh.

## Teste positivo

1. Criar um marcador único no formato `LAB-FIM-<timestamp>`.
2. Criar o diretório de teste se ele não existir e criar um arquivo `.txt` com o marcador.
3. Alterar o mesmo arquivo uma vez, sem dados pessoais ou segredos.
4. Confirmar localmente que o arquivo existe e registrar o hash SHA-256 e horário.
5. Aguardar um intervalo limitado para o Wazuh processar o evento.
6. No manager, localizar o evento FIM pelo agente Linux, caminho e horário. Comparar os hashes disponíveis antes/depois.

## Teste negativo

1. Acessar ou listar o arquivo sem modificá-lo.
2. Verificar que isso não é registrado como alteração FIM.

## Critério de aceite

- [ ] O evento aponta para o agente Linux correto, não para filesystem de contêiner.
- [ ] O caminho coincide com `/opt/wazuh-lab/monitorado`.
- [ ] A mudança positiva possui horário e hashes coerentes.
- [ ] O teste negativo não produz alteração FIM.
- [ ] A evidência é redigida antes de ser adicionada ao repositório.

## Estado

**Pendente.** Nenhum item deste roteiro deve ser marcado como aprovado sem a confirmação no manager.
