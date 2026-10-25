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

1. Criar um arquivo de controle em `/opt/wazuh-lab/fora-do-escopo`, fora do diretório configurado no `syscheck`.
2. Verificar no Manager que o caminho de controle não gerou alerta FIM.

## Critério de aceite

- [x] O evento aponta para o agente Linux correto, não para filesystem de contêiner.
- [x] O caminho coincide com `/opt/wazuh-lab/monitorado`.
- [x] A mudança positiva possui horário e hashes coerentes.
- [x] O teste negativo não produz alteração FIM.
- [x] A evidência é redigida antes de ser adicionada ao repositório.

## Estado

**Validado em 25/10/2026.** O agente nativo `kali-native-fim` gerou a regra 554 para criação e a regra 550 para mudança de checksum no arquivo de teste. O controle em `/opt/wazuh-lab/fora-do-escopo` gerou zero alertas.
