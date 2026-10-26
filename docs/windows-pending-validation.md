# Cenários Windows pendentes — validação controlada

## Estado confirmado em 25/10/2026

- O agente Windows está ativo no Manager.
- O canal Sysmon foi coletado e os IDs 1, 3 e 11 já foram observados no Manager.
- A rede host-only e o Guest Additions estão operacionais.
- WinRM HTTP responde na rede isolada, mas não há um canal de administração remota autenticado configurado.

## Cenário 1 — PowerShell benigno

**Objetivo:** gerar uma execução administrativa inofensiva e correlacionar no Manager o usuário, o processo-pai, o comando e o Sysmon ID 1.

**Estado:** concluído em 25/10/2026. A execução controlada gerou Sysmon ID 1, recebido pela regra nativa 92027 com comando, usuário e processo-pai. Execuções internas sem marcador foram mantidas como contexto separado.

**Limite:** eventos genéricos de ID 1 não substituem esse teste; a evidência precisa identificar o comando benigno da execução controlada.

## Cenário 2 — conexão privada autorizada

**Objetivo:** produzir uma única conexão para serviço privado autorizado e correlacionar processo, destino, porta e Sysmon ID 3.

**Estado:** concluído em 25/10/2026. A recarga autorizada do painel HTTPS privado gerou eventos ID 3 do Edge, classificados pela regra 100105 no Manager. Após a navegação, a contagem permaneceu inalterada durante 20 segundos sem nova ação.

**Limite:** não usar destino público, transferência de dados, varredura, força bruta ou conteúdo sensível. A conexão deve ser de laboratório e autorizada.

## Acesso seguro necessário

A execução pode ocorrer no console local do Windows ou mediante administração remota autenticada. O projeto não habilita `TrustedHosts`, não usa senha em texto, não cria port forwarding e não presume credenciais. A configuração de acesso remoto, se desejada, deve usar WinRM HTTPS com autenticação apropriada ou OpenSSH com chave pública, seguida de validação e registro no repositório.
