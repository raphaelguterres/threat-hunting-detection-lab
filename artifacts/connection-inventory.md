# Inventário de conexão — dual VM lab

Coletado em 23/10/2026 a partir do host Windows, sem credenciais ou conteúdo sensível.

## Host

| Item | Valor |
| --- | --- |
| Sistema operacional | Windows 11 Pro (10.0.26200) |
| VirtualBox | Detectado em `C:\Program Files\Oracle\VirtualBox\VBoxManage.exe` |
| Projeto | `threat-hunting-detection-lab` no branch `main` |
| Remoto Git | `origin` configurado para GitHub |

## Máquinas autorizadas

| Papel | Nome VirtualBox | UUID | Estado | Redes | Clipboard |
| --- | --- | --- | --- | --- | --- |
| Windows / agente Wazuh | `WindowsServer` | `db57ee0e-c884-433b-9852-41091df69403` | Executando | rede interna + NAT | Bidirecional |
| Kali / Wazuh | `kali-linux-2025.3-virtualbox-amd64` | `f00b7093-11ce-41f5-a5ec-1d3dd5bece3f` | Executando | NAT + rede interna | Bidirecional |

As duas VMs publicam endereços privados nas propriedades de convidado. Esses endereços não são versionados aqui porque podem mudar e não são necessários para operar o repositório.

## Canais de gerenciamento verificados

| Destino | Canal | Resultado | Decisão |
| --- | --- | --- | --- |
| Windows | VirtualBox status/propriedades | Sessão `Administrator` observada | Disponível para observação do host |
| Windows | WinRM/OpenSSH/guestcontrol | Não confirmado | Não habilitar sem autorização específica e credenciais válidas |
| Kali | VirtualBox status/propriedades | Sessão `kali` observada | Disponível para observação do host |
| Kali | SSH do host | Porta não alcançável pela rota testada | Não criar redirecionamento nem aceitar fingerprint automaticamente |
| Kali | guestcontrol | Não confirmado | Depende de Guest Additions compatíveis e credenciais válidas |

## Evidências de telemetria já observadas

- O serviço Windows `Sysmon64` foi observado em execução após instalação com a configuração do laboratório.
- O Kali exibiu evento Wazuh `syscheck_integrity_changed` oriundo do Windows, comprovando que a coleta FIM não está regressada no estado observado.

## Limites atuais

- O VirtualBox ainda não publicou uma versão de Guest Additions para o Windows nas propriedades consultadas; clipboard configurado não equivale a `guestcontrol` funcional.
- Não há um transporte remoto autenticado e pré-configurado do host para executar comandos dentro das VMs sem interação local. O orquestrador deve marcar esses passos como `BLOCKED`, e não improvisar WinRM, SSH ou port forwarding.
- Na verificação de saúde mais recente, ambas as VMs estavam desligadas. Nenhuma tentativa de inicialização foi feita, pois iniciar/reiniciar VM exige aprovação específica.
