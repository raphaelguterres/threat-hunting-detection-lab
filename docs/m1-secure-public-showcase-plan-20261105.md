# Plano de exposição segura à internet — laboratório Wazuh (05/11/2026)

**Decisão proposta:** publicar **uma demonstração separada**, e **não** expor diretamente o laboratório Wazuh/VirtualBox. **Nenhuma mudança de firewall, roteador, port-forward, VM, Docker, credencial ou serviço foi feita nesta análise.**

## Estado verificado

- O laboratório atual utiliza duas VMs VirtualBox (**Kali/Wazuh** e **Windows Server**). Em 05/11/2026, cada uma tinha interfaces **NAT, rede interna e host-only**.
- A listagem read-only de regras NAT da configuração dessas VMs retornou **0 redirecionamentos** em ambas.
- Isso **não é um teste externo de alcance nem uma auditoria de todas as interfaces**. Não foram avaliados roteador, túnel externo, firewall de borda, Cloudflare Tunnel, UPnP, outros hosts, serviços do host Windows ou regras de terceiros.
- O Wazuh usado no laboratório segue a família 4.x; componentes típicos: Manager (1514/1515 e API 55000), Indexer (9200) e Dashboard (443). **Essas portas não devem ser publicadas diretamente para demonstração**. As configurações atuais de bind Docker não foram atestadas nesta sessão.
- O M1 está **14/17**, com três critérios restantes: change control Windows **4698**, correlações reais completas H01/H02/H03 e revisão independente/encerramento. A exceção de continuação do proprietário é restrita a trabalho local/offline/readonly, **não autoriza expor serviços na internet**.

## Arquitetura recomendada

```text
   INTERNET (público)
          |
      HTTPS + CDN/WAF
          |
  SITE DE DEMONSTRAÇÃO ISOLADO
    - arquitetura e roadmap
    - métricas fictícias claramente rotuladas OU métricas reais sanitizadas
    - estudos FIM/H01-H03 com status exato
    - capturas revisadas, sem dados brutos
          ^
          | somente publicação de artefatos aprovados;
          | NENHUMA conexão entrante ao laboratório
          |
   [PUBLICAÇÃO UNIDIRECIONAL, REVISADA]

  LABORATÓRIO PRIVADO (VirtualBox)
    Kali + Docker Wazuh Manager/Indexer/Dashboard
    Windows Server + agentes
    logs, regras, evidências .lab/
    backups versionados, restauração e rollback
          ^
          |
       VPN PRIVADA com MFA
          |
     OPERADOR AUTORIZADO
```

**Princípios:** sem ligação pública direta a 1514, 1515, 55000, 9200, SSH, RDP, hypervisor, Docker socket ou painel administrativo. O Dashboard do Wazuh real só via VPN/identidade e regras de acesso restritivas; no site público, **não fazer proxy do Dashboard** e não disponibilizar credenciais de “visitante” no sistema real. Uma aplicação pública separada pode ser hospedada em serviço estático isolado do host Wazuh; publicar por pipeline de arquivos JSON sanitizados e aprovados, nunca com acesso à rede interna.

Se desejar métricas mais atuais, o agente de publicação deve gerar **snapshots agregados aprovados para divulgação**, sem event IDs, hostnames, IPs, nomes de usuário, caminhos internos, payloads, tokens ou timeline granular reidentificável. A exportação é **outbound-only**, sem token com acesso de administrador, e deve ser removível sem prejudicar a coleta SOC.

## Condições mínimas antes de uma publicação

| Gate | Evidência necessária | Estado em 05/11 |
| --- | --- | --- |
| Mudança Windows 4698 | Baseline recente de `Audit Other Object Access Events`; avaliar Security 20 MiB circular e 2 coletores potencialmente sobrepostos; autorização e rollback; ativação e evento real 4698 validado até Indexer/Discover | **Pendente, alteração não executada** |
| M1 técnico | Correlacionar H01/H02/H03 com eventos reais suficientes, fontes e identidade consistentes; declarar inconclusivos quando for o caso | **Pendente** |
| Revisão independente | Aprovação de PR, evidências sanitizadas e decisão sobre pendência `manager_ingestion` e mudança A | **Pendente** |
| Perímetro | Inventário completo de portas/binds, NAT/forwarding, firewall host/roteador/VPS, túneis/UPnP, segmentação e teste de alcance externo **apenas autorizado** | **Não executado integralmente** |
| Identidade | VPN privada/MFA, contas individuais, least privilege, revogação de acesso, segredos rotacionados | **A verificar** |
| Continuidade | Backup remoto versionado, restauração isolada testada, snapshots/rollback e proteção de credenciais | **A verificar** |
| Publicação | Hospedagem separada, HTTPS, logs mínimos, conteúdo e screenshots sanitizados, revisão antes de cada release | **A projetar** |
| Monitoramento | Alertas de acesso da camada pública, métricas de saúde, plano de resposta e retirada rápida de publicação | **A projetar** |

**Lançamento recomendado:** primeiro um **portfólio público estático**, hospedado longe das VMs, com diagramas, vídeos curtos e dados de demonstração. O laboratório real continua privado. Para um futuro SOC acessível pela internet, usar **implantação nova e segregada**, modelo de ameaças, autenticação forte, perímetro fechado e testes externos autorizados. Não tratar WAF, HTTPS ou a conclusão do M1 como substitutos de isolamento.

## Próxima entrega técnica (15/17 — 88,2%)

A mudança **4698** exige **GO e janela operacional específicos**, independentes do GO limitado de desenvolvimento já aprovado:

1. Confirmar baseline **imediatamente antes** da mudança: `auditpol /get /subcategory:"Other Object Access Events"`, Security habilitado, espaço/retenção e integridade de rollback.
2. Avaliar a sobreposição potencial dos **dois** coletores `Security` (uma fonte ampla e outra negativamente filtrada) e decidir tratamento da retenção 20 MiB **sem alterar tudo no mesmo change request automaticamente**.
3. Aprovar mudanças limitadas e reversíveis com critérios de parada, operador e rollback documentados.
4. Habilitar somente a auditoria `Success` da subcategoria quando a janela for autorizada; efetuar **um teste inerte de tarefa** previamente aprovado e limpar o artefato.
5. Comprovar evento **4698** na VM e a **mesma ocorrência** no Manager/Indexer/Discover por acessos autorizados. Registrar possíveis duplicidades e crescimento do Security; falhas são **NO-GO**, não apenas uma pendência de documentação.
6. Preservar evidências sanitizadas e backup. **Somente após aprovação real**, marcar o item do ROADMAP `[x]` e afirmar `15/17`.

**Status:** preparação de publicação **proposta**, **não publicada**. M1 **14/17** até verificação real da mudança 4698. `DEPLOYMENT_GATE` de aceite final permanece `BLOCKED` e PR #25 sem merge.

## Fontes

- [Wazuh — Architecture and required ports](https://documentation.wazuh.com/current/getting-started/architecture.html)
- [Wazuh — Docker deployment ports](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)
- [Microsoft — Audit Other Object Access Events](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-object-access-events)
- [Mudança local 4698 e rollback](m1-change-control-4698-fim-agent004.md)
- [Revisão de dois coletores Security e FIM 004](m1-inventory-security-overlap-fim004-closure-20261105.md)
- [Issue #15](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/15) · [Issue #9](https://github.com/raphaelguterres/threat-hunting-detection-lab/issues/9) · [PR #25](https://github.com/raphaelguterres/threat-hunting-detection-lab/pull/25)
