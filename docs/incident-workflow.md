# Fluxo de resposta a incidentes

```text
Alerta → validar telemetria → enriquecer contexto → classificar →
decidir com aprovação humana → documentar evidência e encerramento
```

1. Confirmar o alerta: horário, regra, ativo, usuário e `full_log`.
2. Verificar se há teste de laboratório ou mudança aprovada correspondente.
3. Correlacionar eventos do mesmo ativo e janela de tempo; preservar evidências antes de qualquer ação.
4. Classificar confiança, impacto, severidade e prioridade.
5. Recomendar contenção. Em produção, qualquer ação disruptiva requer aprovação humana e plano de rollback.
6. Registrar cronologia, conclusão, limitações e melhoria de detecção.

Playbooks disponíveis:

- [Falhas de autenticação](../playbooks/authentication-triage.md)
- [PowerShell](../playbooks/powershell-triage.md)
- [Alteração de integridade](../playbooks/file-integrity-triage.md)
- [Conexão de rede](../playbooks/network-triage.md)
