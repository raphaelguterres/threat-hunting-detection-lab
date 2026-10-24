# Testes de detecção

Cada teste deve declarar pré-requisito, ação inofensiva, resultado esperado, resultado observado e evidência. Não executar ações contra ativos fora da rede privada do laboratório.

## Verificação local do repositório

Antes de publicar alterações em regras, Sysmon ou playbooks, execute no host:

```powershell
.\scripts\validate_lab_config.ps1
```

O script verifica XML, IDs das regras locais, cobertura mínima da configuração Sysmon e a presença dos roteiros obrigatórios. Ele não acessa VMs, não abre rede e não altera arquivos.
