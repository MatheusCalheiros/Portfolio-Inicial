# Hardening & GPO Audit — Windows Server AD

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=flat&logo=powershell&logoColor=white)
![Windows Server](https://img.shields.io/badge/Windows_Server-2019%2F2022-0078D4?style=flat&logo=windows&logoColor=white)
![Status](https://img.shields.io/badge/status-portfólio-brightgreen)

Aplica e audita configurações de hardening no Active Directory via PowerShell. Gera relatório HTML com status antes/depois de cada política.

## Scripts

| Script | Função |
|---|---|
| `Apply-Hardening.ps1` | Aplica políticas de senha, lockout, auditoria e audita contas privilegiadas |
| `Get-PolicySnapshot.ps1` | Snapshot rápido do estado atual sem modificar nada |

## Uso rápido

```powershell
# Ver estado atual (sem alterar nada)
.\Get-PolicySnapshot.ps1 -DomainName empresa.local

# Simular aplicação (WhatIf)
.\Apply-Hardening.ps1 -DomainName empresa.local -WhatIf

# Apenas auditar, sem aplicar
.\Apply-Hardening.ps1 -DomainName empresa.local -AuditOnly

# Aplicar hardening completo + gerar relatório HTML
.\Apply-Hardening.ps1 -DomainName empresa.local -ReportPath C:\reports
```

## O que é configurado

**Política de senhas**
- Comprimento mínimo: 12 caracteres
- Histórico: 24 senhas
- Expiração: 90 dias / mínimo 1 dia
- Complexidade: habilitada
- Criptografia reversível: desabilitada

**Account Lockout**
- Bloqueio após: 5 tentativas
- Duração: 30 minutos
- Janela de observação: 30 minutos

**Auditoria de eventos** (via auditpol)
- Account Logon, Account Management, Logon/Logoff
- Object Access (File System), Policy Change, Privilege Use, System

**Contas privilegiadas**
- Lista membros de Domain Admins, Enterprise Admins, Schema Admins
- Detecta: desativadas, senha sem expiração, nunca logaram

## Topologia do lab

```
[Windows Server 2022 — DC]
   ├── Active Directory DS
   ├── DNS integrado
   ├── DHCP autorizado
   └── GPO de hardening (este projeto)

[Windows 10 — Cliente]
   └── Membro do domínio empresa.local
```

## Relacionado

- [ad-audit-tool](../p2-ad-audit) — auditoria do AD via Python/LDAP
- [siem-wazuh-lab](../p5-siem-wazuh) — monitoramento dos eventos gerados por este hardening
