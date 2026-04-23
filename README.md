# Portfólio de Segurança & Infraestrutura — Matheus Calheiros

> Cinco projetos práticos cobrindo o ciclo completo de infraestrutura corporativa segura:
> hardening → auditoria → análise ofensiva → DevSecOps → monitoramento SIEM.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Matheus_Calheiros-0A66C2?style=flat&logo=linkedin)](https://www.linkedin.com/in/matheus-calheiros-265367355/)
[![GitHub](https://img.shields.io/badge/GitHub-MatheusCalheiros-181717?style=flat&logo=github)](https://github.com/MatheusCalheiros)
![Foco](https://img.shields.io/badge/foco-Cibersegurança_|_Infra_|_DevSecOps-blueviolet?style=flat)

---

## Projetos

| # | Repositório | Tecnologias | Nível de vaga |
|---|---|---|---|
| P1 | [hardening-gpo](./p1-hardening-gpo) | PowerShell, GPO, Windows Server | Suporte/Infra Jr |
| P2 | [ad-audit-tool](./p2-ad-audit) | Python, LDAP3, Active Directory | Suporte/Infra/DevSecOps Jr |
| P3 | [kali-lab](./p3-kali-lab) | Python, nmap, Metasploit, Kali | Analista Seg. Jr / SOC Jr |
| P4 | [devsecops-pipeline](./p4-devsecops-pipeline) | GitHub Actions, Bandit, Trivy, GitLeaks | DevSecOps Jr |
| P5 | [siem-wazuh-lab](./p5-siem-wazuh) | Wazuh, Python, MITRE ATT&CK | SOC Jr / Analista Seg. Jr |

---

## Como os projetos se conectam

```
┌─────────────────────────────────────────────────────────────────┐
│                    Lab Windows Server (VirtualBox)              │
│                                                                 │
│  P1: Hardening GPO ──────────────────────────────────────────► │
│      Aplica políticas de senha, lockout, auditpol              │
│                ↓ gera eventos de segurança                      │
│  P5: Wazuh SIEM ◄────────────────────────────────────────────  │
│      Detecta e alerta sobre anomalias                           │
│                                                                 │
│  P2: AD Audit (Python/LDAP) ─────────────────────────────────► │
│      Audita usuários, grupos, OUs — identifica riscos           │
│                                                                 │
│  P3: Kali Lab ───────────────────────────────────────────────► │
│      Simula ataques → Wazuh detecta → escreve mitigação         │
└─────────────────────────────────────────────────────────────────┘

P4: DevSecOps Pipeline (GitHub Actions)
    Analisa QUALQUER código deste portfólio antes do deploy
    Bandit → Trivy → GitLeaks → pip-audit
```

---

## Stack técnica coberta

**Sistemas:** Windows Server 2019/2022, Ubuntu Server 22.04, Kali Linux, Windows 10  
**AD/Infra:** Active Directory, DNS, DHCP, GPO, NTFS, SMB, SYSVOL  
**Segurança ofensiva:** nmap, Metasploit, auditoria de CVEs (CVE-2011-2523, CVE-2007-2447)  
**SIEM:** Wazuh 4.9, OpenSearch, MITRE ATT&CK framework  
**DevSecOps:** GitHub Actions, Bandit, Trivy, GitLeaks, Safety, pip-audit  
**Linguagens:** Python 3.10+, PowerShell 5.1+, YAML, XML  
**Ferramentas:** VirtualBox, nmap, ldap3, requests

---

## Sobre o autor

**Matheus Calheiros de Almeida Cordeiro** — Rio de Janeiro/RJ | disponível para São Paulo  
Estudante de Cibersegurança (4º período) | Técnico em Informática  
Buscando primeira oportunidade em Infraestrutura, Suporte, DevSecOps ou Segurança da Informação

📧 ti.matheuscalheiros@gmail.com  
📞 (21) 97975-9927
