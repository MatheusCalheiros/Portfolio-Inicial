# SIEM com Wazuh — Monitoramento do Active Directory

![Wazuh](https://img.shields.io/badge/Wazuh-4.9-005571?style=flat&logo=wazuh&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python)
![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04-E95420?style=flat&logo=ubuntu&logoColor=white)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-mapped-red?style=flat)
![Status](https://img.shields.io/badge/status-portfólio-brightgreen)

Implementação de SIEM com Wazuh monitorando um controlador de domínio Windows Server. Inclui regras customizadas mapeadas ao MITRE ATT&CK, agente configurado para coletar eventos críticos do AD, e script Python que consulta a API do Wazuh e gera relatório de alertas.

## Arquitetura

```
Windows Server DC (Wazuh Agent)
    │   eventos: 4625, 4740, 4728, 5136, 4663...
    ▼
Ubuntu Server (Wazuh Manager + Indexer + Dashboard)
    │   regras: local_rules.xml
    ▼
Dashboard → https://192.168.10.20
    +
wazuh_report.py → relatório via API
```

## Estrutura

```
p5-siem-wazuh/
├── configs/
│   ├── wazuh-rules/
│   │   └── local_rules.xml     # 20 regras customizadas (AD, brute force, GPO, FIM)
│   └── agent/
│       └── ossec.conf          # Configuração do agente Windows (event channels + FIM)
├── scripts/
│   └── wazuh_report.py         # Relatório via API Wazuh (+ modo demo)
└── docs/
    └── setup-wazuh.md          # Guia completo de instalação
```

## Regras customizadas

| ID | Nível | Evento | Descrição | MITRE |
|---|---|---|---|---|
| 100100 | 5 | 4625 | Falha de autenticação | T1110 |
| 100101 | 10 | — | Brute force (5 falhas/2min) | T1110.001 |
| 100102 | 12 | 4740 | Account lockout | T1110 |
| 100103 | 6 | 4624 L10 | Login RDP | T1021.001 |
| 100110 | 8 | 4720 | Novo usuário criado | T1136.001 |
| 100120 | **14** | 4728 | Adição ao Domain Admins | T1098 |
| 100130 | 8 | 5136 | Objeto AD modificado | T1484 |
| 100140 | 6 | 4663 | Acesso a arquivo sensível | T1552 |
| 100141 | **15** | 4663 | Acesso ao ntds.dit | T1003.003 |
| 100150 | 10 | 4624 | Login admin fora do horário | T1078 |

## Script de relatório

```bash
pip install requests colorama

# Demo (sem Wazuh)
python scripts/wazuh_report.py --demo

# Com Wazuh real
python scripts/wazuh_report.py --host 192.168.10.20 --user admin --hours 24
```

Gera: summary de alertas por severidade, top regras disparadas, mapeamento MITRE ATT&CK, lista de críticos e JSON estruturado.

## Integração com os outros projetos

```
P1 (Hardening GPO) ──► gera eventos de segurança ──► P5 (Wazuh detecta)
P3 (Kali Lab)      ──► ataques simulados         ──► P5 (Wazuh alerta)
P2 (AD Audit)      ──► identifica riscos         ──► P5 (monitora em tempo real)
```

## Relacionado

- [hardening-gpo](../p1-hardening-gpo) — políticas que geram os eventos monitorados
- [kali-lab](../p3-kali-lab) — ataques simulados para testar as regras
- [ad-audit-tool](../p2-ad-audit) — auditoria complementar via LDAP
