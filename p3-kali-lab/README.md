# Lab Ofensivo/Defensivo — Kali Linux + Metasploitable 2

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python)
![Kali](https://img.shields.io/badge/Kali_Linux-2024-557C94?style=flat&logo=kalilinux&logoColor=white)
![Nmap](https://img.shields.io/badge/nmap-7.x-00457C?style=flat)
![Metasploit](https://img.shields.io/badge/Metasploit-6.x-E34234?style=flat)
![Status](https://img.shields.io/badge/status-portfólio-brightgreen)

Laboratório de segurança ofensiva e defensiva em ambiente VirtualBox isolado. Inclui scanner de rede próprio em Python, write-up de exploração com Metasploit e documentação das mitigações para cada vulnerabilidade explorada.

## Estrutura

```
p3-kali-lab/
├── scripts/
│   └── network_scanner.py   # Scanner de rede com análise de risco (Python)
├── docs/
│   └── setup-lab.md         # Guia completo de montagem do ambiente
└── write-ups/
    └── lab-pentest-metasploitable.md  # Exercício documentado: reconhecimento → exploração → defesa
```

## Uso do scanner

```bash
pip install python-nmap colorama
# + instalar nmap: https://nmap.org/download.html

# Escanear toda a sub-rede do lab
python scripts/network_scanner.py --target 192.168.56.0/24

# Escanear host específico (todas as portas)
python scripts/network_scanner.py --target 192.168.56.102 --ports 1-65535

# Scan rápido (top 100 portas)
python scripts/network_scanner.py --target 192.168.56.0/24 --fast
```

Gera relatório HTML visual + JSON estruturado na pasta `reports/`.

## Vulnerabilidades exercitadas

| CVE | Serviço | CVSS | Status |
|---|---|---|---|
| CVE-2011-2523 | vsftpd 2.3.4 (backdoor) | 10.0 | ✅ Explorado + mitigado |
| CVE-2007-2447 | Samba 3.0.20 usermap | 10.0 | ✅ Explorado + mitigado |
| — | Telnet (sem criptografia) | — | ✅ Documentado + mitigado |
| — | MySQL sem autenticação externa | — | ✅ Documentado + mitigado |

## Ciclo do exercício

```
Reconhecimento → Enumeração → Exploração → Pós-Exploração → Mitigação → Documentação
     nmap            nmap        Metasploit      manual         iptables     write-up
```

## Relacionado

- [hardening-gpo](../p1-hardening-gpo) — GPO aplicada no Windows Server do mesmo lab
- [siem-wazuh-lab](../p5-siem-wazuh) — detecção dos ataques deste lab via SIEM
