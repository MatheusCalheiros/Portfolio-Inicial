# AD Audit Tool 🔍

> Script Python de auditoria de Active Directory via LDAP — consulta usuários, grupos e OUs, detecta riscos de segurança e exporta relatórios em CSV e JSON.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![ldap3](https://img.shields.io/badge/ldap3-2.9+-informational?style=flat)
![Status](https://img.shields.io/badge/status-portfólio-brightgreen?style=flat)
![Plataforma](https://img.shields.io/badge/plataforma-Windows%20%7C%20Linux-lightgrey?style=flat)

---

## Objetivo

Automatizar a auditoria de ambientes Active Directory, reduzindo o tempo de coleta de informações que normalmente é feito manualmente via ADUC (Active Directory Users and Computers). O script conecta diretamente ao DC via LDAP e extrai dados estruturados, além de aplicar regras básicas de detecção de riscos.

**Contexto**: Desenvolvido como extensão do [lab de infraestrutura Windows Server](../infraestrutura-windows-server-lab) — o mesmo ambiente AD é aqui consultado programaticamente.

---

## Funcionalidades

| Módulo | O que faz |
|---|---|
| **Coleta de usuários** | sAMAccountName, email, OU, grupos, status, datas de logon e criação |
| **Coleta de grupos** | Nome, descrição, membros e contagem |
| **Coleta de OUs** | Estrutura organizacional completa |
| **Análise de riscos** | 4 regras: conta desativada em grupo, conta nunca logada, senha sem expiração, conta sem grupo |
| **Exportação CSV** | Usuários, grupos e achados — abre direto no Excel |
| **Exportação JSON** | Relatório completo com metadata, summary e dados brutos |

---

## Pré-requisitos

- Python 3.10 ou superior
- Acesso de leitura ao AD (conta de domínio comum é suficiente; admin não é obrigatório)
- Conectividade com o DC na porta 389 (LDAP)

```bash
pip install -r requirements.txt
```

---

## Uso

### Com AD real (seu lab Windows Server)

```bash
python scripts/ad_audit.py \
  --server 192.168.10.10 \
  --domain empresa.local \
  --user administrator
```

A senha é solicitada de forma segura via `getpass` (não aparece na tela e não fica no histórico do shell).

### Modo demo (sem AD — para testar e demonstrar)

```bash
python scripts/ad_audit_demo.py
```

Gera os mesmos relatórios com dados fictícios que incluem achados intencionais para demonstração.

---

## Saída

```
reports/
├── usuarios_20250415_143022.csv
├── grupos_20250415_143022.csv
├── achados_20250415_143022.csv
└── relatorio_completo_20250415_143022.json
```

### Exemplo de output no terminal

```
  ╔══════════════════════════════════════════════╗
  ║         AD Audit Tool  —  Portfólio          ║
  ╚══════════════════════════════════════════════╝

[*] Conectando a 192.168.10.10 (empresa.local) ...
[+] Conectado como empresa.local\administrator
[+] 5 usuário(s) encontrado(s)
[+] 4 grupo(s) encontrado(s)
[+] 3 OU(s) encontrada(s)

──────────────────────────────────────────────────────
  RESUMO DA AUDITORIA
──────────────────────────────────────────────────────
  Usuários totais  : 5
  Usuários ativos  : 4
  Usuários inativos: 1
  Grupos           : 4
  OUs              : 3
  Achados          : 5
──────────────────────────────────────────────────────

  ACHADOS DE SEGURANÇA

  [ALTO ]  Conta ativa nunca fez login
           Usuário : svc.backup
           Detalhe : Criada em: 2024-01-01 00:00

  [MEDIO]  Conta desativada ainda em grupos
           Usuário : carlos.old
           Detalhe : Grupos: GRP_FINANCEIRO

  [MEDIO]  Senha nunca expira
           Usuário : maria.ti
           Detalhe : Último reset: 2023-03-10 12:00
```

---

## Regras de auditoria implementadas

| Severidade | Regra | Risco |
|---|---|---|
| 🔴 ALTO | Conta ativa que nunca fez login | Possível conta órfã ou backdoor |
| 🟡 MÉDIO | Conta desativada ainda em grupos de segurança | Acesso residual a recursos |
| 🟡 MÉDIO | Senha configurada para nunca expirar | Violação de política de senhas |
| 🔵 INFO | Conta ativa sem nenhum grupo | Possível erro de provisionamento |

---

## Arquitetura do código

```
ad_audit.py
│
├── connect()          → Autenticação NTLM no DC via ldap3
├── get_users()        → Search LDAP com filtro objectClass=user
│   └── Decodifica userAccountControl (bitmask)
├── get_groups()       → Search LDAP com filtro objectClass=group
├── get_ous()          → Search LDAP com filtro objectClass=organizationalUnit
├── analyze_risks()    → Aplica 4 regras de detecção
├── export_csv()       → Gera CSV com utf-8-sig (compatível com Excel pt-BR)
├── export_json()      → Gera JSON estruturado com metadata
└── print_summary()    → Relatório visual no terminal com severidade colorida
```

---

## Tecnologias

- **ldap3** — cliente LDAP puro Python, suporte a NTLM/Kerberos
- **csv / json** — módulos nativos do Python para exportação
- **getpass** — leitura de senha sem expor no terminal
- **argparse** — interface de linha de comando
- **colorama** — saída colorida no Windows e Linux

---

## Próximos passos / extensões possíveis

- [ ] Regra: detectar usuários com senhas antigas (> 90 dias sem reset)
- [ ] Regra: contas com login há mais de 60 dias (possíveis inativos)
- [ ] Exportação para HTML com tabela estilizada
- [ ] Suporte a Kerberos além de NTLM
- [ ] Modo `--watch`: executa em loop e alerta sobre mudanças
- [ ] Integração com Wazuh (enviar achados como alertas)

---

## Relacionado

- [infraestrutura-windows-server-lab](../infraestrutura-windows-server-lab) — ambiente AD que este script audita
- Próximo projeto: [lab-seguranca-kali](../lab-seguranca-kali) — análise ofensiva/defensiva

---

## Autor

**Matheus Calheiros de Almeida Cordeiro**  
Estudante de Cibersegurança | Infra & DevSecOps  
[LinkedIn](https://www.linkedin.com/in/matheus-calheiros-265367355/) · [GitHub](https://github.com/MatheusCalheiros)
