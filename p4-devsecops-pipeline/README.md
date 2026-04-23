# DevSecOps Pipeline — GitHub Actions + SAST + SCA + Secrets Scan

![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=flat&logo=github-actions&logoColor=white)
![Bandit](https://img.shields.io/badge/Bandit-SAST-orange?style=flat)
![Trivy](https://img.shields.io/badge/Trivy-Container-1904DA?style=flat)
![GitLeaks](https://img.shields.io/badge/GitLeaks-Secrets-red?style=flat)
![Status](https://img.shields.io/badge/status-portfólio-brightgreen)

Pipeline de segurança automatizado que roda em cada push e pull request, integrando 4 ferramentas de análise de segurança com relatório consolidado no PR.

## O que o pipeline faz

```
Push / PR
    │
    ├── 🔑 Secrets Scan (GitLeaks)
    │       Detecta: API keys, tokens, senhas, private keys no histórico git
    │
    ├── 🔍 SAST — Bandit
    │       Detecta: SQL injection, shell injection, MD5/pickle inseguros,
    │       YAML sem SafeLoader, TLS sem verificação, senhas hardcoded
    │       Upload automático para GitHub Security (aba Security > Code scanning)
    │
    ├── 📦 SCA — Safety + pip-audit
    │       Detecta: dependências com CVEs conhecidos
    │       Compara requirements.txt contra banco de vulnerabilidades
    │
    └── 🐳 Container Scan — Trivy
            Detecta: vulnerabilidades na imagem Docker base e pacotes do SO
            Upload SARIF para GitHub Security
```

## Estrutura

```
p4-devsecops-pipeline/
├── .github/
│   └── workflows/
│       └── devsecops.yml      # Pipeline completo (4 jobs paralelos)
├── src/
│   ├── vulnerable_app.py      # Código com vulnerabilidades intencionais (demonstração)
│   └── secure_app.py          # Versão corrigida após análise SAST
└── docs/
    └── bandit-findings.md     # Documentação de cada achado e correção
```

## Como usar

1. Faça fork ou clone deste repositório no GitHub
2. O pipeline roda automaticamente em cada push
3. Acesse **Security > Code scanning alerts** para ver os achados do Bandit e Trivy
4. Abra um PR para ver o comentário automático de relatório

## Vulnerabilidades demonstradas (src/vulnerable_app.py)

| Código Bandit | Categoria | Severidade | Correção |
|---|---|---|---|
| B602 | subprocess com shell=True | HIGH | Lista de args + shlex.quote |
| B303 | MD5 para senhas | MEDIUM | PBKDF2-HMAC com salt |
| B608 | SQL Injection | HIGH | Query parametrizada |
| B301 | pickle.loads inseguro | HIGH | json.loads |
| B506 | yaml.load sem Loader | MEDIUM | yaml.safe_load |
| B105 | Senha hardcoded | LOW | Variável de ambiente |
| B501 | TLS sem verificação | HIGH | ssl.create_default_context() |

## Ferramentas integradas

| Ferramenta | Tipo | O que detecta |
|---|---|---|
| **GitLeaks** | Secrets | Credenciais expostas no repositório |
| **Bandit** | SAST | Padrões inseguros no código Python |
| **Safety / pip-audit** | SCA | CVEs em dependências |
| **Trivy** | Container | Vulns na imagem Docker |

## Relacionado

- [ad-audit-tool](../p2-ad-audit) — o código Python deste projeto poderia ser auditado por este pipeline
- [siem-wazuh-lab](../p5-siem-wazuh) — monitoramento do ambiente que roda estes artefatos
