"""
ad_audit_demo.py — Modo demonstração sem AD real
Gera dados fictícios e executa toda a lógica de análise e exportação.
Útil para testar o pipeline e demonstrar o projeto no portfólio.

Uso: python ad_audit_demo.py
"""

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Reutiliza as funções do módulo principal
sys.path.insert(0, str(Path(__file__).parent))
from ad_audit import analyze_risks, export_csv, export_json, print_summary, ok, info, banner

# ─── Dados fictícios ──────────────────────────────────────────────────────────

DEMO_USERS = [
    {
        "username": "joao.financeiro", "display_name": "João Silva",
        "email": "joao@empresa.local", "ou": "Financeiro",
        "groups": "GRP_FINANCEIRO", "enabled": True,
        "pwd_never_expires": False, "last_logon": "2025-04-10 08:30",
        "pwd_last_set": "2025-01-15 09:00", "when_created": "2024-06-01 10:00",
        "description": "Analista financeiro",
    },
    {
        "username": "maria.ti", "display_name": "Maria Souza",
        "email": "maria@empresa.local", "ou": "TI",
        "groups": "GRP_TI; Domain Admins", "enabled": True,
        "pwd_never_expires": True,           # ACHADO: senha nunca expira
        "last_logon": "2025-04-14 17:45",
        "pwd_last_set": "2023-03-10 12:00", "when_created": "2023-03-01 08:00",
        "description": "Administradora de TI",
    },
    {
        "username": "carlos.old", "display_name": "Carlos Andrade",
        "email": "", "ou": "Financeiro",
        "groups": "GRP_FINANCEIRO",          # ACHADO: desativado ainda em grupo
        "enabled": False,
        "pwd_never_expires": False, "last_logon": "2024-11-05 16:20",
        "pwd_last_set": "2024-08-01 10:00", "when_created": "2022-05-10 09:00",
        "description": "Desligado em dez/2024",
    },
    {
        "username": "svc.backup", "display_name": "Service Backup",
        "email": "", "ou": "raiz",
        "groups": "",                         # ACHADO: ativo sem grupo
        "enabled": True,
        "pwd_never_expires": True,            # ACHADO: senha nunca expira
        "last_logon": "nunca",                # ACHADO: nunca logou
        "pwd_last_set": "2024-01-01 00:00", "when_created": "2024-01-01 00:00",
        "description": "Conta de serviço de backup",
    },
    {
        "username": "pedro.rh", "display_name": "Pedro Lima",
        "email": "pedro@empresa.local", "ou": "RH",
        "groups": "GRP_RH", "enabled": True,
        "pwd_never_expires": False, "last_logon": "2025-04-13 09:15",
        "pwd_last_set": "2025-02-20 14:00", "when_created": "2024-09-01 11:00",
        "description": "",
    },
]

DEMO_GROUPS = [
    {"group_name": "GRP_FINANCEIRO", "description": "Grupo financeiro", "members": "joao.financeiro; carlos.old", "member_count": 2},
    {"group_name": "GRP_TI",         "description": "Grupo de TI",       "members": "maria.ti",                  "member_count": 1},
    {"group_name": "GRP_RH",         "description": "Recursos Humanos",  "members": "pedro.rh",                  "member_count": 1},
    {"group_name": "Domain Admins",  "description": "Admins do domínio", "members": "administrator; maria.ti",   "member_count": 2},
]

DEMO_OUS = [
    {"ou": "Financeiro", "description": "Departamento financeiro"},
    {"ou": "TI",         "description": "Departamento de tecnologia"},
    {"ou": "RH",         "description": "Recursos humanos"},
]

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    banner()
    info("Modo DEMO — dados fictícios (sem conexão AD real)")

    findings = analyze_risks(DEMO_USERS)
    print_summary(DEMO_USERS, DEMO_GROUPS, DEMO_OUS, findings)

    out_dir = Path("reports")
    out_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    export_csv(DEMO_USERS,    out_dir / f"usuarios_demo_{ts}.csv")
    export_csv(DEMO_GROUPS,   out_dir / f"grupos_demo_{ts}.csv")
    export_csv(findings,      out_dir / f"achados_demo_{ts}.csv")

    export_json({
        "metadata": {
            "domain": "empresa.local (DEMO)",
            "server": "192.168.10.10 (DEMO)",
            "generated": datetime.now(timezone.utc).isoformat(),
            "auditor": "demo",
        },
        "summary": {
            "total_users":    len(DEMO_USERS),
            "active_users":   sum(1 for u in DEMO_USERS if u["enabled"]),
            "inactive_users": sum(1 for u in DEMO_USERS if not u["enabled"]),
            "total_groups":   len(DEMO_GROUPS),
            "total_ous":      len(DEMO_OUS),
            "total_findings": len(findings),
        },
        "findings": findings,
        "users":    DEMO_USERS,
        "groups":   DEMO_GROUPS,
        "ous":      DEMO_OUS,
    }, out_dir / f"relatorio_completo_demo_{ts}.json")

    print(f"\n  Relatórios de demo salvos em: {out_dir.resolve()}\n")

if __name__ == "__main__":
    main()
