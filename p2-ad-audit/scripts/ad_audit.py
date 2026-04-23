"""
ad_audit.py — Auditoria de Active Directory via LDAP
Projeto de portfólio: consulta usuários, grupos e permissões do AD
e gera relatório em CSV + JSON.

Dependências: pip install ldap3 colorama
Uso:         python ad_audit.py --server 192.168.10.10 --domain empresa.local
             python ad_audit.py --server 192.168.10.10 --domain empresa.local --user administrator
"""

import argparse
import csv
import json
import getpass
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, ALL_ATTRIBUTES
    from ldap3.core.exceptions import LDAPException
except ImportError:
    print("[ERRO] Pacote ldap3 não encontrado. Execute: pip install ldap3")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

# ─── Helpers de saída ────────────────────────────────────────────────────────

def ok(msg):
    prefix = f"{Fore.GREEN}[+]{Style.RESET_ALL}" if COLOR else "[+]"
    print(f"{prefix} {msg}")

def info(msg):
    prefix = f"{Fore.CYAN}[*]{Style.RESET_ALL}" if COLOR else "[*]"
    print(f"{prefix} {msg}")

def warn(msg):
    prefix = f"{Fore.YELLOW}[!]{Style.RESET_ALL}" if COLOR else "[!]"
    print(f"{prefix} {msg}")

def err(msg):
    prefix = f"{Fore.RED}[-]{Style.RESET_ALL}" if COLOR else "[-]"
    print(f"{prefix} {msg}")

def banner():
    print("""
  ╔══════════════════════════════════════════════╗
  ║         AD Audit Tool  —  Portfólio          ║
  ║   Consulta LDAP | Relatório CSV + JSON       ║
  ╚══════════════════════════════════════════════╝
    """)

# ─── Conexão LDAP ────────────────────────────────────────────────────────────

def build_base_dn(domain: str) -> str:
    """empresa.local → DC=empresa,DC=local"""
    parts = domain.split(".")
    return ",".join(f"DC={p}" for p in parts)

def connect(server_ip: str, domain: str, username: str, password: str) -> Connection:
    """Estabelece conexão autenticada com o DC via NTLM."""
    info(f"Conectando a {server_ip} ({domain}) ...")
    srv = Server(server_ip, get_info=ALL)
    upn = f"{domain}\\{username}"          # NTLM format
    conn = Connection(
        srv,
        user=upn,
        password=password,
        authentication=NTLM,
        auto_bind=True,
    )
    ok(f"Conectado como {upn}")
    return conn

# ─── Coleta de dados ──────────────────────────────────────────────────────────

def get_users(conn: Connection, base_dn: str) -> list[dict]:
    """
    Retorna todos os usuários do AD com atributos relevantes para auditoria.
    Flags de userAccountControl decodificadas:
        2   = ACCOUNTDISABLE
        512 = NORMAL_ACCOUNT
        66048 = PASSWORD_NEVER_EXPIRES (512 + 65536)
    """
    info("Coletando usuários...")
    attrs = [
        "sAMAccountName", "displayName", "mail",
        "userAccountControl", "lastLogonTimestamp",
        "pwdLastSet", "memberOf", "distinguishedName",
        "whenCreated", "description",
    ]
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=user)(objectCategory=person))",
        search_scope=SUBTREE,
        attributes=attrs,
    )

    users = []
    for entry in conn.entries:
        uac = int(entry.userAccountControl.value or 0)
        last_logon_raw = entry.lastLogonTimestamp.value
        pwd_set_raw    = entry.pwdLastSet.value

        # Converte timestamps do formato LDAP (datetime ou None)
        def fmt_dt(v):
            if v is None:
                return "nunca"
            if isinstance(v, datetime):
                return v.strftime("%Y-%m-%d %H:%M")
            return str(v)

        # Extrai só o CN dos grupos
        groups = []
        if entry.memberOf:
            raw = entry.memberOf.value
            if isinstance(raw, str):
                raw = [raw]
            for dn in raw:
                cn = next((p.split("=", 1)[1] for p in dn.split(",") if p.startswith("CN=")), dn)
                groups.append(cn)

        # OU onde o usuário está
        dn_str = str(entry.distinguishedName)
        ou_parts = [p.split("=", 1)[1] for p in dn_str.split(",") if p.startswith("OU=")]
        ou = " > ".join(reversed(ou_parts)) if ou_parts else "raiz"

        users.append({
            "username":          str(entry.sAMAccountName),
            "display_name":      str(entry.displayName or ""),
            "email":             str(entry.mail or ""),
            "ou":                ou,
            "groups":            "; ".join(groups),
            "enabled":           not bool(uac & 2),
            "pwd_never_expires": bool(uac & 65536),
            "last_logon":        fmt_dt(last_logon_raw),
            "pwd_last_set":      fmt_dt(pwd_set_raw),
            "when_created":      fmt_dt(entry.whenCreated.value),
            "description":       str(entry.description or ""),
        })

    ok(f"{len(users)} usuário(s) encontrado(s)")
    return users

def get_groups(conn: Connection, base_dn: str) -> list[dict]:
    """Retorna todos os grupos com seus membros."""
    info("Coletando grupos...")
    conn.search(
        search_base=base_dn,
        search_filter="(objectClass=group)",
        search_scope=SUBTREE,
        attributes=["cn", "description", "member", "distinguishedName"],
    )

    groups = []
    for entry in conn.entries:
        members = []
        if entry.member:
            raw = entry.member.value
            if isinstance(raw, str):
                raw = [raw]
            for dn in raw:
                cn = next((p.split("=", 1)[1] for p in dn.split(",") if p.startswith("CN=")), dn)
                members.append(cn)

        groups.append({
            "group_name":  str(entry.cn),
            "description": str(entry.description or ""),
            "members":     "; ".join(members),
            "member_count": len(members),
        })

    ok(f"{len(groups)} grupo(s) encontrado(s)")
    return groups

def get_ous(conn: Connection, base_dn: str) -> list[dict]:
    """Retorna a estrutura de OUs."""
    info("Coletando Organizational Units...")
    conn.search(
        search_base=base_dn,
        search_filter="(objectClass=organizationalUnit)",
        search_scope=SUBTREE,
        attributes=["ou", "description"],
    )
    ous = [
        {
            "ou":          str(e.ou),
            "description": str(e.description or ""),
        }
        for e in conn.entries
    ]
    ok(f"{len(ous)} OU(s) encontrada(s)")
    return ous

# ─── Análise de riscos ────────────────────────────────────────────────────────

def analyze_risks(users: list[dict]) -> list[dict]:
    """
    Regras simples de auditoria de segurança.
    Retorna lista de achados para o relatório.
    """
    findings = []

    disabled_with_groups = [
        u for u in users
        if not u["enabled"] and u["groups"]
    ]
    for u in disabled_with_groups:
        findings.append({
            "severity": "MEDIO",
            "type":     "Conta desativada ainda em grupos",
            "user":     u["username"],
            "detail":   f"Grupos: {u['groups']}",
        })

    stale_users = [
        u for u in users
        if u["enabled"] and u["last_logon"] == "nunca"
    ]
    for u in stale_users:
        findings.append({
            "severity": "ALTO",
            "type":     "Conta ativa nunca fez login",
            "user":     u["username"],
            "detail":   f"Criada em: {u['when_created']}",
        })

    pwd_never_exp = [
        u for u in users
        if u["enabled"] and u["pwd_never_expires"]
    ]
    for u in pwd_never_exp:
        findings.append({
            "severity": "MEDIO",
            "type":     "Senha nunca expira",
            "user":     u["username"],
            "detail":   f"Último reset: {u['pwd_last_set']}",
        })

    no_group = [
        u for u in users
        if u["enabled"] and not u["groups"]
    ]
    for u in no_group:
        findings.append({
            "severity": "INFO",
            "type":     "Usuário ativo sem grupos",
            "user":     u["username"],
            "detail":   "Verificar se acesso está correto",
        })

    return findings

# ─── Exportação ──────────────────────────────────────────────────────────────

def export_csv(data: list[dict], path: Path):
    if not data:
        return
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
    ok(f"CSV exportado → {path}")

def export_json(payload: dict, path: Path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, default=str)
    ok(f"JSON exportado → {path}")

# ─── Relatório no terminal ────────────────────────────────────────────────────

def print_summary(users, groups, ous, findings):
    print("\n" + "─" * 54)
    print("  RESUMO DA AUDITORIA")
    print("─" * 54)
    print(f"  Usuários totais  : {len(users)}")
    print(f"  Usuários ativos  : {sum(1 for u in users if u['enabled'])}")
    print(f"  Usuários inativos: {sum(1 for u in users if not u['enabled'])}")
    print(f"  Grupos           : {len(groups)}")
    print(f"  OUs              : {len(ous)}")
    print(f"  Achados          : {len(findings)}")
    print("─" * 54)

    if findings:
        print("\n  ACHADOS DE SEGURANÇA\n")
        sev_color = {"ALTO": Fore.RED, "MEDIO": Fore.YELLOW, "INFO": Fore.CYAN} if COLOR else {}
        for f in findings:
            col = sev_color.get(f["severity"], "")
            rst = Style.RESET_ALL if COLOR else ""
            print(f"  {col}[{f['severity']:5}]{rst}  {f['type']}")
            print(f"           Usuário : {f['user']}")
            print(f"           Detalhe : {f['detail']}\n")
    else:
        ok("Nenhum achado de segurança — ambiente limpo!")

# ─── Entrada principal ────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Auditoria de Active Directory via LDAP3"
    )
    p.add_argument("--server",  required=True, help="IP ou hostname do DC")
    p.add_argument("--domain",  required=True, help="FQDN do domínio (ex: empresa.local)")
    p.add_argument("--user",    default="administrator", help="Usuário AD (padrão: administrator)")
    p.add_argument("--out",     default="reports", help="Pasta de saída dos relatórios")
    return p.parse_args()

def main():
    banner()
    args = parse_args()

    password = getpass.getpass(f"  Senha para {args.user}@{args.domain}: ")

    try:
        conn = connect(args.server, args.domain, args.user, password)
    except LDAPException as e:
        err(f"Falha na conexão: {e}")
        sys.exit(1)

    base_dn = build_base_dn(args.domain)
    info(f"Base DN: {base_dn}")

    users    = get_users(conn, base_dn)
    groups   = get_groups(conn, base_dn)
    ous      = get_ous(conn, base_dn)
    findings = analyze_risks(users)

    print_summary(users, groups, ous, findings)

    # Exporta relatórios
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    export_csv(users,    out_dir / f"usuarios_{ts}.csv")
    export_csv(groups,   out_dir / f"grupos_{ts}.csv")
    export_csv(findings, out_dir / f"achados_{ts}.csv")

    export_json({
        "metadata": {
            "domain":    args.domain,
            "server":    args.server,
            "generated": datetime.now(timezone.utc).isoformat(),
            "auditor":   args.user,
        },
        "summary": {
            "total_users":    len(users),
            "active_users":   sum(1 for u in users if u["enabled"]),
            "inactive_users": sum(1 for u in users if not u["enabled"]),
            "total_groups":   len(groups),
            "total_ous":      len(ous),
            "total_findings": len(findings),
        },
        "findings": findings,
        "users":    users,
        "groups":   groups,
        "ous":      ous,
    }, out_dir / f"relatorio_completo_{ts}.json")

    conn.unbind()
    print(f"\n  Relatórios salvos em: {out_dir.resolve()}\n")

if __name__ == "__main__":
    main()
