#!/usr/bin/env python3
"""
wazuh_report.py — Consulta a API REST do Wazuh e gera relatório de alertas
Projeto de portfólio: integração com SIEM via API.

Dependências: pip install requests colorama
Uso: python wazuh_report.py --host 192.168.10.20 --user wazuh --hours 24
"""

import argparse
import json
import sys
import urllib3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import requests
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[ERRO] pip install requests")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

def c(color, text):
    return f"{color}{text}{Style.RESET_ALL}" if COLOR else text

# ─── Autenticação Wazuh API ───────────────────────────────────────────────────

def get_token(host: str, user: str, password: str) -> str:
    """Obtém JWT token da API Wazuh."""
    url = f"https://{host}:55000/security/user/authenticate"
    resp = requests.post(url, auth=(user, password), verify=False, timeout=10)
    resp.raise_for_status()
    return resp.json()["data"]["token"]

def api_get(host: str, token: str, endpoint: str, params: dict = None) -> dict:
    """GET autenticado na API Wazuh."""
    url = f"https://{host}:55000{endpoint}"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers, params=params or {}, verify=False, timeout=15)
    resp.raise_for_status()
    return resp.json()

# ─── Coleta de dados ──────────────────────────────────────────────────────────

def get_alerts(host: str, token: str, hours: int) -> list:
    """Busca alertas das últimas N horas via Wazuh Indexer API."""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Wazuh usa OpenSearch/Elasticsearch internamente
    search_url = f"https://{host}:9200/wazuh-alerts-*/_search"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    query = {
        "size": 500,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "range": {
                "timestamp": {"gte": since}
            }
        },
        "_source": [
            "timestamp", "rule.id", "rule.description", "rule.level",
            "rule.groups", "rule.mitre.id", "rule.mitre.tactic",
            "agent.name", "agent.ip",
            "data.win.eventdata.targetUserName",
            "data.win.eventdata.ipAddress",
            "data.win.system.eventID",
        ]
    }

    try:
        resp = requests.post(search_url, headers=headers, json=query, verify=False, timeout=15)
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
        return [h["_source"] for h in hits]
    except requests.exceptions.RequestException as e:
        print(c(Fore.YELLOW, f"[!] Indexer não acessível, usando API de resumo: {e}"))
        return []

def get_agents_summary(host: str, token: str) -> list:
    """Resumo dos agentes conectados."""
    data = api_get(host, token, "/agents", {"limit": 100})
    return data.get("data", {}).get("affected_items", [])

def get_rules_summary(host: str, token: str) -> dict:
    """Top regras disparadas (endpoint summary)."""
    try:
        data = api_get(host, token, "/overview/agents")
        return data.get("data", {})
    except Exception:
        return {}

# ─── Análise ──────────────────────────────────────────────────────────────────

def analyze(alerts: list) -> dict:
    """Agrega alertas por severidade, regra, agente e técnica MITRE."""
    sev_count  = Counter()
    rule_count = Counter()
    agent_count = Counter()
    mitre_count = Counter()
    critical_alerts = []

    for a in alerts:
        level = int(a.get("rule", {}).get("level", 0))
        sev = (
            "CRÍTICO" if level >= 12 else
            "ALTO"    if level >= 10 else
            "MÉDIO"   if level >= 7  else
            "BAIXO"
        )
        sev_count[sev] += 1
        rule_count[a.get("rule", {}).get("description", "?")] += 1
        agent_count[a.get("agent", {}).get("name", "?")] += 1

        mitre = a.get("rule", {}).get("mitre", {})
        if isinstance(mitre, dict):
            for tid in mitre.get("id", []):
                mitre_count[tid] += 1

        if level >= 12:
            critical_alerts.append({
                "ts":    a.get("timestamp", ""),
                "rule":  a.get("rule", {}).get("description", ""),
                "level": level,
                "agent": a.get("agent", {}).get("name", ""),
                "user":  a.get("data", {}).get("win", {}).get("eventdata", {}).get("targetUserName", ""),
                "srcip": a.get("data", {}).get("win", {}).get("eventdata", {}).get("ipAddress", ""),
            })

    return {
        "total":          len(alerts),
        "by_severity":    dict(sev_count),
        "top_rules":      rule_count.most_common(10),
        "top_agents":     agent_count.most_common(5),
        "top_mitre":      mitre_count.most_common(5),
        "critical_alerts": critical_alerts,
    }

# ─── Saída terminal ───────────────────────────────────────────────────────────

def print_report(analysis: dict, agents: list, hours: int):
    print("\n" + "═" * 60)
    print(c(Fore.CYAN, "  WAZUH SIEM — RELATÓRIO DE ALERTAS"))
    print(c(Fore.CYAN, f"  Período: últimas {hours} horas"))
    print("═" * 60)

    # Agentes
    print(c(Fore.YELLOW, f"\n  AGENTES ({len(agents)} registrado(s))"))
    for ag in agents:
        status_color = Fore.GREEN if ag.get("status") == "active" else Fore.RED
        print(f"    {c(status_color, '●')} {ag.get('name','?'):20} {ag.get('ip','?'):15} [{ag.get('status','?')}]")

    # Contagem por severidade
    print(c(Fore.YELLOW, f"\n  ALERTAS — TOTAL: {analysis['total']}"))
    sev_colors = {"CRÍTICO": Fore.RED, "ALTO": Fore.YELLOW, "MÉDIO": Fore.CYAN, "BAIXO": Fore.WHITE}
    for sev, count in sorted(analysis["by_severity"].items(), key=lambda x: ["CRÍTICO","ALTO","MÉDIO","BAIXO"].index(x[0])):
        bar = "█" * min(count, 40)
        print(f"    {c(sev_colors.get(sev, Fore.WHITE), f'{sev:8}')} {count:5}  {bar}")

    # Top regras
    if analysis["top_rules"]:
        print(c(Fore.YELLOW, "\n  TOP 10 REGRAS DISPARADAS"))
        for rule, count in analysis["top_rules"]:
            print(f"    {count:5}x  {rule[:55]}")

    # Top MITRE ATT&CK
    if analysis["top_mitre"]:
        print(c(Fore.YELLOW, "\n  TÉCNICAS MITRE ATT&CK DETECTADAS"))
        for tid, count in analysis["top_mitre"]:
            print(f"    {c(Fore.MAGENTA, tid):12}  {count}x")

    # Alertas críticos
    if analysis["critical_alerts"]:
        print(c(Fore.RED, f"\n  ⚠ ALERTAS CRÍTICOS ({len(analysis['critical_alerts'])})"))
        for a in analysis["critical_alerts"][:10]:
            ts = a["ts"][:19] if a["ts"] else "?"
            user = f" | user: {a['user']}" if a["user"] else ""
            src  = f" | src: {a['srcip']}" if a["srcip"] else ""
            print(f"    [{ts}] L{a['level']} {a['agent']}{user}{src}")
            print(f"         {c(Fore.RED, a['rule'])}")
    else:
        print(c(Fore.GREEN, "\n  ✓ Nenhum alerta crítico no período"))

    print()

# ─── Exportação ──────────────────────────────────────────────────────────────

def export_json(analysis: dict, agents: list, hours: int, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = out_dir / f"wazuh_report_{ts}.json"
    payload = {
        "metadata": {
            "generated": datetime.now(timezone.utc).isoformat(),
            "period_hours": hours,
        },
        "agents":   agents,
        "analysis": analysis,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(c(Fore.GREEN, f"[+] JSON exportado → {out}"))

# ─── Demo mode (sem Wazuh real) ───────────────────────────────────────────────

DEMO_ALERTS = [
    {"timestamp":"2025-04-14T22:10:00Z","rule":{"id":"100101","description":"Possível brute force - pedro.rh","level":10,"groups":["brute_force"],"mitre":{"id":["T1110.001"],"tactic":["Credential Access"]}},"agent":{"name":"WIN-DC01","ip":"192.168.10.10"},"data":{"win":{"eventdata":{"targetUserName":"pedro.rh","ipAddress":"192.168.10.50"}}}},
    {"timestamp":"2025-04-14T22:10:35Z","rule":{"id":"100102","description":"Conta bloqueada por lockout - pedro.rh","level":12,"groups":["account_lockout"],"mitre":{"id":["T1110"],"tactic":["Credential Access"]}},"agent":{"name":"WIN-DC01","ip":"192.168.10.10"},"data":{"win":{"eventdata":{"targetUserName":"pedro.rh","callerComputerName":"WORKSTATION01"}}}},
    {"timestamp":"2025-04-14T23:45:00Z","rule":{"id":"100150","description":"Login RDP fora do horário - administrator","level":10,"groups":["after_hours"],"mitre":{"id":["T1078"],"tactic":["Persistence"]}},"agent":{"name":"WIN-DC01","ip":"192.168.10.10"},"data":{"win":{"eventdata":{"targetUserName":"administrator","ipAddress":"192.168.10.99"}}}},
    {"timestamp":"2025-04-15T08:30:00Z","rule":{"id":"100110","description":"Novo usuário criado: svc.teste","level":8,"groups":["user_creation"],"mitre":{"id":["T1136.001"],"tactic":["Persistence"]}},"agent":{"name":"WIN-DC01","ip":"192.168.10.10"},"data":{"win":{"eventdata":{"targetUserName":"svc.teste","subjectUserName":"administrator"}}}},
    {"timestamp":"2025-04-15T09:00:00Z","rule":{"id":"100120","description":"Usuário adicionado ao Domain Admins","level":14,"groups":["privilege_escalation"],"mitre":{"id":["T1098"],"tactic":["Privilege Escalation"]}},"agent":{"name":"WIN-DC01","ip":"192.168.10.10"},"data":{"win":{"eventdata":{"memberName":"CN=svc.teste","targetUserName":"Domain Admins"}}}},
    {"timestamp":"2025-04-15T09:05:00Z","rule":{"id":"100141","description":"Acesso ao banco do AD (ntds.dit)","level":15,"groups":["credential_access","critical"],"mitre":{"id":["T1003.003"],"tactic":["Credential Access"]}},"agent":{"name":"WIN-DC01","ip":"192.168.10.10"},"data":{"win":{"eventdata":{"objectName":"C:\\Windows\\NTDS\\ntds.dit","subjectUserName":"svc.teste"}}}},
    {"timestamp":"2025-04-15T10:00:00Z","rule":{"id":"100100","description":"Falha de autenticação - maria.ti","level":5,"groups":["authentication_failure"],"mitre":{"id":["T1110"]}},"agent":{"name":"WIN-DC01","ip":"192.168.10.10"},"data":{"win":{"eventdata":{"targetUserName":"maria.ti","ipAddress":"192.168.10.30"}}}},
]

DEMO_AGENTS = [
    {"name":"WIN-DC01","ip":"192.168.10.10","status":"active","os":{"name":"Windows Server 2022"}},
    {"name":"WIN-CLIENT01","ip":"192.168.10.30","status":"active","os":{"name":"Windows 10"}},
]

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("\n  ╔══════════════════════════════════════════════╗")
    print("  ║    Wazuh SIEM Report — Portfólio            ║")
    print("  ╚══════════════════════════════════════════════╝")

    p = argparse.ArgumentParser()
    p.add_argument("--host",  default="192.168.10.20", help="IP do servidor Wazuh")
    p.add_argument("--user",  default="wazuh",         help="Usuário da API")
    p.add_argument("--hours", type=int, default=24,    help="Janela de tempo em horas")
    p.add_argument("--out",   default="reports",       help="Pasta de saída")
    p.add_argument("--demo",  action="store_true",     help="Modo demo (sem Wazuh real)")
    args = p.parse_args()

    if args.demo:
        print(c(Fore.CYAN, "\n[*] Modo DEMO — dados fictícios\n"))
        alerts = DEMO_ALERTS
        agents = DEMO_AGENTS
    else:
        import getpass
        password = getpass.getpass(f"  Senha para {args.user}@{args.host}: ")
        try:
            token  = get_token(args.host, args.user, password)
            alerts = get_alerts(args.host, token, args.hours)
            agents = get_agents_summary(args.host, token)
        except requests.exceptions.RequestException as e:
            print(c(Fore.RED, f"[-] Erro de conexão: {e}"))
            print(c(Fore.YELLOW, "[!] Use --demo para testar sem Wazuh"))
            sys.exit(1)

    analysis = analyze(alerts)
    print_report(analysis, agents, args.hours)
    export_json(analysis, agents, args.hours, Path(args.out))

if __name__ == "__main__":
    main()
