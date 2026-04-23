#!/usr/bin/env python3
"""
network_scanner.py — Scanner de rede e análise de superfície de ataque
Projeto de portfólio: enumera hosts, portas e serviços na rede local.
Gera relatório HTML com mapa de superfície de ataque.

Dependências: pip install python-nmap colorama jinja2
Uso: python network_scanner.py --target 192.168.10.0/24
     python network_scanner.py --target 192.168.10.5 --ports 1-1024
"""

import argparse
import json
import sys
import socket
from datetime import datetime
from pathlib import Path

try:
    import nmap
except ImportError:
    print("[ERRO] python-nmap não encontrado. Execute: pip install python-nmap")
    print("       Além disso, instale o nmap: https://nmap.org/download.html")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

# ─── Helpers ─────────────────────────────────────────────────────────────────
def ok(m):   print(f"{''+Fore.GREEN if COLOR else ''}[+]{Style.RESET_ALL if COLOR else ''} {m}")
def info(m): print(f"{''+Fore.CYAN  if COLOR else ''}[*]{Style.RESET_ALL if COLOR else ''} {m}")
def warn(m): print(f"{''+Fore.YELLOW if COLOR else ''}[!]{Style.RESET_ALL if COLOR else ''} {m}")
def err(m):  print(f"{''+Fore.RED   if COLOR else ''}[-]{Style.RESET_ALL if COLOR else ''} {m}")

# Portas de risco alto — mapeadas para serviço e motivo de alerta
HIGH_RISK_PORTS = {
    21:   ("FTP",        "Transferência em texto claro — use SFTP"),
    22:   ("SSH",        "Verificar versão e autenticação por chave"),
    23:   ("Telnet",     "CRÍTICO: protocolo sem criptografia"),
    25:   ("SMTP",       "Verificar relay aberto"),
    53:   ("DNS",        "Verificar zone transfer permitido"),
    80:   ("HTTP",       "Sem TLS — risco de interceptação"),
    135:  ("MSRPC",      "Vetor comum de exploração Windows"),
    139:  ("NetBIOS",    "Desabilitar se não necessário"),
    443:  ("HTTPS",      "Verificar versão TLS e certificado"),
    445:  ("SMB",        "Vetor EternalBlue — garantir patching"),
    1433: ("MSSQL",      "Banco de dados exposto — restringir acesso"),
    3306: ("MySQL",      "Banco de dados exposto — restringir acesso"),
    3389: ("RDP",        "Alto risco — restringir por IP + NLA obrigatório"),
    5985: ("WinRM HTTP", "Gerenciamento remoto em texto claro"),
    5986: ("WinRM HTTPS","Verificar autenticação e certificado"),
    8080: ("HTTP-Alt",   "Porta alternativa — verificar aplicação"),
}

# ─── Scanner ─────────────────────────────────────────────────────────────────
def scan(target: str, ports: str, fast: bool) -> dict:
    nm = nmap.PortScanner()
    args = "-sV -O --open" if not fast else "-F --open"

    info(f"Iniciando scan em {target} (portas: {ports}) ...")
    info("Isso pode levar 1-3 minutos dependendo da rede...")

    try:
        nm.scan(hosts=target, ports=ports, arguments=args)
    except nmap.PortScannerError as e:
        err(f"Erro no nmap: {e}")
        err("Verifique se o nmap está instalado e se está rodando como admin/sudo")
        sys.exit(1)

    return nm

def parse_results(nm) -> list:
    hosts = []

    for host in nm.all_hosts():
        info(f"Processando host {host}...")
        h_data = nm[host]

        # Tenta resolver hostname
        try:
            hostname = socket.gethostbyaddr(host)[0]
        except socket.herror:
            hostname = h_data.hostname() or "unknown"

        # OS detection
        os_guess = "Desconhecido"
        if "osmatch" in h_data and h_data["osmatch"]:
            best = max(h_data["osmatch"], key=lambda x: int(x.get("accuracy", 0)))
            os_guess = f"{best['name']} ({best['accuracy']}%)"

        open_ports = []
        risk_findings = []

        for proto in h_data.all_protocols():
            for port in sorted(h_data[proto].keys()):
                svc = h_data[proto][port]
                if svc["state"] != "open":
                    continue

                service_name = svc.get("name", "unknown")
                product      = svc.get("product", "")
                version      = svc.get("version", "")
                svc_str      = " ".join(filter(None, [product, version])) or service_name

                port_info = {
                    "port":     port,
                    "protocol": proto,
                    "service":  service_name,
                    "version":  svc_str,
                    "risk":     None,
                }

                if port in HIGH_RISK_PORTS:
                    _, reason = HIGH_RISK_PORTS[port]
                    port_info["risk"] = reason
                    risk_findings.append({
                        "port":    port,
                        "service": service_name,
                        "reason":  reason,
                        "sev":     "CRITICO" if port in [23, 445, 3389] else "ALTO",
                    })

                open_ports.append(port_info)

        host_result = {
            "ip":            host,
            "hostname":      hostname,
            "state":         h_data.state(),
            "os":            os_guess,
            "open_ports":    open_ports,
            "risk_findings": risk_findings,
            "risk_score":    len(risk_findings),
        }
        hosts.append(host_result)
        ok(f"{host} ({hostname}) — {len(open_ports)} porta(s) abertas, {len(risk_findings)} risco(s)")

    return sorted(hosts, key=lambda x: x["risk_score"], reverse=True)

# ─── Relatório HTML ───────────────────────────────────────────────────────────
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Network Scan Report</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;padding:2rem}
  h1{color:#58a6ff;font-size:1.6rem;margin-bottom:.25rem}
  .meta{color:#8b949e;font-size:.85rem;margin-bottom:2rem}
  .summary{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2rem}
  .card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;text-align:center}
  .card .n{font-size:2rem;font-weight:700}
  .card .l{font-size:.75rem;color:#8b949e;margin-top:.25rem}
  .blue{color:#58a6ff}.green{color:#3fb950}.yellow{color:#d29922}.red{color:#f85149}
  .host{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:1.5rem;overflow:hidden}
  .host-header{background:#21262d;padding:.75rem 1rem;display:flex;justify-content:space-between;align-items:center}
  .host-ip{font-weight:700;color:#58a6ff;font-size:1rem}
  .host-os{font-size:.8rem;color:#8b949e}
  .badge{padding:.2rem .6rem;border-radius:4px;font-size:.75rem;font-weight:600}
  .badge-ok{background:#1a3a1a;color:#3fb950}
  .badge-med{background:#3a2a0a;color:#d29922}
  .badge-hi{background:#3a1010;color:#f85149}
  .host-body{padding:1rem}
  table{width:100%;border-collapse:collapse;font-size:.85rem;margin-top:.5rem}
  th{color:#8b949e;text-align:left;padding:.4rem .75rem;border-bottom:1px solid #21262d;font-size:.75rem;text-transform:uppercase}
  td{padding:.5rem .75rem;border-bottom:1px solid #21262d}
  .risk-port{color:#f85149}
  .findings{margin-top:1rem;padding:.75rem;background:#1a0f0f;border:1px solid #3a1010;border-radius:6px}
  .findings h4{color:#f85149;margin-bottom:.5rem;font-size:.85rem}
  .finding{font-size:.82rem;padding:.25rem 0;border-bottom:1px solid #2a1515}
  .finding:last-child{border:none}
  .sev-CRITICO{color:#f85149;font-weight:700}
  .sev-ALTO{color:#d29922;font-weight:700}
</style>
</head>
<body>
<h1>🔍 Network Scan Report</h1>
<div class="meta">Target: <strong>{target}</strong> &nbsp;|&nbsp; {timestamp} &nbsp;|&nbsp; {host_count} host(s) encontrado(s)</div>
<div class="summary">
  <div class="card"><div class="n blue">{host_count}</div><div class="l">Hosts ativos</div></div>
  <div class="card"><div class="n green">{total_ports}</div><div class="l">Portas abertas</div></div>
  <div class="card"><div class="n yellow">{total_risks}</div><div class="l">Achados de risco</div></div>
  <div class="card"><div class="n red">{critical_count}</div><div class="l">Críticos</div></div>
</div>
{hosts_html}
</body></html>"""

def build_host_html(h: dict) -> str:
    score = h["risk_score"]
    badge = (
        '<span class="badge badge-hi">ALTO RISCO</span>'  if score >= 3 else
        '<span class="badge badge-med">MÉDIO RISCO</span>' if score >= 1 else
        '<span class="badge badge-ok">BAIXO RISCO</span>'
    )

    port_rows = ""
    for p in h["open_ports"]:
        risk_cls = ' class="risk-port"' if p["risk"] else ""
        risk_icon = "⚠️ " if p["risk"] else ""
        port_rows += f"<tr><td{risk_cls}>{risk_icon}{p['port']}/{p['protocol']}</td><td>{p['service']}</td><td>{p['version'] or '—'}</td><td{risk_cls}>{p['risk'] or '—'}</td></tr>"

    findings_html = ""
    if h["risk_findings"]:
        items = ""
        for f in h["risk_findings"]:
            items += f'<div class="finding"><span class="sev-{f["sev"]}">[{f["sev"]}]</span> Porta {f["port"]} ({f["service"]}): {f["reason"]}</div>'
        findings_html = f'<div class="findings"><h4>⚠ Achados de Segurança</h4>{items}</div>'

    return f"""
<div class="host">
  <div class="host-header">
    <div>
      <span class="host-ip">{h['ip']}</span>
      <span class="host-os"> — {h['hostname']} | {h['os']}</span>
    </div>
    {badge}
  </div>
  <div class="host-body">
    <table>
      <tr><th>Porta</th><th>Serviço</th><th>Versão</th><th>Observação</th></tr>
      {port_rows if port_rows else '<tr><td colspan="4" style="color:#8b949e">Nenhuma porta aberta detectada</td></tr>'}
    </table>
    {findings_html}
  </div>
</div>"""

def export_html(hosts: list, target: str, out_dir: Path) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    total_ports  = sum(len(h["open_ports"])    for h in hosts)
    total_risks  = sum(len(h["risk_findings"]) for h in hosts)
    critical     = sum(1 for h in hosts for f in h["risk_findings"] if f["sev"] == "CRITICO")
    hosts_html   = "\n".join(build_host_html(h) for h in hosts)

    html = HTML_TEMPLATE.format(
        target=target,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M"),
        host_count=len(hosts),
        total_ports=total_ports,
        total_risks=total_risks,
        critical_count=critical,
        hosts_html=hosts_html,
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"scan_report_{ts}.html"
    out_file.write_text(html, encoding="utf-8")
    ok(f"Relatório HTML → {out_file}")

    json_file = out_dir / f"scan_results_{ts}.json"
    json_file.write_text(json.dumps({
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "hosts": hosts
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    ok(f"Dados JSON → {json_file}")
    return out_file

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print("\n  ╔══════════════════════════════════════════════╗")
    print("  ║    Network Scanner — Portfólio Segurança    ║")
    print("  ╚══════════════════════════════════════════════╝\n")

    p = argparse.ArgumentParser(description="Scanner de rede com análise de risco")
    p.add_argument("--target", required=True, help="IP, range (192.168.1.0/24) ou hostname")
    p.add_argument("--ports",  default="1-1024", help="Portas a escanear (padrão: 1-1024)")
    p.add_argument("--fast",   action="store_true", help="Scan rápido (top 100 portas)")
    p.add_argument("--out",    default="reports", help="Pasta de saída")
    args = p.parse_args()

    nm    = scan(args.target, args.ports, args.fast)
    hosts = parse_results(nm)

    if not hosts:
        warn("Nenhum host encontrado. Verifique o target e conectividade.")
        return

    export_html(hosts, args.target, Path(args.out))
    print(f"\n  Scan concluído — {len(hosts)} host(s) analisado(s)\n")

if __name__ == "__main__":
    main()
