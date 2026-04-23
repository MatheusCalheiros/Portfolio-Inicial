# Setup do Wazuh — Servidor + Agente Windows

Guia de instalação do ambiente SIEM completo integrado ao lab Windows Server.

## Arquitetura

```
┌─────────────────────────────────────────────────────────────┐
│  VirtualBox — Rede interna: 192.168.10.0/24                │
│                                                             │
│  ┌─────────────────────┐    ┌──────────────────────────┐   │
│  │  Ubuntu Server 22   │    │  Windows Server 2022     │   │
│  │  192.168.10.20      │◄───│  192.168.10.10 (DC)      │   │
│  │                     │    │                          │   │
│  │  Wazuh Manager      │    │  Wazuh Agent             │   │
│  │  Wazuh Indexer      │    │  (coleta eventos AD)     │   │
│  │  Wazuh Dashboard    │    │                          │   │
│  │  (OpenSearch)       │    │  + Hardening GPO (P1)    │   │
│  └─────────────────────┘    └──────────────────────────┘   │
│                                                             │
│  ┌─────────────────────┐                                    │
│  │  Windows 10 Client  │                                    │
│  │  192.168.10.30      │ (Wazuh Agent opcional)            │
│  └─────────────────────┘                                    │
└─────────────────────────────────────────────────────────────┘
```

## VM Ubuntu — Servidor Wazuh

**Especificações mínimas:** 4 vCPU, 8GB RAM, 50GB disco

```bash
# 1. Instalar Wazuh (All-in-one: Manager + Indexer + Dashboard)
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.9/config.yml

# 2. Editar config.yml com os IPs do seu lab
#    nodes.indexer.ip: 192.168.10.20
#    nodes.server.ip:  192.168.10.20
#    nodes.dashboard.ip: 192.168.10.20

# 3. Executar instalação
sudo bash wazuh-install.sh -a

# Anotar as credenciais geradas ao final (admin + senha)
```

**Acessar o dashboard:**
```
https://192.168.10.20  →  admin / <senha gerada>
```

## Instalar agente no Windows Server (DC)

No Windows Server, como Administrador:

```powershell
# Baixar e instalar agente Wazuh
$url = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi"
Invoke-WebRequest -Uri $url -OutFile "wazuh-agent.msi"

msiexec.exe /i wazuh-agent.msi `
  WAZUH_MANAGER="192.168.10.20" `
  WAZUH_AGENT_NAME="WIN-DC01" `
  /quiet

# Iniciar o serviço
NET START WazuhSvc
```

## Aplicar configurações customizadas

```powershell
# Copiar ossec.conf customizado (deste projeto)
Copy-Item "configs\agent\ossec.conf" `
  "C:\Program Files (x86)\ossec-agent\ossec.conf" -Force

# Reiniciar agente para aplicar
Restart-Service WazuhSvc
```

## Aplicar regras customizadas

No servidor Wazuh (Ubuntu):

```bash
# Copiar regras do projeto
sudo cp configs/wazuh-rules/local_rules.xml \
  /var/ossec/etc/rules/local_rules.xml

# Validar sintaxe
sudo /var/ossec/bin/wazuh-logtest

# Reiniciar manager
sudo systemctl restart wazuh-manager
```

## Verificar funcionamento

```bash
# Ver agentes conectados
sudo /var/ossec/bin/agent_control -l

# Acompanhar alertas em tempo real
sudo tail -f /var/ossec/logs/alerts/alerts.json | python3 -m json.tool
```

## Testar as regras (gerar eventos)

No Windows Server, execute ações que devem gerar alertas:

```powershell
# Gerar falhas de autenticação (testa regra 100100/100101)
for ($i=0; $i -lt 6; $i++) {
    $cred = New-Object System.Management.Automation.PSCredential("usuário_invalido", (ConvertTo-SecureString "senha_errada" -AsPlainText -Force))
    try { Start-Process cmd -Credential $cred -ErrorAction Stop } catch {}
    Start-Sleep 5
}

# Criar usuário de teste (testa regra 100110)
New-ADUser -Name "teste.siem" -SamAccountName "teste.siem" -Enabled $false

# Limpar depois
Remove-ADUser -Identity "teste.siem" -Confirm:$false
```

## Script de relatório

```bash
# Instalar dependências
pip install requests colorama

# Modo demo (sem Wazuh real)
python scripts/wazuh_report.py --demo

# Com Wazuh real
python scripts/wazuh_report.py --host 192.168.10.20 --user admin --hours 24
```
