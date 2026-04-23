# Setup do Lab — Kali Linux + Metasploitable 2

Guia completo para montar o ambiente ofensivo/defensivo do zero no VirtualBox.

## Pré-requisitos

- VirtualBox 7.x instalado
- Mínimo 8GB RAM disponível
- 40GB de espaço em disco

## Downloads necessários

| VM | Link oficial | SHA256 (verificar) |
|---|---|---|
| Kali Linux VirtualBox | https://www.kali.org/get-kali/#kali-virtual-machines | Disponível na página |
| Metasploitable 2 | https://sourceforge.net/projects/metasploitable/ | — |

## Configuração de rede isolada

```
VirtualBox > Ferramentas > Rede > Criar rede "labnet"
  - IPv4: 192.168.56.0/24
  - DHCP: desabilitado (IPs fixos em cada VM)
```

### Kali Linux
```
Adaptador 1: NAT (acesso à internet para updates)
Adaptador 2: Rede interna "labnet"
```

### Metasploitable 2
```
Adaptador 1: Rede interna "labnet" APENAS
(nunca expor o Metasploitable à internet)
```

## IPs estáticos

### Kali (interface eth1 — rede interna)
```bash
# /etc/network/interfaces
auto eth1
iface eth1 inet static
  address 192.168.56.101
  netmask 255.255.255.0
```

### Metasploitable
```bash
# Após boot (login: msfadmin/msfadmin)
sudo nano /etc/network/interfaces
# Configurar eth0 com 192.168.56.102
```

## Verificação do isolamento

```bash
# No Kali — deve responder
ping 192.168.56.102

# No Kali — NÃO deve responder (Metasploitable sem acesso externo)
# O Metasploitable não deve conseguir pingar IPs externos
```

## Snapshots recomendados

Antes de começar qualquer exercício, tire um snapshot de ambas as VMs:
```
VirtualBox > Máquina > Tirar snapshot > "Estado limpo"
```

Após cada exercício, restaure para o estado limpo para garantir um ambiente consistente.
