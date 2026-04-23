#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Aplica configurações de hardening via GPO local e audita o estado do domínio.
.DESCRIPTION
    Script de portfólio: configura políticas de senha, lockout, auditoria de
    eventos e segurança de rede diretamente no controlador de domínio.
    Gera relatório HTML com antes/depois de cada configuração aplicada.
.EXAMPLE
    .\Apply-Hardening.ps1 -DomainName "empresa.local" -ReportPath "C:\reports"
.NOTES
    Autor : Matheus Calheiros
    Req.  : Windows Server 2019/2022, RSAT AD Tools
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$DomainName,
    [string]$ReportPath = "$PSScriptRoot\..\reports-template",
    [switch]$AuditOnly   # Se ativo, só lê — não aplica nada
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─── Paleta de saída ──────────────────────────────────────────────────────────
function Write-OK   { param($m) Write-Host "[+] $m" -ForegroundColor Green  }
function Write-Info { param($m) Write-Host "[*] $m" -ForegroundColor Cyan   }
function Write-Warn { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Fail { param($m) Write-Host "[-] $m" -ForegroundColor Red    }

# ─── Módulo AD ───────────────────────────────────────────────────────────────
function Assert-ADModule {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Fail "Módulo ActiveDirectory não encontrado. Instale o RSAT."
        exit 1
    }
    Import-Module ActiveDirectory -Verbose:$false
    Write-OK "Módulo ActiveDirectory carregado"
}

# ─── 1. Política de senhas ───────────────────────────────────────────────────
function Set-PasswordPolicy {
    Write-Info "Configurando política de senhas..."
    $before = Get-ADDefaultDomainPasswordPolicy -Identity $DomainName

    $params = @{
        Identity              = $DomainName
        MinPasswordLength     = 12
        PasswordHistoryCount  = 24
        MaxPasswordAge        = (New-TimeSpan -Days 90)
        MinPasswordAge        = (New-TimeSpan -Days 1)
        ComplexityEnabled     = $true
        ReversibleEncryptionEnabled = $false
    }

    $result = [PSCustomObject]@{
        Category = "Política de Senhas"
        Settings = @()
    }

    $checks = @(
        @{ Name="Comprimento mínimo"; Before=$before.MinPasswordLength;    After=12;    Pass=($before.MinPasswordLength -ge 12) }
        @{ Name="Histórico de senhas"; Before=$before.PasswordHistoryCount; After=24;    Pass=($before.PasswordHistoryCount -ge 24) }
        @{ Name="Expiração máxima";   Before=$before.MaxPasswordAge.Days;  After="90d"; Pass=($before.MaxPasswordAge.Days -le 90) }
        @{ Name="Complexidade";        Before=$before.ComplexityEnabled;    After=$true; Pass=$before.ComplexityEnabled }
        @{ Name="Criptografia reversa";Before=$before.ReversibleEncryptionEnabled; After=$false; Pass=(-not $before.ReversibleEncryptionEnabled) }
    )

    foreach ($c in $checks) {
        $result.Settings += [PSCustomObject]@{
            Setting = $c.Name
            Antes   = $c.Before
            Depois  = $c.After
            Status  = if ($c.Pass) { "OK" } else { "CORRIGIDO" }
        }
    }

    if (-not $AuditOnly -and $PSCmdlet.ShouldProcess($DomainName, "Aplicar política de senhas")) {
        Set-ADDefaultDomainPasswordPolicy @params
        Write-OK "Política de senhas aplicada"
    } else {
        Write-Warn "Modo AuditOnly — política NÃO aplicada"
    }

    return $result
}

# ─── 2. Account Lockout ───────────────────────────────────────────────────────
function Set-LockoutPolicy {
    Write-Info "Configurando política de bloqueio de conta..."
    $before = Get-ADDefaultDomainPasswordPolicy -Identity $DomainName

    $params = @{
        Identity              = $DomainName
        LockoutThreshold      = 5
        LockoutDuration       = (New-TimeSpan -Minutes 30)
        LockoutObservationWindow = (New-TimeSpan -Minutes 30)
    }

    $result = [PSCustomObject]@{
        Category = "Account Lockout"
        Settings = @(
            [PSCustomObject]@{ Setting="Tentativas antes do bloqueio"; Antes=$before.LockoutThreshold;       Depois=5;      Status=if($before.LockoutThreshold -in 3..5){"OK"}else{"CORRIGIDO"} }
            [PSCustomObject]@{ Setting="Duração do bloqueio (min)";    Antes=$before.LockoutDuration.Minutes; Depois=30;     Status=if($before.LockoutDuration.Minutes -ge 15){"OK"}else{"CORRIGIDO"} }
            [PSCustomObject]@{ Setting="Janela de observação (min)";   Antes=$before.LockoutObservationWindow.Minutes; Depois=30; Status="CONFIGURADO" }
        )
    }

    if (-not $AuditOnly -and $PSCmdlet.ShouldProcess($DomainName, "Aplicar lockout policy")) {
        Set-ADDefaultDomainPasswordPolicy @params
        Write-OK "Lockout policy aplicada"
    }
    return $result
}

# ─── 3. Auditoria de eventos (auditpol) ──────────────────────────────────────
function Set-AuditPolicy {
    Write-Info "Configurando auditoria de eventos de segurança..."

    $categories = @(
        @{ Name="Account Logon";        Sub="Credential Validation" }
        @{ Name="Account Management";   Sub="User Account Management" }
        @{ Name="Logon/Logoff";         Sub="Logon" }
        @{ Name="Object Access";        Sub="File System" }
        @{ Name="Policy Change";        Sub="Audit Policy Change" }
        @{ Name="Privilege Use";        Sub="Sensitive Privilege Use" }
        @{ Name="System";               Sub="Security System Extension" }
    )

    $result = [PSCustomObject]@{ Category="Auditoria de Eventos"; Settings=@() }

    foreach ($cat in $categories) {
        if (-not $AuditOnly) {
            auditpol /set /subcategory:"$($cat.Sub)" /success:enable /failure:enable 2>&1 | Out-Null
        }
        $current = auditpol /get /subcategory:"$($cat.Sub)" 2>&1
        $result.Settings += [PSCustomObject]@{
            Setting = "$($cat.Name) → $($cat.Sub)"
            Antes   = "Variável"
            Depois  = "Sucesso e Falha"
            Status  = if ($current -match "Success and Failure") { "OK" } else { if ($AuditOnly) { "PENDENTE" } else { "CORRIGIDO" } }
        }
    }

    Write-OK "Política de auditoria configurada ($($categories.Count) categorias)"
    return $result
}

# ─── 4. Contas privilegiadas ──────────────────────────────────────────────────
function Get-PrivilegedAccountsAudit {
    Write-Info "Auditando contas privilegiadas..."

    $domainAdmins    = Get-ADGroupMember "Domain Admins"    -Recursive -ErrorAction SilentlyContinue
    $enterpriseAdmins = Get-ADGroupMember "Enterprise Admins" -Recursive -ErrorAction SilentlyContinue
    $schemaAdmins    = Get-ADGroupMember "Schema Admins"    -Recursive -ErrorAction SilentlyContinue

    $all = @($domainAdmins; $enterpriseAdmins; $schemaAdmins) | Select-Object -Unique -Property SamAccountName, DistinguishedName

    $result = [PSCustomObject]@{ Category="Contas Privilegiadas"; Settings=@() }
    foreach ($acc in $all) {
        $user = Get-ADUser $acc.SamAccountName -Properties Enabled, LastLogonDate, PasswordNeverExpires -ErrorAction SilentlyContinue
        if ($user) {
            $risk = @()
            if (-not $user.Enabled)            { $risk += "CONTA DESATIVADA" }
            if ($user.PasswordNeverExpires)    { $risk += "SENHA SEM EXPIRAÇÃO" }
            if (-not $user.LastLogonDate)      { $risk += "NUNCA LOGOU" }

            $result.Settings += [PSCustomObject]@{
                Setting = $user.SamAccountName
                Antes   = $acc.DistinguishedName
                Depois  = if ($risk) { $risk -join " | " } else { "Sem riscos detectados" }
                Status  = if ($risk) { "RISCO" } else { "OK" }
            }
        }
    }

    Write-OK "$($result.Settings.Count) conta(s) privilegiada(s) auditada(s)"
    return $result
}

# ─── 5. Relatório HTML ────────────────────────────────────────────────────────
function Export-HtmlReport {
    param([array]$Results, [string]$Domain)

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"
    $ts_file   = Get-Date -Format "yyyyMMdd_HHmmss"

    $rows = foreach ($section in $Results) {
        "<tr><td colspan='4' class='section'>$($section.Category)</td></tr>"
        foreach ($s in $section.Settings) {
            $cls = switch ($s.Status) {
                "OK"         { "ok" }
                "CORRIGIDO"  { "fixed" }
                "RISCO"      { "risk" }
                default      { "info" }
            }
            "<tr><td>$($s.Setting)</td><td>$($s.Antes)</td><td>$($s.Depois)</td><td class='$cls'>$($s.Status)</td></tr>"
        }
    }

    $total   = ($Results | ForEach-Object { $_.Settings } | Measure-Object).Count
    $ok      = ($Results | ForEach-Object { $_.Settings } | Where-Object { $_.Status -eq "OK" } | Measure-Object).Count
    $fixed   = ($Results | ForEach-Object { $_.Settings } | Where-Object { $_.Status -eq "CORRIGIDO" } | Measure-Object).Count
    $risks   = ($Results | ForEach-Object { $_.Settings } | Where-Object { $_.Status -eq "RISCO" } | Measure-Object).Count

    $html = @"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Hardening Report — $Domain</title>
<style>
  body  { font-family: 'Segoe UI', sans-serif; background:#0d1117; color:#c9d1d9; margin:0; padding:2rem; }
  h1    { color:#58a6ff; border-bottom:1px solid #30363d; padding-bottom:.5rem; }
  .meta { color:#8b949e; font-size:.9rem; margin-bottom:2rem; }
  .cards{ display:grid; grid-template-columns:repeat(4,1fr); gap:1rem; margin-bottom:2rem; }
  .card { background:#161b22; border:1px solid #30363d; border-radius:8px; padding:1rem; text-align:center; }
  .card .num{ font-size:2rem; font-weight:700; }
  .card .lbl{ font-size:.8rem; color:#8b949e; }
  .c-ok  { color:#3fb950; }
  .c-fix { color:#d29922; }
  .c-rsk { color:#f85149; }
  .c-tot { color:#58a6ff; }
  table { width:100%; border-collapse:collapse; background:#161b22; border-radius:8px; overflow:hidden; }
  th    { background:#21262d; padding:.75rem 1rem; text-align:left; color:#8b949e; font-size:.85rem; letter-spacing:.05em; }
  td    { padding:.65rem 1rem; border-bottom:1px solid #21262d; font-size:.9rem; }
  .section{ background:#0d1117; color:#58a6ff; font-weight:600; font-size:.85rem; letter-spacing:.1em; text-transform:uppercase; }
  .ok   { color:#3fb950; font-weight:600; }
  .fixed{ color:#d29922; font-weight:600; }
  .risk { color:#f85149; font-weight:600; }
  .info { color:#58a6ff; }
</style>
</head>
<body>
<h1>🔒 Hardening Report</h1>
<div class="meta">Domínio: <strong>$Domain</strong> &nbsp;|&nbsp; Gerado em: $timestamp &nbsp;|&nbsp; Modo: $(if($AuditOnly){"Auditoria"}else{"Aplicação"})</div>
<div class="cards">
  <div class="card"><div class="num c-tot">$total</div><div class="lbl">Total de verificações</div></div>
  <div class="card"><div class="num c-ok">$ok</div><div class="lbl">Já conformes</div></div>
  <div class="card"><div class="num c-fix">$fixed</div><div class="lbl">Corrigidos</div></div>
  <div class="card"><div class="num c-rsk">$risks</div><div class="lbl">Riscos detectados</div></div>
</div>
<table>
  <tr><th>Configuração</th><th>Antes</th><th>Depois / Valor</th><th>Status</th></tr>
  $($rows -join "`n  ")
</table>
</body>
</html>
"@

    $outFile = "$ReportPath\hardening_$ts_file.html"
    New-Item -ItemType Directory -Force -Path $ReportPath | Out-Null
    $html | Out-File -FilePath $outFile -Encoding UTF8
    Write-OK "Relatório exportado → $outFile"
    return $outFile
}

# ─── Main ─────────────────────────────────────────────────────────────────────
function Main {
    Write-Host "`n  ╔══════════════════════════════════════════════╗" -ForegroundColor Blue
    Write-Host "  ║    AD Hardening & GPO Audit Tool             ║" -ForegroundColor Blue
    Write-Host "  ╚══════════════════════════════════════════════╝`n" -ForegroundColor Blue

    Assert-ADModule

    $results = @(
        Set-PasswordPolicy
        Set-LockoutPolicy
        Set-AuditPolicy
        Get-PrivilegedAccountsAudit
    )

    $reportFile = Export-HtmlReport -Results $results -Domain $DomainName

    Write-Host "`n  Concluído. Abra o relatório em:" -ForegroundColor Green
    Write-Host "  $reportFile`n" -ForegroundColor Cyan
}

Main
