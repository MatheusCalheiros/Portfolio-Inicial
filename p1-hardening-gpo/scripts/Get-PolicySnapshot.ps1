#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Snapshot rápido das políticas de domínio — sem aplicar nada.
.EXAMPLE
    .\Get-PolicySnapshot.ps1 -DomainName empresa.local
#>
param([Parameter(Mandatory)][string]$DomainName)

Import-Module ActiveDirectory -Verbose:$false

$policy  = Get-ADDefaultDomainPasswordPolicy -Identity $DomainName
$domAdm  = (Get-ADGroupMember "Domain Admins" -Recursive -ErrorAction SilentlyContinue).Count

Write-Host "`n═══════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  SNAPSHOT DE POLÍTICAS — $DomainName"    -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════`n" -ForegroundColor Cyan

Write-Host "SENHAS" -ForegroundColor Yellow
Write-Host "  Comprimento mínimo      : $($policy.MinPasswordLength)"
Write-Host "  Histórico               : $($policy.PasswordHistoryCount)"
Write-Host "  Expiração máxima        : $($policy.MaxPasswordAge.Days) dias"
Write-Host "  Expiração mínima        : $($policy.MinPasswordAge.Days) dias"
Write-Host "  Complexidade habilitada : $($policy.ComplexityEnabled)"
Write-Host "  Criptografia reversível : $($policy.ReversibleEncryptionEnabled)"

Write-Host "`nLOCKOUT" -ForegroundColor Yellow
Write-Host "  Tentativas até bloqueio : $($policy.LockoutThreshold)"
Write-Host "  Duração do bloqueio     : $($policy.LockoutDuration.Minutes) minutos"
Write-Host "  Janela de observação    : $($policy.LockoutObservationWindow.Minutes) minutos"

Write-Host "`nACCOUNT" -ForegroundColor Yellow
Write-Host "  Domain Admins (total)   : $domAdm"

$usersNoPwdExpiry = (Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} | Measure-Object).Count
$usersDisabled    = (Get-ADUser -Filter {Enabled -eq $false} | Measure-Object).Count
Write-Host "  Usuários ativos sem expiração de senha: $usersNoPwdExpiry"
Write-Host "  Contas desativadas                    : $usersDisabled"
Write-Host ""
