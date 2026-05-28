# ============================================================
# NHI SCRIPT 1 — Active Directory Service Accounts
# READ ONLY — no changes made to AD
# Requires: PowerShell 7 on a domain-joined machine with RSAT
# Run from: Domain-joined machine — NOT Azure Cloud Shell
# Output:   C:\IAM-Audit\NHI_AD_ServiceAccounts.csv
# ============================================================

New-Item -ItemType Directory -Path "C:\IAM-Audit" -Force | Out-Null

Import-Module ActiveDirectory

# GET all enabled accounts where password never expires
# These are almost always service accounts or ungoverned accounts
$accounts = Get-ADUser -Filter {
    PasswordNeverExpires -eq $true -and Enabled -eq $true
} -Properties `
    DisplayName, SamAccountName, PasswordNeverExpires,
    LastLogonDate, PasswordLastSet, Description,
    MemberOf, ServicePrincipalNames, Created

$results = @()

foreach ($acct in $accounts) {

    # Password age in days
    $pwdAge = if ($acct.PasswordLastSet) {
        [int]((Get-Date) - $acct.PasswordLastSet).TotalDays
    } else { 9999 }

    # Days since last logon
    $lastLogonDays = if ($acct.LastLogonDate) {
        [int]((Get-Date) - $acct.LastLogonDate).TotalDays
    } else { 9999 }

    # Group count — high count = high blast radius if compromised
    $groupCount = $acct.MemberOf.Count

    # SPN presence confirms this is a true service account
    $hasSPN = ($acct.ServicePrincipalNames.Count -gt 0)

    # Risk scoring
    $riskScore = 0
    if ($pwdAge -gt 365)        { $riskScore += 2 }
    if (-not $acct.Description) { $riskScore += 2 }
    if ($groupCount -gt 10)     { $riskScore += 3 }
    if ($lastLogonDays -gt 90)  { $riskScore += 2 }

    $riskLevel = if ($riskScore -ge 7)     { "HIGH" }
                 elseif ($riskScore -ge 4) { "MEDIUM" }
                 else                      { "LOW" }

    $results += [PSCustomObject]@{
        DisplayName      = $acct.DisplayName
        SamAccountName   = $acct.SamAccountName
        Description      = if ($acct.Description) { $acct.Description } else { "NO DESCRIPTION" }
        PasswordAge_Days = $pwdAge
        LastLogon        = if ($acct.LastLogonDate) { $acct.LastLogonDate.ToString("yyyy-MM-dd") } else { "Never" }
        DaysSinceLogon   = $lastLogonDays
        GroupCount       = $groupCount
        HasSPN           = $hasSPN
        Created          = if ($acct.Created) { $acct.Created.ToString("yyyy-MM-dd") } else { "Unknown" }
        RiskScore        = $riskScore
        RiskLevel        = $riskLevel
    }
}

$high = $results | Where-Object { $_.RiskLevel -eq "HIGH" }
$med  = $results | Where-Object { $_.RiskLevel -eq "MEDIUM" }

Write-Host ""
Write-Host "Total service accounts found: $($results.Count)" -ForegroundColor Cyan
Write-Host "HIGH risk:   $($high.Count)" -ForegroundColor Red
Write-Host "MEDIUM risk: $($med.Count)" -ForegroundColor Yellow

$results | Sort-Object RiskScore -Descending | Format-Table -AutoSize
$results | Sort-Object RiskScore -Descending |
    Export-Csv -Path "C:\IAM-Audit\NHI_AD_ServiceAccounts.csv" -NoTypeInformation
Write-Host "Done. Exported: C:\IAM-Audit\NHI_AD_ServiceAccounts.csv" -ForegroundColor Green
