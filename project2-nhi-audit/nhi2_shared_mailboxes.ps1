# ============================================================
# NHI SCRIPT 2 — Shared Mailboxes with Sign-In Enabled
# READ ONLY — no changes made to tenant
# Requires: Microsoft Graph REST API via Azure Cloud Shell
# Scopes:   User.Read.All
# Note:     Hybrid environments — mailboxSettings endpoint
#           unavailable for on-premises mailboxes.
#           For hybrid tenants run from local PS7 with
#           Exchange Online PowerShell module instead.
# Output:   IAM-Audit/NHI_SharedMailboxes.csv
# ============================================================

New-Item -ItemType Directory -Path "/home/jay/IAM-Audit" -Force | Out-Null

# Get token from existing Azure Cloud Shell session
$tokenObj = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
$token    = [System.Net.NetworkCredential]::new("", $tokenObj.Token).Password
$headers  = @{ Authorization = "Bearer $token" }

$results     = @()
$allAccounts = @()

# GET all active accounts
$uri = "https://graph.microsoft.com/v1.0/users?`$filter=accountEnabled eq true&`$select=id,displayName,userPrincipalName,accountEnabled,assignedLicenses,createdDateTime,signInActivity&`$top=999"

do {
    $response     = Invoke-RestMethod -Uri $uri -Headers $headers
    $allAccounts += $response.value
    $uri          = $response.'@odata.nextLink'
} while ($uri)

Write-Host "Checking $($allAccounts.Count) accounts for shared mailbox indicators..." -ForegroundColor Cyan

foreach ($user in $allAccounts) {

    # Check mailbox settings to identify shared mailboxes
    $mailboxType = $null
    try {
        $mbSettings  = Invoke-RestMethod `
            -Uri "https://graph.microsoft.com/v1.0/users/$($user.id)/mailboxSettings" `
            -Headers $headers -ErrorAction Stop
        $mailboxType = $mbSettings.userPurpose
    } catch { continue }

    # Only process shared mailboxes
    if ($mailboxType -ne "shared") { continue }

    # Sign-in activity
    $lastSignInStr   = "Never"
    $daysSinceSignIn = "N/A"
    if ($user.signInActivity -and $user.signInActivity.lastSignInDateTime) {
        $lastSignIn      = [datetime]$user.signInActivity.lastSignInDateTime
        $lastSignInStr   = $lastSignIn.ToString("yyyy-MM-dd")
        $daysSinceSignIn = [int]((Get-Date) - $lastSignIn).TotalDays
    }

    $risk = if ($user.accountEnabled) {
        "HIGH - Sign-in enabled on shared mailbox"
    } else {
        "OK - Sign-in disabled"
    }

    $results += [PSCustomObject]@{
        DisplayName      = $user.displayName
        UPN              = $user.userPrincipalName
        MailboxType      = $mailboxType
        SignInEnabled    = $user.accountEnabled
        LicenseCount     = $user.assignedLicenses.Count
        LastSignIn       = $lastSignInStr
        DaysSinceSignIn  = $daysSinceSignIn
        Risk             = $risk
    }
}

$highRisk = $results | Where-Object { $_.SignInEnabled -eq $true }

Write-Host ""
Write-Host "Total shared mailboxes found: $($results.Count)" -ForegroundColor Cyan
Write-Host "Sign-in ENABLED (HIGH risk):  $($highRisk.Count)" -ForegroundColor Red

$results | Sort-Object SignInEnabled -Descending | Format-Table -AutoSize
$results | Sort-Object SignInEnabled -Descending |
    Export-Csv -Path "/home/jay/IAM-Audit/NHI_SharedMailboxes.csv" -NoTypeInformation
Write-Host "Done. Exported: /home/jay/IAM-Audit/NHI_SharedMailboxes.csv" -ForegroundColor Green
