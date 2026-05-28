# ============================================================
# SCRIPT 2 — Stale Accounts (90+ Days No Sign-In)
# READ ONLY — no changes made to tenant
# Requires: Microsoft Graph REST API via Azure Cloud Shell
# Scopes:   AuditLog.Read.All, User.Read.All
# Note:     SignInActivity requires Entra ID P1 or P2
# Output:   IAM-Audit/StaleAccounts_Audit.csv
# ============================================================

New-Item -ItemType Directory -Path "/home/jay/IAM-Audit" -Force | Out-Null

# Get token from existing Azure Cloud Shell session
$tokenObj = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
$token    = [System.Net.NetworkCredential]::new("", $tokenObj.Token).Password
$headers  = @{ Authorization = "Bearer $token" }

$cutoffDays = 90
$cutoffDate = (Get-Date).AddDays(-$cutoffDays)
$results    = @()

# GET all users with sign-in and license data — paginated
$uri = "https://graph.microsoft.com/v1.0/users?`$select=displayName,userPrincipalName,accountEnabled,userType,signInActivity,assignedLicenses,createdDateTime&`$top=999"

do {
    $response = Invoke-RestMethod -Uri $uri -Headers $headers
    $users    = $response.value

    foreach ($user in $users) {

        # Filter locally — active, licensed, member accounts only
        if ($user.accountEnabled -ne $true)      { continue }
        if ($user.userType -ne "Member")          { continue }
        if ($user.assignedLicenses.Count -eq 0)  { continue }

        # Null-safe sign-in check
        $lastSignIn    = $null
        $lastSignInStr = "Never"
        $staleDays     = "N/A"

        if ($user.signInActivity -and $user.signInActivity.lastSignInDateTime) {
            $lastSignIn    = [datetime]$user.signInActivity.lastSignInDateTime
            $lastSignInStr = $lastSignIn.ToString("yyyy-MM-dd")
            $staleDays     = [int]((Get-Date) - $lastSignIn).TotalDays
        }

        # Include: never signed in OR last sign-in older than cutoff
        $isStale = ($null -eq $lastSignIn) -or ($lastSignIn -lt $cutoffDate)
        if (-not $isStale) { continue }

        # Null-safe CreatedDateTime
        $createdStr = if ($user.createdDateTime) {
            ([datetime]$user.createdDateTime).ToString("yyyy-MM-dd")
        } else { "Unknown" }

        $results += [PSCustomObject]@{
            DisplayName     = $user.displayName
            UPN             = $user.userPrincipalName
            LastSignIn      = $lastSignInStr
            DaysSinceSignIn = $staleDays
            LicenseCount    = $user.assignedLicenses.Count
            CreatedDate     = $createdStr
            Flag            = if ($null -eq $lastSignIn) { "NEVER SIGNED IN" } else { "STALE $cutoffDays+ DAYS" }
        }
    }

    $uri = $response.'@odata.nextLink'

} while ($uri)

Write-Host "Stale licensed accounts found: $($results.Count)" -ForegroundColor Yellow
$results | Sort-Object Flag, LastSignIn | Format-Table -AutoSize
$results | Export-Csv -Path "/home/jay/IAM-Audit/StaleAccounts_Audit.csv" -NoTypeInformation
Write-Host "Done. Exported: /home/jay/IAM-Audit/StaleAccounts_Audit.csv" -ForegroundColor Green
