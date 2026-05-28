# ============================================================
# SCRIPT 4 — Guest Account Exposure
# READ ONLY — no changes made to tenant
# Requires: Microsoft Graph REST API via Azure Cloud Shell
# Scopes:   User.Read.All, GroupMember.Read.All
# Output:   IAM-Audit/GuestAccounts_Audit.csv
# ============================================================

New-Item -ItemType Directory -Path "/home/jay/IAM-Audit" -Force | Out-Null

# Get token from existing Azure Cloud Shell session
$tokenObj = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
$token    = [System.Net.NetworkCredential]::new("", $tokenObj.Token).Password
$headers  = @{ Authorization = "Bearer $token" }

$results   = @()
$allGuests = @()

# GET all guest users with required fields
$uri = "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$select=id,displayName,userPrincipalName,accountEnabled,createdDateTime,signInActivity,assignedLicenses,externalUserState,userType&`$top=999"

do {
    $response   = Invoke-RestMethod -Uri $uri -Headers $headers
    $allGuests += $response.value
    $uri        = $response.'@odata.nextLink'
} while ($uri)

Write-Host "Total guest accounts found: $($allGuests.Count)" -ForegroundColor Yellow

$i = 0
foreach ($guest in $allGuests) {
    $i++
    Write-Host "Processing $i of $($allGuests.Count): $($guest.displayName)" -ForegroundColor Cyan

    # Null-safe sign-in
    $lastSignInStr   = "Never"
    $daysSinceSignIn = "N/A"
    if ($guest.signInActivity -and $guest.signInActivity.lastSignInDateTime) {
        $lastSignIn      = [datetime]$guest.signInActivity.lastSignInDateTime
        $lastSignInStr   = $lastSignIn.ToString("yyyy-MM-dd")
        $daysSinceSignIn = [int]((Get-Date) - $lastSignIn).TotalDays
    }

    # Null-safe created date
    $createdStr = if ($guest.createdDateTime) {
        ([datetime]$guest.createdDateTime).ToString("yyyy-MM-dd")
    } else { "Unknown" }

    # Flag pending invites 30+ days old
    $inviteFlag = ""
    if ($guest.externalUserState -eq "PendingAcceptance" -and $guest.createdDateTime) {
        $pendingDays = [int]((Get-Date) - [datetime]$guest.createdDateTime).TotalDays
        if ($pendingDays -ge 30) {
            $inviteFlag = "INVITE PENDING $pendingDays DAYS"
        }
    }

    # GET group memberships
    $groupNames = "None"
    try {
        $groupsResp = Invoke-RestMethod `
            -Uri "https://graph.microsoft.com/v1.0/users/$($guest.id)/memberOf" `
            -Headers $headers -ErrorAction Stop
        $names = $groupsResp.value | Where-Object { $_.displayName } |
                 ForEach-Object { $_.displayName }
        if ($names) { $groupNames = $names -join "; " }
    } catch {}

    # GET app role assignments
    $appNames = "None"
    try {
        $appsResp = Invoke-RestMethod `
            -Uri "https://graph.microsoft.com/v1.0/users/$($guest.id)/appRoleAssignments" `
            -Headers $headers -ErrorAction Stop
        $apps = $appsResp.value | Where-Object { $_.resourceDisplayName } |
                ForEach-Object { $_.resourceDisplayName }
        if ($apps) { $appNames = $apps -join "; " }
    } catch {}

    $results += [PSCustomObject]@{
        DisplayName      = $guest.displayName
        UPN              = $guest.userPrincipalName
        AccountEnabled   = $guest.accountEnabled
        ExternalState    = $guest.externalUserState
        CreatedDate      = $createdStr
        LastSignIn       = $lastSignInStr
        DaysSinceSignIn  = $daysSinceSignIn
        LicenseCount     = $guest.assignedLicenses.Count
        GroupMemberships = $groupNames
        AppAccess        = $appNames
        Flag             = $inviteFlag
    }
}

$pending = $results | Where-Object { $_.Flag -ne "" }
Write-Host ""
Write-Host "Total guests processed: $($results.Count)" -ForegroundColor Yellow
if ($pending.Count -gt 0) {
    Write-Host "Guests with stale pending invites: $($pending.Count)" -ForegroundColor Red
}

$results | Sort-Object ExternalState, LastSignIn | Format-Table -AutoSize
$results | Export-Csv -Path "/home/jay/IAM-Audit/GuestAccounts_Audit.csv" -NoTypeInformation
Write-Host "Done. Exported: /home/jay/IAM-Audit/GuestAccounts_Audit.csv" -ForegroundColor Green
