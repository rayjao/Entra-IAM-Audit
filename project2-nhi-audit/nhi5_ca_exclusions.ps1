# ============================================================
# NHI SCRIPT 5 — Conditional Access Policy User Exclusions
# READ ONLY — no changes made to tenant
# Requires: PowerShell 7 local — NOT compatible with Cloud Shell
# Scopes:   Policy.Read.All, User.Read.All
# Note:     Policy.Read.All not available in Cloud Shell token
#           Run from local PS7 with:
#           Connect-MgGraph -Scopes "Policy.Read.All","User.Read.All"
# Output:   C:\IAM-Audit\NHI_CA_Exclusions.csv
# ============================================================

New-Item -ItemType Directory -Path "C:\IAM-Audit" -Force | Out-Null

# Get token from existing Azure Cloud Shell session
$tokenObj = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
$token    = [System.Net.NetworkCredential]::new("", $tokenObj.Token).Password
$headers  = @{ Authorization = "Bearer $token" }

$results = @()

# GET all Conditional Access policies
$policies = (Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
    -Headers $headers).value

Write-Host "Found $($policies.Count) Conditional Access policies" -ForegroundColor Cyan

foreach ($policy in $policies) {

    $excludedUserIds  = $policy.conditions.users.excludeUsers
    $excludedGroupIds = $policy.conditions.users.excludeGroups

    # Process individually excluded users
    foreach ($userId in $excludedUserIds) {
        $user = $null
        try {
            $user = Invoke-RestMethod `
                -Uri "https://graph.microsoft.com/v1.0/users/$userId`?`$select=displayName,userPrincipalName,userType,accountEnabled" `
                -Headers $headers -ErrorAction Stop
        } catch { continue }

        $risk = if ($policy.state -eq "enabled") {
            if ($user.userType -eq "Guest") {
                "HIGH - Guest excluded from active policy"
            } elseif ($user.userPrincipalName -match "service|svc|admin") {
                "HIGH - Service or admin account excluded from active policy"
            } else {
                "MEDIUM - User excluded from active policy"
            }
        } else {
            "LOW - Policy is disabled or report-only"
        }

        $results += [PSCustomObject]@{
            PolicyName     = $policy.displayName
            PolicyState    = $policy.state
            ExclusionType  = "Direct User"
            ExcludedName   = $user.displayName
            UPN            = $user.userPrincipalName
            UserType       = $user.userType
            AccountEnabled = $user.accountEnabled
            Risk           = $risk
        }
    }

    # Process excluded groups
    foreach ($groupId in $excludedGroupIds) {
        $group = $null
        try {
            $group = Invoke-RestMethod `
                -Uri "https://graph.microsoft.com/v1.0/groups/$groupId`?`$select=displayName" `
                -Headers $headers -ErrorAction Stop
        } catch { continue }

        $results += [PSCustomObject]@{
            PolicyName     = $policy.displayName
            PolicyState    = $policy.state
            ExclusionType  = "Group: $($group.displayName)"
            ExcludedName   = $group.displayName
            UPN            = "N/A - Group exclusion"
            UserType       = "Group"
            AccountEnabled = "N/A"
            Risk           = if ($policy.state -eq "enabled") {
                "MEDIUM - Group excluded from active policy"
            } else { "LOW - Policy disabled or report-only" }
        }
    }
}

$high = $results | Where-Object { $_.Risk -match "HIGH" }
$med  = $results | Where-Object { $_.Risk -match "MEDIUM" }

Write-Host ""
Write-Host "Total CA exclusions found: $($results.Count)" -ForegroundColor Cyan
Write-Host "HIGH risk exclusions:      $($high.Count)" -ForegroundColor Red
Write-Host "MEDIUM risk exclusions:    $($med.Count)" -ForegroundColor Yellow

$results | Sort-Object PolicyState, Risk | Format-Table -AutoSize
$results | Sort-Object PolicyState, Risk |
    Export-Csv -Path "C:\IAM-Audit\NHI_CA_Exclusions.csv" -NoTypeInformation
Write-Host "Done. Exported: C:\IAM-Audit\NHI_CA_Exclusions.csv" -ForegroundColor Green
