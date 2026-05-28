# ============================================================
# SCRIPT 1 — Privileged Role Assignments
# READ ONLY — no changes made to tenant
# Requires: Microsoft Graph REST API via Azure Cloud Shell
# Scopes:   RoleManagement.Read.Directory, User.Read.All, Group.Read.All
# Output:   IAM-Audit/PrivilegedRoles_Audit.csv
# ============================================================

New-Item -ItemType Directory -Path "/home/jay/IAM-Audit" -Force | Out-Null

# Get token from existing Azure Cloud Shell session
$tokenObj = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
$token    = [System.Net.NetworkCredential]::new("", $tokenObj.Token).Password
$headers  = @{ Authorization = "Bearer $token" }

$targetRoles = @(
    "Global Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Privileged Role Administrator",
    "User Administrator",
    "Compliance Administrator",
    "Authentication Administrator",
    "Helpdesk Administrator",
    "Application Administrator"
)

# GET all activated roles — local filter is more reliable than server-side filter
$allRoles = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryRoles" -Headers $headers).value
$results  = @()

foreach ($roleName in $targetRoles) {
    $role = $allRoles | Where-Object { $_.displayName -eq $roleName }
    if (-not $role) { continue }

    # GET members of this role
    $members = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members" -Headers $headers).value

    foreach ($member in $members) {
        $odataType = $member.'@odata.type'

        if ($odataType -eq "#microsoft.graph.user") {
            $results += [PSCustomObject]@{
                Role           = $roleName
                DisplayName    = $member.displayName
                UPN            = $member.userPrincipalName
                AccountEnabled = $member.accountEnabled
                UserType       = $member.userType
                MemberType     = "DirectUser"
            }

        } elseif ($odataType -eq "#microsoft.graph.group") {
            # Expand group members — users assigned via group are invisible without this
            $groupMembers = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups/$($member.id)/members" -Headers $headers).value
            foreach ($gm in $groupMembers) {
                if (-not $gm.userPrincipalName) { continue }
                $results += [PSCustomObject]@{
                    Role           = $roleName
                    DisplayName    = $gm.displayName
                    UPN            = $gm.userPrincipalName
                    AccountEnabled = $gm.accountEnabled
                    UserType       = $gm.userType
                    MemberType     = "ViaGroup:$($member.displayName)"
                }
            }

        } else {
            # Service principal or other non-user object — log it, never skip silently
            $results += [PSCustomObject]@{
                Role           = $roleName
                DisplayName    = $member.displayName
                UPN            = "N/A - Non-user object"
                AccountEnabled = "N/A"
                UserType       = $member.'@odata.type'
                MemberType     = "ServicePrincipal/Other"
            }
        }
    }
}

$results | Sort-Object Role, DisplayName | Format-Table -AutoSize
$results | Export-Csv -Path "/home/jay/IAM-Audit/PrivilegedRoles_Audit.csv" -NoTypeInformation
Write-Host "Done. Exported: /home/jay/IAM-Audit/PrivilegedRoles_Audit.csv" -ForegroundColor Green
