# ============================================================
# SCRIPT 5 — App Registration & Service Principal Audit
# READ ONLY — no changes made to tenant
# Requires: Microsoft Graph REST API via Azure Cloud Shell
# Scopes:   Application.Read.All, Directory.Read.All
# Output:   IAM-Audit/AppRegistrations_Audit.csv
# ============================================================

New-Item -ItemType Directory -Path "/home/jay/IAM-Audit" -Force | Out-Null

# Get token from existing Azure Cloud Shell session
$tokenObj = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
$token    = [System.Net.NetworkCredential]::new("", $tokenObj.Token).Password
$headers  = @{ Authorization = "Bearer $token" }

$highRiskPerms = @(
    "Directory.ReadWrite.All",
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.ReadWrite.All",
    "User.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "Group.ReadWrite.All",
    "Sites.FullControl.All",
    "Exchange.ManageAsApp",
    "Calendars.ReadWrite",
    "MailboxSettings.ReadWrite"
)

# GET all app registrations with pagination
$allApps = @()
$uri = "https://graph.microsoft.com/v1.0/applications?`$select=id,displayName,appId,createdDateTime,requiredResourceAccess,signInAudience&`$top=999"

do {
    $response = Invoke-RestMethod -Uri $uri -Headers $headers
    $allApps += $response.value
    $uri      = $response.'@odata.nextLink'
} while ($uri)

Write-Host "Total app registrations found: $($allApps.Count)" -ForegroundColor Cyan

# Cache service principal lookups — avoids duplicate API calls
$spCache = @{}
$results = @()
$i       = 0

foreach ($app in $allApps) {
    $i++
    Write-Host "Processing $i of $($allApps.Count): $($app.displayName)" -ForegroundColor Cyan

    $flaggedPerms = @()

    foreach ($resource in $app.requiredResourceAccess) {
        $resourceAppId = $resource.resourceAppId

        # Cache SP lookup — only call API once per unique resource
        if (-not $spCache.ContainsKey($resourceAppId)) {
            try {
                $spResp = Invoke-RestMethod `
                    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$resourceAppId'&`$select=appId,appRoles,oauth2PermissionScopes" `
                    -Headers $headers -ErrorAction Stop
                $spCache[$resourceAppId] = $spResp.value | Select-Object -First 1
            } catch {
                $spCache[$resourceAppId] = $null
            }
        }
        $sp = $spCache[$resourceAppId]
        if (-not $sp) { continue }

        $allScopeDefinitions = @()
        if ($sp.appRoles)               { $allScopeDefinitions += $sp.appRoles }
        if ($sp.oauth2PermissionScopes) { $allScopeDefinitions += $sp.oauth2PermissionScopes }

        foreach ($scope in $resource.resourceAccess) {
            $permName = $allScopeDefinitions |
                Where-Object { $_.id -eq $scope.id } |
                Select-Object -ExpandProperty value -First 1

            if (-not $permName) { continue }

            if ($highRiskPerms -contains $permName) {
                $flaggedPerms += "$permName ($($scope.type))"
            }
        }
    }

    # GET app owners
    $ownerNames = "NO OWNER ASSIGNED"
    try {
        $ownersResp = Invoke-RestMethod `
            -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)/owners" `
            -Headers $headers -ErrorAction Stop
        $names = $ownersResp.value |
            Where-Object { $_.userPrincipalName } |
            ForEach-Object { $_.userPrincipalName }
        if ($names) { $ownerNames = $names -join "; " }
    } catch {}

    $createdStr = if ($app.createdDateTime) {
        ([datetime]$app.createdDateTime).ToString("yyyy-MM-dd")
    } else { "Unknown" }

    $results += [PSCustomObject]@{
        AppName        = $app.displayName
        AppId          = $app.appId
        CreatedDate    = $createdStr
        SignInAudience = $app.signInAudience
        Owners         = $ownerNames
        HighRiskPerms  = if ($flaggedPerms.Count -gt 0) { $flaggedPerms -join " | " } else { "None flagged" }
        RiskFlag       = if ($flaggedPerms.Count -gt 0) { "REVIEW" } `
                         elseif ($ownerNames -eq "NO OWNER ASSIGNED") { "NO OWNER" } `
                         else { "OK" }
    }
}

$flagged = $results | Where-Object { $_.RiskFlag -eq "REVIEW" }
$noOwner = $results | Where-Object { $_.Owners -eq "NO OWNER ASSIGNED" }

Write-Host ""
Write-Host "Total apps scanned:             $($results.Count)" -ForegroundColor Cyan
Write-Host "Apps flagged (high-risk perms): $($flagged.Count)" -ForegroundColor Red
Write-Host "Apps with no owner assigned:    $($noOwner.Count)" -ForegroundColor Yellow

$results | Sort-Object RiskFlag, AppName | Format-Table -AutoSize
$results | Export-Csv -Path "/home/jay/IAM-Audit/AppRegistrations_Audit.csv" -NoTypeInformation
Write-Host "Done. Exported: /home/jay/IAM-Audit/AppRegistrations_Audit.csv" -ForegroundColor Green
