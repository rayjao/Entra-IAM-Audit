# ============================================================
# NHI SCRIPT 3 — App Secrets & Credential Expiry Audit
# READ ONLY — no changes made to tenant
# Requires: Microsoft Graph REST API via Azure Cloud Shell
# Scopes:   Application.Read.All
# Output:   IAM-Audit/NHI_AppSecrets.csv
# ============================================================

New-Item -ItemType Directory -Path "/home/jay/IAM-Audit" -Force | Out-Null

# Get token from existing Azure Cloud Shell session
$tokenObj = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
$token    = [System.Net.NetworkCredential]::new("", $tokenObj.Token).Password
$headers  = @{ Authorization = "Bearer $token" }

$today   = Get-Date
$results = @()

# GET all app registrations with credential details
$allApps = @()
$uri = "https://graph.microsoft.com/v1.0/applications?`$select=id,displayName,appId,createdDateTime,passwordCredentials,keyCredentials&`$top=999"

do {
    $response = Invoke-RestMethod -Uri $uri -Headers $headers
    $allApps += $response.value
    $uri      = $response.'@odata.nextLink'
} while ($uri)

Write-Host "Auditing secrets for $($allApps.Count) app registrations..." -ForegroundColor Cyan

foreach ($app in $allApps) {

    # Process client secrets (password credentials)
    if ($app.passwordCredentials -and $app.passwordCredentials.Count -gt 0) {
        foreach ($secret in $app.passwordCredentials) {

            if ($secret.endDateTime) {
                $daysUntilExpiry = [int]($secret.endDateTime - $today).TotalDays
                $status = if ($daysUntilExpiry -lt 0)  { "EXPIRED" }
                          elseif ($daysUntilExpiry -lt 30) { "CRITICAL - Expires within 30 days" }
                          elseif ($daysUntilExpiry -lt 90) { "WARNING - Expires within 90 days" }
                          else { "OK" }
            } else {
                $daysUntilExpiry = "No expiry"
                $status = "REVIEW - No expiry date set"
            }

            $results += [PSCustomObject]@{
                AppName         = $app.displayName
                AppId           = $app.appId
                CredentialType  = "Client Secret"
                SecretName      = if ($secret.displayName) { $secret.displayName } else { "Unnamed" }
                ExpiryDate      = if ($secret.endDateTime) { ([datetime]$secret.endDateTime).ToString("yyyy-MM-dd") } else { "None" }
                DaysUntilExpiry = $daysUntilExpiry
                Status          = $status
            }
        }
    }

    # Process certificates (key credentials)
    if ($app.keyCredentials -and $app.keyCredentials.Count -gt 0) {
        foreach ($cert in $app.keyCredentials) {

            if ($cert.endDateTime) {
                $daysUntilExpiry = [int]($cert.endDateTime - $today).TotalDays
                $status = if ($daysUntilExpiry -lt 0)  { "EXPIRED" }
                          elseif ($daysUntilExpiry -lt 30) { "CRITICAL - Expires within 30 days" }
                          elseif ($daysUntilExpiry -lt 90) { "WARNING - Expires within 90 days" }
                          else { "OK" }
            } else {
                $daysUntilExpiry = "No expiry"
                $status = "REVIEW - No expiry date set"
            }

            $results += [PSCustomObject]@{
                AppName         = $app.displayName
                AppId           = $app.appId
                CredentialType  = "Certificate"
                SecretName      = if ($cert.displayName) { $cert.displayName } else { "Unnamed cert" }
                ExpiryDate      = if ($cert.endDateTime) { ([datetime]$cert.endDateTime).ToString("yyyy-MM-dd") } else { "None" }
                DaysUntilExpiry = $daysUntilExpiry
                Status          = $status
            }
        }
    }

    # Flag apps with no credentials at all
    if (($app.passwordCredentials.Count -eq 0) -and ($app.keyCredentials.Count -eq 0)) {
        $results += [PSCustomObject]@{
            AppName         = $app.displayName
            AppId           = $app.appId
            CredentialType  = "None"
            SecretName      = "No credentials registered"
            ExpiryDate      = "N/A"
            DaysUntilExpiry = "N/A"
            Status          = "REVIEW - No credentials found"
        }
    }
}

$expired  = $results | Where-Object { $_.Status -eq "EXPIRED" }
$critical = $results | Where-Object { $_.Status -match "CRITICAL" }
$warning  = $results | Where-Object { $_.Status -match "WARNING" }

Write-Host ""
Write-Host "EXPIRED secrets:          $($expired.Count)"  -ForegroundColor Red
Write-Host "CRITICAL (< 30 days):     $($critical.Count)" -ForegroundColor Red
Write-Host "WARNING  (< 90 days):     $($warning.Count)"  -ForegroundColor Yellow
Write-Host "Total credential entries: $($results.Count)"

$results | Sort-Object {
    switch -Wildcard ($_.Status) {
        "EXPIRED"   { 0 }
        "CRITICAL*" { 1 }
        "WARNING*"  { 2 }
        "REVIEW*"   { 3 }
        default     { 4 }
    }
} | Format-Table -AutoSize

$results | Export-Csv -Path "/home/jay/IAM-Audit/NHI_AppSecrets.csv" -NoTypeInformation
Write-Host "Done. Exported: /home/jay/IAM-Audit/NHI_AppSecrets.csv" -ForegroundColor Green
