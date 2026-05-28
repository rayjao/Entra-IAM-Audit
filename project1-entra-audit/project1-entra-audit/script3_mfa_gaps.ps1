# ============================================================
# SCRIPT 3 — MFA Gaps (No MFA Method Registered)
# READ ONLY — no changes made to tenant
# Requires: PowerShell 7 local — NOT compatible with Cloud Shell
# Scopes:   UserAuthenticationMethod.Read.All, User.Read.All
# Note:     UserAuthenticationMethod.Read.All not available in
#           Cloud Shell delegated token — run from local PS7
#           with: Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All","User.Read.All"
# Output:   C:\IAM-Audit\MFAGaps_Audit.csv
# ============================================================

New-Item -ItemType Directory -Path "C:\IAM-Audit" -Force | Out-Null

# Get token from existing Azure Cloud Shell session
$tokenObj = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
$token    = [System.Net.NetworkCredential]::new("", $tokenObj.Token).Password
$headers  = @{ Authorization = "Bearer $token" }

$methodLabels = @{
    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"  = "Authenticator App"
    "#microsoft.graph.phoneAuthenticationMethod"                   = "Phone/SMS"
    "#microsoft.graph.fido2AuthenticationMethod"                   = "FIDO2 Key"
    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" = "Windows Hello"
    "#microsoft.graph.emailAuthenticationMethod"                   = "Email OTP"
    "#microsoft.graph.softwareOathAuthenticationMethod"            = "OATH TOTP App"
    "#microsoft.graph.temporaryAccessPassAuthenticationMethod"     = "Temp Access Pass"
    "#microsoft.graph.passwordAuthenticationMethod"                = "Password Only"
}

# GET all active member users with pagination
$allUsers = @()
$uri = "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,userPrincipalName,accountEnabled,userType&`$top=999"
do {
    $response  = Invoke-RestMethod -Uri $uri -Headers $headers
    $allUsers += $response.value
    $uri       = $response.'@odata.nextLink'
} while ($uri)

# Filter to active members only before making per-user calls
$members = $allUsers | Where-Object {
    $_.accountEnabled -eq $true -and $_.userType -eq "Member"
}

$total   = $members.Count
$i       = 0
$results = @()

Write-Host "Found $total active member accounts to check..." -ForegroundColor Cyan
Write-Host "Estimated time: $([math]::Round($total * 0.5 / 60, 1)) minutes" -ForegroundColor Cyan

foreach ($user in $members) {
    $i++
    if ($i % 20 -eq 0) {
        Write-Host "Progress: $i of $total ($([math]::Round($i/$to
