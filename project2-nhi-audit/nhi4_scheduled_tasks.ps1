# ============================================================
# NHI SCRIPT 4 — Scheduled Tasks Running Under Named Accounts
# READ ONLY — no changes made to system
# Requires: PowerShell 7 on a domain-joined machine
# Run from: Domain-joined machine — NOT Azure Cloud Shell
# Output:   C:\IAM-Audit\NHI_ScheduledTasks.csv
# ============================================================

New-Item -ItemType Directory -Path "C:\IAM-Audit" -Force | Out-Null

# Get all scheduled tasks on the local machine
$tasks   = Get-ScheduledTask
$results = @()

foreach ($task in $tasks) {
    $principal = $task.Principal

    # Skip built-in Windows service accounts — not a governance risk
    $builtIn = @(
        "SYSTEM",
        "NT AUTHORITY\SYSTEM",
        "LOCAL SERVICE",
        "NT AUTHORITY\LOCAL SERVICE",
        "NETWORK SERVICE",
        "NT AUTHORITY\NETWORK SERVICE",
        "LOCALSERVICE",
        "NETWORKSERVICE",
        "Users",
        "Administrators"
    )

    $runAs = $principal.UserId
    if (-not $runAs)                    { continue }
    if ($builtIn -contains $runAs)      { continue }
    if ($runAs -match "^S-1-5-18|^S-1-5-19|^S-1-5-20") { continue }

    # Get last run info
    $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName `
        -TaskPath $task.TaskPath -ErrorAction SilentlyContinue

    # Risk scoring — real user accounts running tasks is the highest risk
    $risk = if ($runAs -match "@|\\") {
        if ($runAs -match "admin|svc|service") {
            "HIGH - Service account running scheduled task"
        } else {
            "CRITICAL - Named user account running scheduled task"
        }
    } else {
        "MEDIUM - Review account type"
    }

    $results += [PSCustomObject]@{
        TaskName     = $task.TaskName
        TaskPath     = $task.TaskPath
        RunAsAccount = $runAs
        LogonType    = $principal.LogonType
        State        = $task.State
        LastRunTime  = if ($taskInfo.LastRunTime) {
            $taskInfo.LastRunTime.ToString("yyyy-MM-dd HH:mm")
        } else { "Never" }
        LastResult   = if ($taskInfo.LastTaskResult) { $taskInfo.LastTaskResult } else { "N/A" }
        Risk         = $risk
    }
}

$critical = $results | Where-Object { $_.Risk -match "CRITICAL" }
$high     = $results | Where-Object { $_.Risk -match "HIGH" }

Write-Host ""
Write-Host "Tasks running under named accounts: $($results.Count)" -ForegroundColor Cyan
Write-Host "CRITICAL (named user accounts): $($critical.Count)" -ForegroundColor Red
Write-Host "HIGH (service accounts):        $($high.Count)" -ForegroundColor Yellow

$results | Sort-Object Risk | Format-Table -AutoSize
$results | Sort-Object Risk |
    Export-Csv -Path "C:\IAM-Audit\NHI_ScheduledTasks.csv" -NoTypeInformation
Write-Host "Done. Exported: C:\IAM-Audit\NHI_ScheduledTasks.csv" -ForegroundColor Green
