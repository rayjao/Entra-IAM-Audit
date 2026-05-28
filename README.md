# Entra ID — IAM & Non-Human Identity Security Audit

> Read-only identity security audit of a real Microsoft 365 / Entra ID environment  
> built using PowerShell 7 and the Microsoft Graph REST API via Azure Cloud Shell.  
> **No changes were made to the tenant. All scripts use HTTP GET operations only.**

---

## Overview

This project documents a real-world identity security audit executed against a live 1,143-user hybrid Active Directory and Microsoft Entra ID environment across three physical sites. The goal was to establish the organization's first formal identity security baseline and surface active attack surface across both human and non-human identities.

The audit identified **6 critical and 8 high severity findings** — including a vendor tool with accumulated permissions sufficient to silently take over the entire tenant, 42 stale licensed accounts, 3 expired app secrets including a broken ransomware protection tool, and 13 of 24 app registrations with no owner assigned.

All findings were delivered as an 8-page executive report mapped to NIST SP 800-53, CIS Controls v8, and ISO/IEC 27001, with a 16-item prioritized remediation roadmap.

---

## What Makes This Different

- **Real environment** — executed against a live production tenant, not a lab
- **Token-based auth** — bypasses the Microsoft Graph Command Line Tools consent requirement by using a delegated Azure Cloud Shell session token directly against the REST API
- **Cross-script correlation** — findings appearing in multiple scripts are flagged and escalated (e.g. an account that is stale, holds an admin role, AND is an external guest simultaneously)
- **Framework-mapped** — every finding is tied to a specific NIST, CIS, or ISO control reference so findings translate directly to compliance and GRC conversations

---

## Audit Scope

### Project 1 — Entra ID Identity Audit

| Script | Category | What It Finds |
|---|---|---|
| `script1_privileged_roles.ps1` | Privileged Role Assignments | Over-privileged users, non-human accounts in admin roles, group-based role assignments that hide privileged users from standard queries |
| `script2_stale_accounts.ps1` | Stale Accounts | Active licensed accounts inactive 90+ days, accounts that have never signed in, cross-referenced against privileged role holders |
| `script3_mfa_gaps.ps1` | MFA Gaps | Active licensed users with no MFA method registered — includes method enumeration (Authenticator App, Phone/SMS, FIDO2, Windows Hello) |
| `script4_guest_accounts.ps1` | Guest Account Exposure | Stale guests, uncollected invitations 30+ days old, external users holding admin roles, group memberships and app access per guest |
| `script5_app_registrations.ps1` | App Registrations | High-risk API permissions (Directory.ReadWrite.All, Mail.ReadWrite, etc.), apps with no owner, SignInAudience scope review |

### Project 2 — Non-Human Identity (NHI) Audit

| Script | Category | What It Finds |
|---|---|---|
| `nhi1_ad_service_accounts.ps1` | AD Service Accounts | On-prem accounts with never-expiring passwords, high group membership count, no documented owner — risk scored by password age and blast radius |
| `nhi2_shared_mailboxes.ps1` | Shared Mailboxes | Shared mailboxes with interactive sign-in enabled in Entra ID — these accounts have no MFA and are rarely monitored |
| `nhi3_app_secrets.ps1` | App Secrets & Credentials | Expired secrets, secrets expiring within 30/90 days, secrets with no expiry date (no rotation policy) — covers both client secrets and certificates |
| `nhi4_scheduled_tasks.ps1` | Scheduled Tasks | Tasks running under named user accounts or service accounts instead of managed service accounts — identifies human accounts used as automation identities |
| `nhi5_ca_exclusions.ps1` | CA Policy Exclusions | Users and groups manually excluded from Conditional Access policies — identities that bypass MFA and other security controls entirely |

---

## Real Findings Summary

Executed against a live 1,143-user tenant. Anonymized summary:

| Finding | Severity | Scripts |
|---|---|---|
| Vendor tool holds Privileged Role Admin + Directory.ReadWrite.All + Mail.ReadWrite — full tenant write access, no MFA, no owner | CRITICAL | 1, 5, NHI-3 |
| 7 Global Administrators including 2 non-human accounts — one never signed in, both licensed | CRITICAL | 1, 2 |
| Account inactive 1,128 days still holding 3 licenses and active admin roles | CRITICAL | 1, 2 |
| 3 expired app secrets — including ransomware protection tool offline for 4+ months | CRITICAL | NHI-3 |
| External guest holding SharePoint Administrator role, inactive 144 days | HIGH | 1, 2, 4 |
| 13 of 24 app registrations with no owner assigned | HIGH | 5 |
| 421-day uncollected guest invitation — open access token | HIGH | 4 |
| 42 stale accounts total — 12 never signed in, all licensed | HIGH | 2 |

---

## Technical Approach

**Authentication**
```powershell
# Run from Azure Cloud Shell at portal.azure.com
# No consent screens, no local module installs, no Graph Command Line Tools app required
$tokenObj = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
$token    = [System.Net.NetworkCredential]::new("", $tokenObj.Token).Password
$headers  = @{ Authorization = "Bearer $token" }
```

**API Design**
- Microsoft Graph REST API v1.0 — all calls HTTP GET only
- `$select` on every user query — pulls only required fields, reduces payload
- `$top=999` — maximizes page size to minimize API round trips
- `@odata.nextLink` pagination on all list endpoints

**Reliability**
- Retry loop with 10-second backoff on HTTP 429 (rate limiting) — critical for per-user auth method calls
- Checkpoint saves every 50 users on long-running scripts
- Null checks on all nullable Graph properties: `SignInActivity`, `CreatedDateTime`, `PasswordCredentials.EndDateTime`

**Output**
- One structured CSV per script
- Risk-scored and flagged columns in every output
- Cross-script findings identified manually from CSV correlation

---

## Risk Scoring

| Level | Criteria 
|---|---|
| CRITICAL | Immediate exploitation path, no compensating controls 
| HIGH | Significant attack surface, prompt remediation required 
| MEDIUM | Governance gap, schedule for remediation 
| LOW | Best practice deviation, low immediate risk 

---

## Framework Alignment

| Framework | Controls Applied |
|---|---|
| NIST SP 800-53 Rev 5 | AC-2 (Account Mgmt), AC-6 (Least Privilege), IA-2 (MFA), IA-5(1) (Credential Rotation), CM-7 (Least Functionality), PS-4 (Personnel Termination) |
| CIS Controls v8 | 5.3 (Disable Dormant Accounts), 5.4 (Restrict Admin Privileges), 6.2 (Access Revoking), 3.11 (Credential Protection) |
| ISO/IEC 27001:2022 | A.9.2.3 (Privileged Access), A.9.2.6 (Access Rights Removal), A.9.4.3 (Password Management) |

---

## Prerequisites

| Requirement | Details |
|---|---|
| PowerShell version | PS7+ required — PS 5.1 exceeds the 4096-function limit when loading Microsoft.Graph |
| Execution environment | Azure Cloud Shell at portal.azure.com (recommended for scripts 1, 2, 4, 5, NHI-2, NHI-3) |
| Entra ID role | Security Reader or Global Reader minimum |
| AD scripts (NHI-1, NHI-4) | Domain-joined machine with RSAT tools — requires ActiveDirectory PS module |
| MFA script (Script 3) | Local PS7 — `UserAuthenticationMethod.Read.All` not available in Cloud Shell token |
| CA Exclusions (NHI-5) | Local PS7 — `Policy.Read.All` not available in Cloud Shell token |

---

## Repository Structure
