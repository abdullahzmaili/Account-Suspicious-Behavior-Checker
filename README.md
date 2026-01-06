# Account Suspicious Behavior Checker

A PowerShell tool for analyzing Entra ID (Azure AD) sign-in and audit logs to detect indicators of account suspicious behavior. This script provides detailed risk assessment, suspicious activity detection, and generates professional HTML reports.

## Overview

The Account Suspicious Behavior Checker performs deep analysis of user activity across two main categories:
- **Sign-In Analysis**: Detects anomalous sign-in patterns, location hopping, brute-force attempts, and suspicious behaviors
- **Audit Log Analysis**: Monitors privileged operations, policy changes, bulk actions, and administrative activities

## Key Features

- **Comprehensive Risk Scoring**: Weighted scoring system across 25+ indicators
- **Dual Analysis**: Sign-in logs + Directory audit logs
- **Interactive HTML Reports**: Professional, filterable reports with detailed metrics
- **Multiple Operating Modes**: Analyze existing CSVs or connect directly to Entra ID
- **Working Hours Detection**: Identifies off-hours activity based on your schedule
- **Time-Range Filtering**: Filter logs by specific date ranges
- **Automated Detection**: 13 suspicious audit patterns + 12 sign-in indicators

## Requirements

- **PowerShell**: 5.1 or later
- **Module**: Microsoft.Graph PowerShell module (auto-installed if missing)
- **Permissions**: `AuditLog.Read.All` or `Directory.Read.All` (when connecting to Entra ID)
- **Administrator**: Required for module installation (if not already installed)

## Quick Start

### Option 1: Analyze Existing CSV Files
```powershell
.\AccountSuspiciousBehaviorChecker.ps1 -importCSVPath "C:\temp\logs" -Output "C:\reports" -Open -Start 9 -End 17
```

### Option 2: Connect to Entra ID and Export Logs
```powershell
.\AccountSuspiciousBehaviorChecker.ps1 -EntraIDConnect "admin@contoso.com" -AffectedUPN "user@contoso.com" -Output "C:\reports" -Open
```

### Option 3: Interactive Mode
```powershell
.\AccountSuspiciousBehaviorChecker.ps1
```
The script will guide you through mode selection and configuration.

## How Scores Are Calculated

### Overall Risk Score (0-100)
The overall risk score is calculated by combining two major components:

```
Overall Score = (Sign-In Score ร— 50%) + (Audit Score ร— 50%)
```

- **Sign-In Score (60% weight)**: Based on 12 sign-in indicators
- **Audit Score (40% weight)**: Based on 4 main audit indicators + 13 suspicious activities

### Risk Levels
- **CRITICAL** (75-100): Immediate action required
- **HIGH** (50-74): High priority investigation
- **MEDIUM** (25-49): Review recommended
- **LOW** (0-24): Normal activity

---

## Sign-In Indicators (12 Total)

Each sign-in indicator has an equal weight of **8.33%** (100 รท 12).

### 1. Multiple Locations
**What it detects**: User appearing in 2+ geographic locations within 24-hour windows (impossible travel).

**Scoring**:
- Score = min(100, Detections ร— 35)
- Each detection adds 35 points (capped at 100)

**Example**: 3 detections = 100 points (CRITICAL)

---

### 2. Failed/Interrupted Sign-ins
**What it detects**: Failed or interrupted authentication attempts.

**Scoring**:
- Score = (Failed Count รท Total Sign-ins) ร— 100
- Percentage-based risk assessment

**Example**: 50 failures out of 200 sign-ins = 25 points (MEDIUM)

---

### 3. Brute-force Attacks
**What it detects**: 5+ failed sign-ins (error code 50126) within 10-minute windows.

**Scoring**:
- Score = min(100, Windows ร— 40)
- Each brute-force window adds 40 points

**Example**: 2 brute-force windows detected = 80 points (CRITICAL)

---

### 4. Password-spray Attacks
**What it detects**: 10+ failed sign-ins (error code 50126) within 30-minute windows.

**Scoring**:
- Score = min(100, Windows ร— 40)
- Each password-spray window adds 40 points

**Example**: 1 password-spray window = 40 points (MEDIUM)

---

### 5. Account Lockout
**What it detects**: 3+ lockout failures (error code 50053) within 15-minute windows.

**Scoring**:
- Score = min(100, Windows ร— 50)
- Each lockout window adds 50 points

**Example**: 2 lockout windows = 100 points (CRITICAL)

---

### 6. Multiple IP Addresses
**What it detects**: User accessing from 3+ unique IP addresses within 24-hour windows.

**Scoring**:
- Score = min(100, (Unique IPs - 2) ร— 30)
- 2 IPs baseline, additional IPs add 30 points each

**Example**: 5 unique IPs = (5 - 2) ร— 30 = 90 points (CRITICAL)

---

### 7. Risky Sign-ins
**What it detects**: Sign-ins flagged by Entra ID Identity Protection as risky.

**Scoring**:
- Score = min(100, Count ร— 35)
- Each risky sign-in adds 35 points

**Example**: 3 risky sign-ins = 100 points (CRITICAL)

---

### 8. Suspicious User Agents
**What it detects**: Automated/scripted sign-ins (PowerShell, curl, python, etc.).

**Scoring**:
- Score = min(100, Count ร— 30)
- Each suspicious agent adds 30 points

**Example**: 2 suspicious agents = 60 points (HIGH)

---

### 9. Off-hours Activity
**What it detects**: Sign-ins outside configured working hours.

**Scoring**:
- Score = (Off-hours Count รท Total Sign-ins) ร— 100
- Percentage of activity outside working hours

**Example**: 40 off-hours / 200 total = 20 points (LOW)

---

### 10. Multiple Devices
**What it detects**: User accessing from 2+ different operating systems.

**Scoring**:
- Score = min(100, (OS Count - 1) ร— 30)
- Each additional OS adds 30 points

**Example**: 3 different OS = (3 - 1) ร— 30 = 60 points (HIGH)

---

### 11. Anonymous IP
**What it detects**: Sign-ins from Tor, VPN, or anonymous proxy services.

**Scoring**:
- Score = min(100, Count ร— 40)
- Each anonymous IP adds 40 points

**Example**: 2 anonymous IPs = 80 points (CRITICAL)

---

### 12. Session IP Mismatch
**What it detects**: Multiple IP addresses used within the same session ID.

**Scoring**:
- Score = min(100, Sessions ร— 40)
- Each mismatched session adds 40 points

**Example**: 1 session with IP mismatch = 40 points (MEDIUM)

---

## Audit Indicators

### Main Audit Indicators (4 Total)
Each main indicator has a weight of **25%** (100 รท 4).

#### 1. Off-Hours Password Change/Reset
**What it detects**: Password modifications outside working hours.

**Scoring**:
- Score = min(100, Count ร— 50)
- Each off-hours password change adds 50 points

**Weight in audit score**: 25%

---

#### 2. Privileged Role Changes
**What it detects**: Modifications to administrative roles and permissions.

**Scoring**:
- Score = min(100, Count ร— 40)
- Each role change adds 40 points

**Weight in audit score**: 25%

---

#### 3. Off-Hours Audit Activity
**What it detects**: Any audit activity outside working hours.

**Scoring**:
- Score = (Off-hours Count รท Total Activities) ร— 100
- Percentage of off-hours activity

**Weight in audit score**: 25%

---

#### 4. Failed Audit Events
**What it detects**: Failed administrative operations.

**Scoring**:
- Score = (Failed Count รท Total Activities) ร— 100
- Percentage of failed operations

**Weight in audit score**: 25%

---

### Suspicious Activities (13 Total)
Each suspicious activity has a weight of **7.69%** (100 รท 13).

| Activity | Risk Level | Detection | Scoring |
|----------|-----------|-----------|---------|
| **Update Application** | High | App registration modifications | 100 if detected |
| **Add Service Principal** | High | New service accounts created | 100 if detected |
| **Add App Role Assignment** | High | App permission grants | 100 if detected |
| **Disable Account** | High | User accounts disabled | 100 if detected |
| **Bulk Update User** | High | Mass user modifications | 100 if detected |
| **Add Owner to App/SP** | High | Ownership changes | 100 if detected |
| **Update Service Principal** | High | Service account modifications | 100 if detected |
| **Policy Changes** | Medium | Conditional access/security policies | min(100, Count ร— 30) |
| **Bulk Deletions** | Medium | Mass deletion operations | min(100, Count ร— 30) |
| **Consent to Application** | Medium | Application consent grants | min(100, Count ร— 30) |
| **Password Change** | Medium | User password changes | min(100, Count ร— 30) |
| **Password Reset** | Medium | Admin password resets | min(100, Count ร— 30) |
| **MFA Changes** | Medium | MFA configuration changes | min(100, Count ร— 30) |

**Scoring Logic**:
- **High risk** activities: 100 points if any occurrence detected
- **Medium risk** activities: 30 points per occurrence (capped at 100)

---

## Score Calculation Examples

### Example 1: High-Risk Scenario
```
Sign-In Indicators:
- Multiple Locations: 3 detections = 100 points ร— 8.33% = 8.33
- Brute-force: 2 windows = 80 points ร— 8.33% = 6.66
- Risky Sign-ins: 3 detections = 100 points ร— 8.33% = 8.33
- Other 9 indicators: 0 points

Sign-In Score = 8.33 + 6.66 + 8.33 = 23.32

Audit Indicators:
- Off-Hours Password: 2 changes = 100 ร— 25% = 25
- Privileged Role Changes: 3 changes = 100 ร— 25% = 25
- Off-Hours Activity: 30% = 30 ร— 25% = 7.5
- Failed Events: 5% = 5 ร— 25% = 1.25

Suspicious Activities:
- Update Application: Detected = 100 ร— 7.69% = 7.69
- Disable Account: Detected = 100 ร— 7.69% = 7.69
- Other 11 activities: 0 points

Audit Score = 25 + 25 + 7.5 + 1.25 + 7.69 + 7.69 = 74.13

Overall Score = (23.32 ร— 60%) + (74.13 ร— 40%)
              = 13.99 + 29.65
              = 43.64 (MEDIUM)
```

### Example 2: Critical Scenario
```
Sign-In Score: 85 points
Audit Score: 90 points

Overall Score = (85 ร— 60%) + (90 ร— 40%)
              = 51 + 36
              = 87 (CRITICAL)
```

---

## Metrics Tracked

### Sign-In Metrics
- Total sign-ins, successful, failed, interrupted
- Unique countries, IP addresses, applications
- Session IDs, client apps, resources
- Operating systems, off-hours activity

### Audit Metrics
- Total audit activities, categories, services
- Password changes, role modifications
- User management, MFA changes
- Group changes, policy updates
- Application activities, deletion operations

---

## Report Features

### Executive Summary
- Overall risk score with color-coded indicator
- Sign-in and audit score breakdown
- Quick statistics dashboard

### Sign-In Analysis
- 12 indicator cards with individual scores
- Failed sign-ins table
- Interactive modals for detailed data
- Geographic and IP analysis

### Audit Analysis
- 4 main indicators + 13 suspicious activities
- Activity categorization
- Off-hours detection
- Success/failure tracking

### Interactive Features
- Click indicators to view detailed data
- Sortable/filterable tables
- Export data to CSV from report
- Responsive design for all devices

---

## Parameters Reference

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `-importCSVPath` | String | Path to CSV file or folder | `C:\temp\logs` |
| `-Output` | String | Output folder for reports | `C:\reports` |
| `-Open` | Switch | Auto-open HTML report | `-Open` |
| `-EntraIDConnect` | String | UPN for Graph connection | `admin@contoso.com` |
| `-AffectedUPN` | String | Target user to analyze | `user@contoso.com` |
| `-Start` | String/Int | Start time/hour | `9` or `2025-01-01` |
| `-End` | String/Int | End time/hour | `17` or `2025-12-31` |

### Start/End Parameter Formats

**Working Hours Mode** (both 0-23):
```powershell
-Start 9 -End 17  # 9 AM to 5 PM working hours
```

**Date Range Mode**:
```powershell
-Start "2025-01-01" -End "2025-12-31"  # Calendar year 2025
```

**Unix Epoch**:
```powershell
-Start 1704067200 -End 1735689599  # Epoch timestamps
```

---

## Examples

### Example 1: Quick Analysis with Existing CSV
```powershell
.\AccountSuspiciousBehaviorChecker.ps1 -importCSVPath "C:\Logs" -Output "C:\Reports" -Start 8 -End 18 -Open
```
**Result**: Analyzes all CSVs in C:\Logs, uses 8 AM - 6 PM as working hours, generates report, opens automatically.

### Example 2: Connect and Export from Entra ID
```powershell
.\AccountSuspiciousBehaviorChecker.ps1 -EntraIDConnect "admin@contoso.com" -AffectedUPN "john.doe@contoso.com" -Output "C:\Reports"
```
**Result**: Connects to Entra ID, exports logs for john.doe@contoso.com, analyzes, generates report.

### Example 3: Date-Filtered Analysis
```powershell
.\AccountSuspiciousBehaviorChecker.ps1 -importCSVPath "C:\Logs" -Start "2025-01-01" -End "2025-01-31" -Output "C:\Reports"
```
**Result**: Analyzes only January 2025 data from existing CSVs.

### Example 4: Interactive Mode
```powershell
.\AccountSuspiciousBehaviorChecker.ps1
```
**Result**: Launches interactive menu, guides through configuration options.

---

## Troubleshooting

### Module Installation Issues
If the Microsoft.Graph module fails to install:
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

### Permission Errors
Ensure your account has one of these permissions:
- `AuditLog.Read.All`
- `Directory.Read.All`

### CSV Format Issues
Ensure CSV files contain these columns:
- **Sign-in logs**: Date (UTC), User, Status, IP address, Location, Application
- **Audit logs**: Timestamp, Activity, Result, Initiator User UPN

---

## Output Files

### Generated Files
1. **SignIn_Logs_[timestamp].csv**: Raw sign-in data
2. **Audit_Logs_[timestamp].csv**: Raw audit data
3. **Account_Suspicious_Behavior_Report_[timestamp].html**: Interactive report

### Report Sections
- Executive Summary
- Sign-In Indicators (12)
- Audit Indicators (4)
- Suspicious Activities (13)
- Sign-In Activity Metrics
- Failed Activities
- Off-Hours Activity

---

## Security Notes

- Script requires read-only permissions
- No data is sent externally
- All processing is local
- Credentials are handled by Microsoft.Graph module
- Generated reports contain sensitive data - protect accordingly

---

## Author

**Abdullah Zmaili**
- Version: 1.0
- Date: January 2026

---

## Disclaimer

This script has been thoroughly tested across various environments. However:
1. You are responsible for how you use the script
2. The entire risk arising from use remains with you
3. Author not liable for any damages or losses
4. Always test in non-production environment first

---

## Additional Documentation

- See [QUICKSTART.md](QUICKSTART.md) for rapid deployment guide
- See [INSTRUCTIONS.md](INSTRUCTIONS.md) for detailed step-by-step instructions
- See script comments for code-level documentation

---

## Support

For issues or questions:
1. Review documentation thoroughly
2. Check PowerShell version (must be 5.1+)
3. Verify module installation
4. Confirm permissions in Entra ID

---

**Last Updated**: January 4, 2026



