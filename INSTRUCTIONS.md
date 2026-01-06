# Detailed Instructions - Account Suspicious Behavior Checker

Complete step-by-step guide for using the Account Suspicious Behavior Checker tool.

---

## ๐�“� Table of Contents

1. [Installation and Setup](#installation-and-setup)
2. [Operating Modes](#operating-modes)
3. [Parameter Reference](#parameter-reference)
4. [Score Calculation Deep Dive](#score-calculation-deep-dive)
5. [Indicator Explanations](#indicator-explanations)
6. [Report Navigation](#report-navigation)
7. [Advanced Usage](#advanced-usage)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)

---

## Installation and Setup

### Step 1: Verify PowerShell Version

Open PowerShell and run:
```powershell
$PSVersionTable.PSVersion
```

**Required**: Version 5.1 or later

**If older**:
- Windows 10/11: Update Windows
- Windows Server: Install WMF 5.1
- Or install PowerShell 7+

---

### Step 2: Install Microsoft.Graph Module

The script will auto-install if missing, or manually install:

```powershell
# Install for current user (no admin required)
Install-Module Microsoft.Graph -Scope CurrentUser -Force

# Verify installation
Get-Module Microsoft.Graph -ListAvailable
```

**Expected output**:
```
Version    Name
-------    ----
2.x.x      Microsoft.Graph
```

---

### Step 3: Download the Script

Save `AccountSuspiciousBehaviorChecker.ps1` to a local folder, for example:
```
C:\Scripts\AccountSuspiciousBehaviorChecker\
```

---

### Step 4: Set Execution Policy (if needed)

If you get "script cannot be loaded" error:

```powershell
# Check current policy
Get-ExecutionPolicy

# If Restricted, set to RemoteSigned
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## Operating Modes

The script supports three primary operating modes:

### Mode 1: Analyze Existing CSV Files

**When to use**: You already have exported CSV files from Entra ID portal or previous exports.

**Command**:
```powershell
.\AccountSuspiciousBehaviorChecker.ps1 -importCSVPath "C:\Logs" -Output "C:\Reports" -Start 9 -End 17 -Open
```

**What it does**:
1. Scans the folder `C:\Logs` for CSV files
2. Looks for files matching patterns:
   - `SignIn_Logs_*.csv`
   - `Audit_Logs_*.csv`
3. Imports and analyzes all matching files
4. Combines data from multiple CSVs
5. Applies working hours (9 AM - 5 PM)
6. Generates HTML report in `C:\Reports`
7. Opens report automatically (`-Open` parameter)

**Required CSV columns**:

**Sign-in logs CSV must have**:
- Date (UTC)
- User
- Status
- IP address
- Location - City
- Location - Country/Region
- Application
- Session ID
- Operating System
- Client app
- Risk State
- Risk Event Types v2

**Audit logs CSV must have**:
- Timestamp
- Activity
- Result
- Initiator User UPN
- Initiator IP
- Target Display Name
- Target Type
- Category
- Service

---

### Mode 2: Connect to Entra ID Directly

**When to use**: You want to export fresh data directly from your Entra ID tenant.

**Command**:
```powershell
.\AccountSuspiciousBehaviorChecker.ps1 -EntraIDConnect "admin@contoso.com" -AffectedUPN "user@contoso.com" -Output "C:\Reports" -Open
```

**What it does**:
1. Prompts for interactive authentication (browser window opens)
2. Connects to Microsoft Graph using the admin account
3. Exports sign-in logs for the specified user (`user@contoso.com`)
4. Exports audit logs initiated by the user
5. Saves CSVs to `C:\Reports` folder
6. Analyzes the exported data
7. Generates HTML report
8. Opens report automatically

**Required permissions** (for the admin account):
- `AuditLog.Read.All` OR
- `Directory.Read.All`

**Time range**:
- By default, retrieves last 30 days of data
- Use `-Start` and `-End` to filter specific date ranges

---

### Mode 3: Interactive Mode

**When to use**: First-time users or when you want guided setup.

**Command**:
```powershell
.\AccountSuspiciousBehaviorChecker.ps1
```

**What it does**:
1. Displays main menu with two options:
   - Option 1: Analyze existing CSV files
   - Option 2: Connect to Entra ID and export logs

2. **If you choose Option 1** (Analyze existing CSVs):
   - Prompts for folder path containing CSVs
   - Prompts for output folder
   - Asks for working hours (start and end)
   - Processes files
   - Generates report
   - Asks if you want to open the report

3. **If you choose Option 2** (Connect to Entra ID):
   - Prompts for output folder
   - Asks if you want to specify a user or let it prompt later
   - Opens browser for authentication
   - After auth, prompts for target user UPN (if not specified)
   - Exports logs
   - Analyzes data
   - Generates report
   - Asks if you want to open the report

---

## Parameter Reference

### `-importCSVPath` (String)

**Description**: Path to a folder containing CSV files OR path to a specific CSV file.

**Usage**:
```powershell
-importCSVPath "C:\Logs"               # Folder (all CSVs analyzed)
-importCSVPath "C:\Logs\SignIn.csv"    # Single file
```

**Behavior**:
- If folder: Scans for all `SignIn_Logs_*.csv` and `Audit_Logs_*.csv` files
- If file: Analyzes only that specific file
- Cannot be used with `-EntraIDConnect`

---

### `-Output` (String)

**Description**: Folder path where reports and exported CSVs will be saved.

**Usage**:
```powershell
-Output "C:\Reports"
-Output "C:\Investigation\User123"
```

**Behavior**:
- Creates folder if it doesn't exist
- If not specified, prompts interactively
- All output files saved here:
  - `SignIn_Logs_[timestamp].csv`
  - `Audit_Logs_[timestamp].csv`
  - `Account_Suspicious_Behavior_Report_[timestamp].html`

---

### `-Open` (Switch)

**Description**: Automatically opens the generated HTML report in default browser.

**Usage**:
```powershell
-Open                    # Opens report after generation
# (no -Open means won't auto-open)
```

**Behavior**:
- If specified: Opens report immediately after generation
- If not specified: Prompts whether to open or not

---

### `-EntraIDConnect` (String)

**Description**: UPN of the admin account to use for Microsoft Graph authentication.

**Usage**:
```powershell
-EntraIDConnect "admin@contoso.com"
```

**Behavior**:
- Initiates interactive browser-based authentication
- Requires Entra ID permissions
- Cannot be used with `-importCSVPath`
- If not specified in Connect mode, may prompt for credentials

---

### `-AffectedUPN` (String)

**Description**: User Principal Name of the target user to analyze.

**Usage**:
```powershell
-AffectedUPN "john.doe@contoso.com"
```

**Behavior**:
- Used only with `-EntraIDConnect`
- Filters logs to this specific user
- If not specified, prompts interactively after authentication

---

### `-Start` (String or Integer)

**Description**: Start of time window - supports multiple formats.

**Format 1 - Working Hours** (Integer 0-23):
```powershell
-Start 9          # 9 AM
-Start 0          # Midnight
-Start 22         # 10 PM
```

**Format 2 - Date String**:
```powershell
-Start "2025-01-01"
-Start "2025-01-01T00:00:00Z"
-Start "January 1, 2025"
```

**Format 3 - Unix Epoch**:
```powershell
-Start 1704067200         # Seconds since 1970-01-01
-Start 1704067200000      # Milliseconds since 1970-01-01
```

**Behavior**:
- **If both `-Start` and `-End` are 0-23**: Treated as working hours for off-hours detection
- **If date/epoch format**: Filters data to only include records on/after this date
- Works with both CSV analysis and Entra ID export modes

---

### `-End` (String or Integer)

**Description**: End of time window - same formats as `-Start`.

**Examples**:
```powershell
-End 17                   # 5 PM (working hours)
-End "2025-12-31"         # Last day of year
-End 1735689599           # Unix epoch
```

**Behavior**:
- **If both `-Start` and `-End` are 0-23**: Treated as working hours
- **If date/epoch format**: Filters data to only include records on/before this date
- Must be used with `-Start` for date range filtering

---

## Score Calculation Deep Dive

### Overall Score Formula

```
Overall Score = (Sign-In Score ร— 60%) + (Audit Score ร— 40%)
```

**Rationale**:
- Sign-in logs typically have more data points
- Audit logs show impact/actions taken
- 60/40 split balances detection and impact

---

### Sign-In Score Calculation

The sign-in score is calculated from **12 indicators**, each with equal weight:

```
Individual Indicator Weight = 100 รท 12 = 8.33%
```

**Formula**:
```
Sign-In Score = ฮฃ(Indicator Score ร— 8.33%)
```

**Step-by-step example**:

Assume these indicator scores:
1. Multiple Locations: 100 points
2. Failed/Interrupted: 25 points
3. Brute-force: 80 points
4. Password-spray: 0 points
5. Account Lockout: 0 points
6. Multiple IPs: 60 points
7. Risky Sign-ins: 100 points
8. Suspicious User Agents: 30 points
9. Off-hours Activity: 20 points
10. Multiple Devices: 60 points
11. Anonymous IP: 0 points
12. Session IP Mismatch: 0 points

**Calculation**:
```
Sign-In Score = (100 ร— 8.33%) + (25 ร— 8.33%) + (80 ร— 8.33%) + (0 ร— 8.33%) + 
                (0 ร— 8.33%) + (60 ร— 8.33%) + (100 ร— 8.33%) + (30 ร— 8.33%) + 
                (20 ร— 8.33%) + (60 ร— 8.33%) + (0 ร— 8.33%) + (0 ร— 8.33%)
              = 8.33 + 2.08 + 6.66 + 0 + 0 + 5.00 + 8.33 + 2.50 + 1.67 + 5.00 + 0 + 0
              = 39.57
```

---

### Audit Score Calculation

The audit score combines **4 main indicators** (25% each) and **13 suspicious activities** (7.69% each):

```
Main Indicator Weight = 100 รท 4 = 25%
Suspicious Activity Weight = 100 รท 13 = 7.69%
```

**Formula**:
```
Audit Score = ฮฃ(Main Indicator Score ร— 25%) + ฮฃ(Suspicious Activity Score ร— 7.69%)
```

**Step-by-step example**:

**Main Indicators**:
1. Off-Hours Password: 100 points
2. Privileged Role Changes: 80 points
3. Off-Hours Activity: 30 points
4. Failed Events: 10 points

**Suspicious Activities** (13 total):
- Update Application: 100 points (detected)
- Add Service Principal: 0 points (not detected)
- Add App Role: 0 points
- Disable Account: 100 points (detected)
- Bulk Update: 0 points
- Add Owner: 0 points
- Update SP: 0 points
- Policy Changes: 60 points (2 detections ร— 30)
- Bulk Deletions: 0 points
- Consent to App: 0 points
- Password Change: 30 points (1 detection ร— 30)
- Password Reset: 30 points (1 detection ร— 30)
- MFA Changes: 0 points

**Calculation**:
```
Main Indicators Contribution:
= (100 ร— 25%) + (80 ร— 25%) + (30 ร— 25%) + (10 ร— 25%)
= 25 + 20 + 7.5 + 2.5
= 55

Suspicious Activities Contribution:
= (100 ร— 7.69%) + (0 ร— 7.69%) + (0 ร— 7.69%) + (100 ร— 7.69%) + 
  (0 ร— 7.69%) + (0 ร— 7.69%) + (0 ร— 7.69%) + (60 ร— 7.69%) + 
  (0 ร— 7.69%) + (0 ร— 7.69%) + (30 ร— 7.69%) + (30 ร— 7.69%) + (0 ร— 7.69%)
= 7.69 + 0 + 0 + 7.69 + 0 + 0 + 0 + 4.61 + 0 + 0 + 2.31 + 2.31 + 0
= 24.61

Audit Score = 55 + 24.61 = 79.61
```

---

### Final Overall Score

Using the examples above:
```
Overall Score = (39.57 ร— 60%) + (79.61 ร— 40%)
              = 23.74 + 31.84
              = 55.58
```

**Risk Level**: HIGH (50-74 range)

---

## Indicator Explanations

### Sign-In Indicators (Detailed)

#### 1. Multiple Locations

**What it detects**: Impossible travel - user appearing in geographically distant locations within physically impossible timeframes (24-hour windows).

**How it's calculated**:
1. Sort all sign-ins chronologically
2. For each sign-in, check next 24 hours of activity
3. Count unique cities in that window
4. If 2+ unique cities detected, flag as suspicious
5. Score = min(100, Detections ร— 35)

**Example data triggering detection**:
```
10:00 AM - Sign-in from New York, USA
11:00 AM - Sign-in from London, UK (impossible in 1 hour)
Score = 1 ร— 35 = 35 points
```

**What to look for in report**:
- Click "Multiple Locations" card
- Review timeline of location changes
- Check if travel time is physically possible
- Look for VPN use (which might explain location shifts)

**False positives**:
- VPN connections
- Cloud-based desktop services
- Split-tunnel VPN (some apps through VPN, others direct)

---

#### 2. Failed/Interrupted Sign-ins

**What it detects**: Elevated failure rates indicating password guessing, credential issues, or account problems.

**How it's calculated**:
1. Count total sign-ins
2. Count failed sign-ins (Status = 'Failure')
3. Count interrupted sign-ins (Status = 'Interrupted')
4. Combined = Failed + Interrupted
5. Score = (Combined รท Total) ร— 100

**Example**:
```
Total sign-ins: 500
Failed: 75
Interrupted: 25
Combined: 100
Score = (100 รท 500) ร— 100 = 20 points
```

**What to look for in report**:
- Failed Activities table shows all failures
- Check error codes (50126 = wrong password, 50053 = lockout, etc.)
- Review failure patterns (time of day, IP addresses)
- Check if legitimate user or attacker

**Common error codes**:
- `50126`: Invalid username or password
- `50053`: Account locked out
- `50055`: Password expired
- `50057`: Account disabled
- `50074`: Strong authentication required

---

#### 3. Brute-force Attacks

**What it detects**: Rapid-fire password attempts indicating automated attack tools.

**How it's calculated**:
1. Filter for error code 50126 (wrong password)
2. Sort by timestamp
3. Use 10-minute sliding windows
4. Count failures in each window
5. If 5+ failures in a window, flag as brute-force
6. Score = min(100, Windows ร— 40)

**Example**:
```
10:00:00 - Failed login (wrong password)
10:01:30 - Failed login (wrong password)
10:03:15 - Failed login (wrong password)
10:05:00 - Failed login (wrong password)
10:07:45 - Failed login (wrong password)
= 5 failures in 10 minutes = 1 brute-force window
Score = 1 ร— 40 = 40 points
```

**What to look for in report**:
- Click "Brute-force" card to see details
- Check IP addresses (single IP or distributed?)
- Review timeline (continuous or sporadic?)
- Look for successful login after failures (suspicious indicator)

**Mitigation indicators**:
- Account locked = Protection working
- MFA challenge = Additional protection
- Conditional Access blocked = Policies effective

---

#### 4. Password-spray Attacks

**What it detects**: Low-and-slow password attempts across multiple accounts, trying common passwords.

**How it's calculated**:
1. Filter for error code 50126 (wrong password)
2. Sort by timestamp
3. Use 30-minute sliding windows (longer than brute-force)
4. Count failures in each window
5. If 10+ failures in a window, flag as password-spray
6. Score = min(100, Windows ร— 40)

**Difference from brute-force**:
- **Brute-force**: Many attempts, same user, short time (5+ in 10 min)
- **Password-spray**: Fewer attempts per user, longer window (10+ in 30 min)

**Example**:
```
10:00 - user1@company.com failed (wrong password)
10:05 - user2@company.com failed (wrong password)
10:10 - user3@company.com failed (wrong password)
...
10:25 - user10@company.com failed (wrong password)
= 10 users ร— 1 attempt = Password spray pattern
Score = 1 ร— 40 = 40 points
```

**What to look for in report**:
- Multiple usernames from same IP
- Common password attempts (often visible in logs)
- Geographic source (often from botnets)

---

#### 5. Account Lockout

**What it detects**: Repeated account lockouts indicating persistent attack attempts or configuration issues.

**How it's calculated**:
1. Filter for error code 50053 (account locked)
2. Sort by timestamp
3. Use 15-minute sliding windows
4. Count lockouts in each window
5. If 3+ lockouts in a window, flag
6. Score = min(100, Windows ร— 50)

**Example**:
```
10:00 - Account locked (error 50053)
10:05 - Account locked (error 50053)
10:10 - Account locked (error 50053)
= 3 lockouts in 15 minutes = 1 lockout window
Score = 1 ร— 50 = 50 points
```

**What to look for in report**:
- Was account actually locked by admin?
- Did lockouts stop (protection working)?
- IP addresses involved
- If continuing lockouts, attacker still active

---

#### 6. Multiple IP Addresses

**What it detects**: User accessing from many different IP addresses in short timeframes, suggesting credential sharing or compromise.

**How it's calculated**:
1. Sort sign-ins by timestamp
2. Use 24-hour sliding windows
3. Count unique IP addresses in each window
4. If 3+ unique IPs, flag
5. Score = min(100, (UniqueIPs - 2) ร— 30)

**Example**:
```
Day 1:
- 10:00 - IP: 1.2.3.4
- 11:00 - IP: 5.6.7.8
- 12:00 - IP: 9.10.11.12
- 13:00 - IP: 13.14.15.16
- 14:00 - IP: 17.18.19.20
= 5 unique IPs in 24 hours
Score = (5 - 2) ร— 30 = 90 points
```

**What to look for in report**:
- Geographic distribution of IPs
- Are they all same ISP/organization?
- Mobile device roaming (cellular IPs change frequently)
- VPN pool (many VPN exit nodes)

**False positives**:
- Mobile workers with cellular
- Users with multiple VPN connections
- Cloud desktop services

---

#### 7. Risky Sign-ins

**What it detects**: Sign-ins flagged by Entra ID Identity Protection as risky based on Microsoft's threat intelligence.

**How it's calculated**:
1. Filter sign-ins where Risk State โ�� 'none'
2. Count risky sign-ins
3. Score = min(100, Count ร— 35)

**Risk states captured**:
- `atRisk`: Active risk detected
- `confirmedCompromised`: Admin confirmed compromise
- `remediated`: Risk mitigated
- `dismissed`: Admin dismissed risk

**Example**:
```
3 sign-ins flagged as risky by Identity Protection
Score = 3 ร— 35 = 100 points (capped)
```

**What to look for in report**:
- Risk detection types (anonymous IP, atypical travel, etc.)
- Detection categories (real-time vs offline)
- Risk levels (low, medium, high)

**Risk Event Types** (examples from report):
- Anonymous IP address
- Atypical travel
- Malware linked IP address
- Suspicious inbox forwarding
- Password spray
- Unfamiliar sign-in properties

---

#### 8. Suspicious User Agents

**What it detects**: Automated tools, scripts, or bots accessing the account (PowerShell, Python, curl, etc.).

**How it's calculated**:
1. Check User Agent strings for patterns:
   - "PowerShell"
   - "Python"
   - "curl"
   - "wget"
   - "HTTP"
   - "automation"
   - "bot"
2. Count unique suspicious user agents
3. Score = min(100, Count ร— 30)

**Example**:
```
Sign-ins detected from:
- Mozilla/5.0 PowerShell
- Python-requests/2.25.1
= 2 suspicious user agents
Score = 2 ร— 30 = 60 points
```

**What to look for in report**:
- Are automation tools expected? (legitimate scripts)
- Check if legitimate admin tools or attack tools
- Review what resources were accessed

**Legitimate uses**:
- Azure PowerShell scripts
- Microsoft Graph API calls
- Automated monitoring tools

**Malicious indicators**:
- Combined with failed logins
- Accessing unusual resources
- From unexpected IPs

---

#### 9. Off-hours Activity

**What it detects**: Sign-ins outside configured working hours.

**How it's calculated**:
1. Take working hours from parameters (e.g., 9 AM - 5 PM)
2. For each sign-in, extract hour of day
3. Check if hour is outside working hours
4. Count off-hours sign-ins
5. Score = (Off-hours รท Total) ร— 100

**Example**:
```
Working hours: 9 AM - 5 PM (Start 9, End 17)
Total sign-ins: 200
Off-hours sign-ins: 40
Score = (40 รท 200) ร— 100 = 20 points
```

**Off-hours logic**:
```
If Start < End (e.g., 9 < 17):
  Off-hours = Hour < Start OR Hour >= End
  
If Start > End (night shift, e.g., 22 > 6):
  Off-hours = Hour >= End AND Hour < Start
```

**What to look for in report**:
- What times are off-hours logins?
- Are they consistent (same time daily)?
- Geographic location (different timezone?)
- Is user known to work flexible hours?

**False positives**:
- Remote workers in different timezones
- Legitimate after-hours work
- Automated scripts (scheduled tasks)

---

#### 10. Multiple Devices

**What it detects**: User accessing from multiple different operating systems (proxy for different devices).

**How it's calculated**:
1. Group sign-ins by user
2. Count unique Operating System values
3. If 2+ different OS, flag
4. Score = min(100, (OSCount - 1) ร— 30)

**Example**:
```
User signed in from:
- Windows 10
- iOS 14
- Android 11
= 3 different OS
Score = (3 - 1) ร— 30 = 60 points
```

**What to look for in report**:
- Are multiple devices expected? (laptop + phone)
- Check timeline (switching frequently?)
- Review device details if available

**False positives**:
- Users with laptop, phone, tablet (normal)
- IT testing multiple systems
- Help desk troubleshooting

---

#### 11. Anonymous IP

**What it detects**: Sign-ins from Tor, VPN, proxy services, or anonymization networks.

**How it's calculated**:
1. Check if sign-in properties flag anonymous IP
2. Or check Risk Event Types for "Anonymous IP"
3. Count sign-ins from anonymous IPs
4. Score = min(100, Count ร— 40)

**Example**:
```
2 sign-ins from Tor exit nodes
Score = 2 ร— 40 = 80 points
```

**What to look for in report**:
- Reason for anonymization (privacy vs hiding)
- Is VPN use approved in organization?
- Other risk indicators present?

**Legitimate uses**:
- Corporate VPN
- Privacy-conscious users
- Work from sensitive locations

**Malicious indicators**:
- Tor usage (rarely legitimate for business)
- Combined with suspicious activity
- Accessing sensitive resources

---

#### 12. Session IP Mismatch

**What it detects**: Multiple different IP addresses used within the same session ID (session hijacking indicator).

**How it's calculated**:
1. Group sign-ins by Session ID
2. For each session, count unique IPs
3. If 2+ IPs in same session, flag
4. Count mismatched sessions
5. Score = min(100, Sessions ร— 40)

**Example**:
```
Session ID: abc123
- 10:00 - IP: 1.2.3.4
- 10:15 - IP: 5.6.7.8 (different IP, same session!)
= 1 mismatched session
Score = 1 ร— 40 = 40 points
```

**What to look for in report**:
- Timeline between IP changes
- Geographic locations of both IPs
- What resources were accessed

**This is a strong suspicious indicator** because:
- Session tokens typically stay on one device
- IP changes mid-session suggest token theft
- Rare in legitimate scenarios

---

### Audit Indicators (Detailed)

#### Main Indicator 1: Off-Hours Password Change/Reset

**What it detects**: Password modifications occurring outside normal working hours.

**How it's calculated**:
1. Filter activities matching 'password' or 'reset'
2. Check timestamp hour against working hours
3. Count off-hours password changes
4. Score = min(100, Count ร— 50)

**Weight**: 25% of audit score

**Example**:
```
Working hours: 9 AM - 5 PM
Password change at 2 AM = Off-hours
Password change at 11 PM = Off-hours
= 2 off-hours changes
Score = 2 ร— 50 = 100 points
Contribution to audit score = 100 ร— 25% = 25
```

**What to look for in report**:
- Was it user-initiated or admin reset?
- Result (success or failure)?
- IP address (expected location?)
- Frequency (one-time or pattern?)

**High risk if**:
- Multiple off-hours changes
- Different IP than usual
- Followed by other suspicious activity

---

#### Main Indicator 2: Privileged Role Changes

**What it detects**: Modifications to administrative roles and permissions.

**How it's calculated**:
1. Filter activities matching 'role', 'permission', 'privilege'
2. Group by: Activity + Initiator UPN + Target Display Name
3. Count unique combinations
4. Score = min(100, Count ร— 40)

**Weight**: 25% of audit score

**Example**:
```
3 unique role changes detected:
- Add member to Global Admin role
- Remove member from Security Admin role
- Update role assignments
Score = 3 ร— 40 = 100 points (capped)
Contribution = 100 ร— 25% = 25
```

**What to look for in report**:
- Who initiated the change (Initiator UPN)?
- Who was affected (Target)?
- What role was changed?
- Was change successful?
- Time of change

**Critical roles to watch**:
- Global Administrator
- Security Administrator
- Privileged Role Administrator
- Application Administrator
- User Administrator

---

#### Main Indicator 3: Off-Hours Audit Activity

**What it detects**: Any audit activity occurring outside working hours.

**How it's calculated**:
1. Check timestamp hour for each activity
2. Compare against working hours
3. Count off-hours activities
4. Score = (Off-hours รท Total) ร— 100

**Weight**: 25% of audit score

**Example**:
```
Total audit activities: 500
Off-hours activities: 150
Score = (150 รท 500) ร— 100 = 30 points
Contribution = 30 ร— 25% = 7.5
```

**What to look for in report**:
- Types of off-hours activities
- Are they scheduled tasks or manual?
- Same user or multiple users?
- Pattern (daily, weekly, sporadic)?

---

#### Main Indicator 4: Failed Audit Events

**What it detects**: Failed administrative operations indicating permission issues or unauthorized attempts.

**How it's calculated**:
1. Filter activities where Result โ�� 'success'
2. Count failed activities
3. Score = (Failed รท Total) ร— 100

**Weight**: 25% of audit score

**Example**:
```
Total audit activities: 500
Failed activities: 25
Score = (25 รท 500) ร— 100 = 5 points
Contribution = 5 ร— 25% = 1.25
```

**What to look for in report**:
- What operations failed?
- Who attempted them?
- Why did they fail (permission, policy, error)?
- Pattern of failures

**High risk if**:
- Multiple failed privilege escalation attempts
- Failed unauthorized resource access
- Failed attempts to modify security settings

---

### Suspicious Activities (Detailed)

Each suspicious activity has **7.69% weight** (100 รท 13).

#### 1. Update Application (High Risk)

**What it detects**: Modifications to application registrations.

**Scoring**: 100 points if detected (any occurrence)

**Why it matters**: Attackers modify app registrations to:
- Add redirect URIs for token theft
- Elevate permissions
- Add credentials for persistence
- Enable implicit grant flow

**What to look for**:
- What was changed?
- Who made the change?
- Was it expected/authorized?

---

#### 2. Add Service Principal (High Risk)

**What it detects**: Creation of new service accounts.

**Scoring**: 100 points if detected

**Why it matters**: Attackers create service principals to:
- Establish automated access
- Bypass MFA
- Create backdoor accounts
- Automate data exfiltration

---

#### 3. Add App Role Assignment (High Risk)

**What it detects**: Granting permissions to applications.

**Scoring**: 100 points if detected

**Why it matters**: Privilege escalation by:
- Granting admin consents
- Assigning high-privilege roles to apps
- Enabling malicious apps

---

#### 4. Disable Account (High Risk)

**What it detects**: User accounts being disabled.

**Scoring**: 100 points if detected

**Why it matters**: Attackers disable accounts to:
- Cover tracks
- Lock out legitimate admins
- Prevent detection
- Cause disruption

---

#### 5. Bulk Update User (High Risk)

**What it detects**: Mass modifications to user properties.

**Scoring**: 100 points if detected

**Why it matters**: Bulk operations can:
- Change multiple user properties at once
- Indicate suspicious of high-privilege account
- Affect many users simultaneously

---

#### 6. Add Owner to Application/Service Principal (High Risk)

**What it detects**: Ownership changes to applications.

**Scoring**: 100 points if detected

**Why it matters**: Ownership allows:
- Full control over application
- Adding credentials
- Modifying permissions
- Persistent access

---

#### 7. Update Service Principal (High Risk)

**What it detects**: Modifications to service accounts.

**Scoring**: 100 points if detected

**Why it matters**: Similar to update application - enables:
- Credential theft
- Permission elevation
- Persistence

---

#### 8-13. Medium Risk Activities (Policy Changes, Bulk Deletions, Consent, Password Changes, MFA)

**Scoring**: min(100, Count ร— 30)

**Each detection adds 30 points** (capped at 100)

**Examples**:
- 1 policy change = 30 points
- 2 password resets = 60 points
- 4 MFA changes = 100 points (capped)

---

## Report Navigation

### Section 1: Executive Summary

**Location**: Top of report

**Contains**:
1. **Risk Score Gauge**: Large circular gauge showing overall score
   - Color-coded (red/orange/yellow/green)
   - Shows exact numeric score
   - Risk level text (CRITICAL/HIGH/MEDIUM/LOW)

2. **Score Breakdown**:
   - Sign-In Score (blue) - 60% weight
   - Audit Score (purple) - 40% weight
   - Calculation shown

3. **Quick Statistics Dashboard**:
   - Total sign-ins
   - Unique countries
   - Unique IPs
   - Total audit activities

**How to interpret**:
- Start here for quick assessment
- If score > 75, investigate immediately
- Compare sign-in vs audit scores (which is higher?)

---

### Section 2: Sign-In Indicators of suspicious behavior

**Location**: After executive summary

**Contains**: 12 indicator cards arranged in grid

**Each card shows**:
- Indicator name and icon
- Score (0-100)
- Detection count
- Status badge (Detected/Not Detected)
- Weight contribution

**Interaction**:
- Click any card to open detailed modal
- Modal shows table of specific detections
- Columns vary by indicator type

**Priority review order**:
1. Red cards (detected with high scores)
2. High-weight indicators (all equal at 8.33%)
3. Cards with counts > 0

---

### Section 3: Failed Sign-In Activities

**Location**: Below sign-in indicators

**Contains**: Table of failed authentication attempts

**Columns**:
- Timestamp
- User
- Application
- Resource
- IP Address
- City
- Operating System
- Error Code
- Result Reason (why it failed)
- Count

**Sorting**:
- Click column headers to sort
- Most recent first by default

**What to look for**:
- Patterns in error codes
- Same IP multiple failures
- Progression (failures then success)

---

### Section 4: Audit Indicators of suspicious behavior

**Location**: After sign-in sections

**Contains**:
1. **How Scores Are Calculated box**: Shows 4 main indicators at 25% each
2. **4 main indicator cards**
3. **13 suspicious activity cards**

**Indicator cards show**:
- Activity name
- Risk level badge (High/Medium)
- Detection count
- Status (Detected/Not Detected)
- Weight

**Interaction**:
- Click cards to see detailed data
- Modals show activity tables
- Filter/sort in modals

---

### Section 5: Sign-In Activity Metrics

**Location**: Near bottom of report

**Contains**: 8 expandable sections:
1. By Countries
2. By IP Addresses
3. By Session IDs
4. By Applications
5. By Client Apps
6. By Resources
7. By Operating Systems
8. Off-Hours Sign-Ins

**Each section shows**:
- Summary count
- Click to expand table
- Grouped/deduplicated data
- Timestamp, status, count

**Use for**:
- Understanding usage patterns
- Identifying anomalies
- Baseline establishment

---

### Section 6: Audit Activity Overview

**Location**: Bottom sections

**Contains**:
1. Total Audit Activities table
2. Successful Activities table
3. User Management Activities
4. MFA Changes
5. Off-Hours Activities
6. Group Changes
7. Password Changes/Resets
8. Application Activities
9. Policy Changes

**Expandable sections**:
- Click to show/hide tables
- Each table shows relevant activities
- Grouped to eliminate duplicates

---

## Advanced Usage

### Scenario 1: Automated Daily Reports

Create scheduled task:

**PowerShell script** (SavedScript.ps1):
```powershell
$today = Get-Date -Format "yyyyMMdd"
$outputFolder = "C:\Reports\DailyReports\$today"

.\AccountSuspiciousBehaviorChecker.ps1 `
    -EntraIDConnect "admin@contoso.com" `
    -AffectedUPN "vip.user@contoso.com" `
    -Output $outputFolder `
    -Start 8 `
    -End 18
```

**Task Scheduler**:
1. Open Task Scheduler
2. Create Basic Task
3. Trigger: Daily at 7:00 AM
4. Action: Start a program
   - Program: `powershell.exe`
   - Arguments: `-File "C:\Scripts\SavedScript.ps1"`

---

### Scenario 2: Bulk User Analysis

Analyze multiple users:

```powershell
# List of users to check
$users = @(
    "user1@contoso.com",
    "user2@contoso.com",
    "user3@contoso.com"
)

# Admin account for connection
$admin = "admin@contoso.com"

# Base output folder
$baseOutput = "C:\BulkAnalysis"

# Process each user
foreach ($user in $users) {
    Write-Host "Analyzing $user..." -ForegroundColor Cyan
    
    # Create user-specific folder
    $userFolder = Join-Path $baseOutput $user.Split('@')[0]
    
    # Run analysis
    .\AccountSuspiciousBehaviorChecker.ps1 `
        -EntraIDConnect $admin `
        -AffectedUPN $user `
        -Output $userFolder `
        -Start 9 `
        -End 17
    
    Write-Host "Completed $user" -ForegroundColor Green
    Start-Sleep -Seconds 5  # Rate limiting
}

Write-Host "`nBulk analysis complete!" -ForegroundColor Green
```

---

### Scenario 3: Forensic Analysis with Date Filtering

Investigate specific incident timeframe:

```powershell
# Incident occurred December 15-20, 2025
.\AccountSuspiciousBehaviorChecker.ps1 `
    -importCSVPath "C:\ForensicData" `
    -Output "C:\Investigation\Incident20251215" `
    -Start "2025-12-15T00:00:00Z" `
    -End "2025-12-20T23:59:59Z" `
    -Open
```

---

### Scenario 4: Compare Time Periods

Compare user behavior before and after suspicious activity:

```powershell
# Week before incident
.\AccountSuspiciousBehaviorChecker.ps1 `
    -importCSVPath "C:\Logs" `
    -Start "2025-12-01" `
    -End "2025-12-07" `
    -Output "C:\Comparison\Before"

# Week of incident
.\AccountSuspiciousBehaviorChecker.ps1 `
    -importCSVPath "C:\Logs" `
    -Start "2025-12-08" `
    -End "2025-12-14" `
    -Output "C:\Comparison\During"

# Compare scores manually
```

---

### Scenario 5: Custom Working Hours for Different Timezones

User in different timezone:

```powershell
# User in London (GMT), you in New York (EST)
# London 9-17 = EST 4-12
.\AccountSuspiciousBehaviorChecker.ps1 `
    -importCSVPath "C:\Logs\LondonUser" `
    -Start 4 `
    -End 12 `
    -Output "C:\Reports"
```

---

## Troubleshooting

### Issue: Script Won't Run - Execution Policy

**Error**:
```
File cannot be loaded because running scripts is disabled on this system.
```

**Solution**:
```powershell
# Check current policy
Get-ExecutionPolicy

# Set to RemoteSigned (allows local scripts)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# Or run with bypass for one time
powershell.exe -ExecutionPolicy Bypass -File .\AccountSuspiciousBehaviorChecker.ps1
```

---

### Issue: Module Not Found

**Error**:
```
Microsoft.Graph module not found
```

**Solution**:
```powershell
# Install module
Install-Module Microsoft.Graph -Scope CurrentUser -Force

# Verify installation
Get-Module Microsoft.Graph -ListAvailable

# Import module
Import-Module Microsoft.Graph
```

---

### Issue: Access Denied When Connecting to Entra ID

**Error**:
```
Insufficient privileges to complete the operation
```

**Causes**:
1. Account lacks required permissions
2. Tenant requires admin consent
3. Conditional Access blocking

**Solutions**:

**Solution 1 - Check Permissions**:
1. Go to Entra ID Portal
2. Roles and administrators
3. Check if admin account has:
   - `Global Reader`
   - `Security Reader`
   - `Reports Reader`
4. Or assign `Directory.Read.All` or `AuditLog.Read.All`

**Solution 2 - Admin Consent**:
```powershell
# Connect with specific scopes
Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All"
```

**Solution 3 - Conditional Access**:
- Check if CA policy blocks service principals
- Add exception for Microsoft Graph Command Line Tools

---

### Issue: No Data in Report

**Symptoms**:
- Report generated but shows zeros
- Empty tables

**Causes**:
1. Date filter too restrictive
2. Wrong CSV format/columns
3. User has no activity in period
4. CSV files empty

**Solutions**:

**Check 1 - Verify CSV Content**:
```powershell
# Check row count
(Import-Csv "C:\Logs\SignIn_Logs.csv").Count

# View first few rows
Import-Csv "C:\Logs\SignIn_Logs.csv" | Select-Object -First 5
```

**Check 2 - Remove Date Filters**:
```powershell
# Run without Start/End
.\AccountSuspiciousBehaviorChecker.ps1 -importCSVPath "C:\Logs" -Output "C:\Reports"
```

**Check 3 - Verify User Has Activity**:
- Check Entra ID Portal for user's sign-in history
- Ensure AffectedUPN is correct
- Try different date range

---

### Issue: Report Shows "NaN" or Calculation Errors

**Symptoms**:
- Scores show "NaN"
- Percentages incorrect

**Causes**:
- Division by zero (no sign-ins)
- Corrupted CSV data
- Incomplete data

**Solutions**:

**Check for zero totals**:
```powershell
# Check CSV has data
$data = Import-Csv "path\to\file.csv"
Write-Host "Row count: $($data.Count)"
```

**Verify CSV structure**:
- Open CSV in text editor
- Check for malformed rows
- Verify headers match expected columns

---

### Issue: Script Runs Very Slowly

**Symptoms**:
- Takes 10+ minutes to complete
- PowerShell becomes unresponsive

**Causes**:
1. Very large CSV files (millions of rows)
2. Insufficient memory
3. Slow disk I/O
4. Many Graph API calls

**Solutions**:

**Solution 1 - Filter Data Before Analysis**:
```powershell
# Pre-filter CSV to smaller date range
$data = Import-Csv "large_file.csv"
$filtered = $data | Where-Object { 
    [DateTime]$_.'Date (UTC)' -ge '2025-01-01' -and 
    [DateTime]$_.'Date (UTC)' -le '2025-01-31' 
}
$filtered | Export-Csv "filtered_file.csv" -NoTypeInformation

# Then analyze filtered file
.\AccountSuspiciousBehaviorChecker.ps1 -importCSVPath "filtered_file.csv"
```

**Solution 2 - Increase Memory**:
```powershell
# Run PowerShell with more memory
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& {$env:PSModulePath; .\AccountSuspiciousBehaviorChecker.ps1}"
```

**Solution 3 - Use SSD**:
- Move script and CSVs to SSD if on HDD

---

### Issue: Graph API Throttling

**Error**:
```
Request was throttled. Please retry after X seconds.
```

**Cause**: Too many API requests in short time

**Solution**:
- Script has built-in throttling handling
- If persists, add delays between bulk operations
- Export data during off-peak hours

---

## Best Practices

### Security Best Practices

1. **Protect Generated Reports**:
   - Reports contain sensitive user data
   - Store in secure location
   - Use encrypted drives
   - Set appropriate NTFS permissions

2. **Use Service Accounts for Automation**:
   - Create dedicated account for scheduled reports
   - Limit permissions to only what's needed
   - Monitor service account activity

3. **Regular Baseline Updates**:
   - Run monthly on normal users to establish baselines
   - Compare suspected compromises against baselines
   - Adjust thresholds if too many false positives

4. **Audit the Auditor**:
   - Log who runs the script
   - Monitor admin account used for Graph connections
   - Alert on unexpected script executions

---

### Operational Best Practices

1. **Working Hours Accuracy**:
   - Set accurate working hours for each user/region
   - Update when schedules change
   - Consider flexible work arrangements

2. **Data Retention**:
   - Keep reports for compliance periods
   - Organize by date and user
   - Use consistent folder structure

3. **Regular Reviews**:
   - Schedule weekly reviews of high-privilege accounts
   - Monthly reviews of all users
   - Quarterly baseline updates

4. **Alert Thresholds**:
   - CRITICAL (75+): Immediate investigation
   - HIGH (50-74): Review within 4 hours
   - MEDIUM (25-49): Review within 24 hours
   - LOW (0-24): Routine monitoring

5. **Documentation**:
   - Document investigation findings
   - Link reports to incident tickets
   - Track false positive patterns

---

### Analysis Best Practices

1. **Start with Overall Score**:
   - Don't get lost in details initially
   - Triage by risk level
   - Focus on CRITICAL first

2. **Check for Patterns**:
   - Multiple indicators firing = higher confidence
   - Single indicator = could be false positive
   - Timeline correlation = strong indicator

3. **Context Matters**:
   - Consider user role (IT admin vs regular user)
   - Geographic factors (travel, timezone)
   - Known organizational changes (mergers, migrations)

4. **Validate with User**:
   - Contact user about suspicious activity
   - Verify locations and devices
   - Confirm scheduled off-hours work

5. **Correlate with Other Tools**:
   - Check EDR/antivirus logs
   - Review email security alerts
   - Check DLP systems
   - Validate against SIEM data

---

### Reporting Best Practices

1. **Naming Conventions**:
   ```
   [Date]_[UserID]_[Incident]_Report.html
   Example: 20250104_jdoe_SuspiciousActivity_Report.html
   ```

2. **Folder Structure**:
   ```
   Reports/
   โ”�โ”€โ”€ 2025/
   โ”�   โ”�โ”€โ”€ 01-January/
   โ”�   โ”�   โ”�โ”€โ”€ Week1/
   โ”�   โ”�   โ”�โ”€โ”€ Week2/
   โ”�   โ”�   โ””โ”€โ”€ Incidents/
   โ”�   โ””โ”€โ”€ 02-February/
   โ””โ”€โ”€ Archives/
   ```

3. **Version Control**:
   - Keep script version in report metadata
   - Track changes to detection logic
   - Maintain changelog

4. **Stakeholder Communication**:
   - Executive summary for management
   - Technical details for security team
   - Action items with owners

---

## Appendix: Error Codes Reference

### Common Sign-in Error Codes

| Code | Description | Meaning |
|------|-------------|---------|
| 50126 | Invalid username or password | Most common - credential error |
| 50053 | Account locked | Too many failed attempts |
| 50055 | Password expired | User needs to change password |
| 50057 | Account disabled | Account disabled by admin |
| 50074 | Strong authentication required | MFA needed but not provided |
| 50076 | MFA required | MFA prompt shown |
| 50079 | User needs to enroll MFA | MFA not set up yet |
| 50097 | Device authentication required | Device not compliant |
| 50105 | User not assigned to application | App access not granted |
| 50125 | Sign-in interrupted by password reset or registration | Self-service flow |
| 50140 | User needs to accept terms of use | TOU acceptance required |

---

## Appendix: CSV Column Requirements

### Sign-In Logs CSV Required Columns

```
Date (UTC)
User
Status
IP address
Location - City
Location - Country/Region
Application
Session ID
Operating System
Client app
Resource
Risk State
Risk Event Types v2
Sign-in error code
Failure reason
User Agent
```

### Audit Logs CSV Required Columns

```
Timestamp
Activity
Result
Category
Service
Initiator User UPN
Initiator IP
Target Display Name
Target Type
Target ID
Operation Type
```

---

**Document Version**: 1.0  
**Last Updated**: January 4, 2026  
**Script Version**: 1.0
