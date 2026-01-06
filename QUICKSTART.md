# Quick Start Guide - Account Suspicious Behavior Checker

Get up and running in under 5 minutes!

## ⚡ Prerequisites Check

Run this command to verify you have PowerShell 5.1+:
```powershell
$PSVersionTable.PSVersion
```

---

## 🚀 Three Ways to Use This Tool

### Option A: Analyze Existing CSV Files (Fastest)

**Best for**: You already have exported sign-in and audit logs

```powershell
# 1. Download the script
cd C:\Scripts

# 2. Run with your CSV folder
.\AccountSuspiciousBehaviorChecker.ps1 -importCSVPath "C:\temp\logs" -Output "C:\Reports" -Open -Start 9 -End 17
```

**What happens**:
- ✅ Analyzes CSV files in `C:\temp\logs`
- ✅ Sets working hours to 9 AM - 5 PM
- ✅ Generates HTML report in `C:\Reports`
- ✅ Opens report automatically

**Expected CSV files**:
- `SignIn_Logs_*.csv` (from Entra ID sign-in logs export)
- `Audit_Logs_*.csv` (from Entra ID audit logs export)

---

### Option B: Connect to Entra ID Directly

**Best for**: You want to export fresh data directly from Entra ID

```powershell
# Run this command
.\AccountSuspiciousBehaviorChecker.ps1 -EntraIDConnect "admin@contoso.com" -AffectedUPN "suspicious.user@contoso.com" -Output "C:\Reports" -Open
```

**What happens**:
1. Prompts for authentication (browser window opens)
2. Exports sign-in logs for the target user
3. Exports audit logs initiated by the user
4. Analyzes all data
5. Generates and opens HTML report

**Requirements**:
- Entra ID admin account with `AuditLog.Read.All` or `Directory.Read.All`
- Internet connectivity

---

### Option C: Interactive Mode (Easiest)

**Best for**: First-time users or when you want guided setup

```powershell
# Just run the script with no parameters
.\AccountSuspiciousBehaviorChecker.ps1
```

**The script will ask you**:
1. Do you want to analyze existing CSVs or connect to Entra ID?
2. Where should output files be saved?
3. What are your working hours? (for off-hours detection)

Then it does everything automatically!

---

## 📊 Understanding Your Results

### Risk Score Interpretation

After analysis, you'll see an overall risk score:

| Score | Level | What It Means | Action |
|-------|-------|---------------|--------|
| **75-100** | 🔴 CRITICAL | Severe indicators | Immediate investigation required |
| **50-74** | 🟠 HIGH | Multiple risk factors present | Priority review recommended |
| **25-49** | 🟡 MEDIUM | Some suspicious activity | Review within 24-48 hours |
| **0-24** | 🟢 LOW | Normal activity patterns | Routine monitoring |

### Score Breakdown

The overall score combines two components:

```
Overall Score = (Sign-In Score × 60%) + (Audit Score × 40%)
```

**Sign-In Score (60%)**:
- Based on 12 indicators
- Detects location hopping, brute-force, suspicious IPs, etc.

**Audit Score (40%)**:
- Based on 4 main indicators + 13 suspicious activities
- Monitors privileged operations, policy changes, bulk actions

---

## 🎯 Common Scenarios

### Scenario 1: Suspected Account Takeover
```powershell
.\AccountSuspiciousBehaviorChecker.ps1 -EntraIDConnect "admin@company.com" -AffectedUPN "compromised.user@company.com" -Output "C:\Investigation" -Open
```
**When to use**: User reports suspicious activity or unusual access patterns

---

### Scenario 2: Post-Incident Analysis
```powershell
.\AccountSuspiciousBehaviorChecker.ps1 -importCSVPath "C:\Forensics\Logs" -Start "2025-12-01" -End "2025-12-31" -Output "C:\Investigation" -Open
```
**When to use**: Analyzing specific time period after security incident

---

### Scenario 3: Regular Security Audit
```powershell
.\AccountSuspiciousBehaviorChecker.ps1 -importCSVPath "C:\MonthlyLogs" -Start 8 -End 18 -Output "C:\AuditReports" -Open
```
**When to use**: Monthly review of privileged account activity

---

### Scenario 4: Quick Check of Multiple Users
```powershell
# Create a simple loop for multiple users
$users = @("user1@company.com", "user2@company.com", "user3@company.com")
foreach ($user in $users) {
    .\AccountSuspiciousBehaviorChecker.ps1 -EntraIDConnect "admin@company.com" -AffectedUPN $user -Output "C:\Reports\$($user.Split('@')[0])"
}
```
**When to use**: Bulk analysis of multiple accounts

---

## 📈 Reading the HTML Report

### Executive Summary Dashboard
Located at the top, shows:
- **Overall Risk Score**: Large colored gauge
- **Sign-In Score**: Blue section (60% weight)
- **Audit Score**: Purple section (40% weight)
- **Quick Stats**: Total sign-ins, countries, IPs, audit activities

### Sign-In Indicators Section
12 cards showing:
- ✅ **Green**: No issues detected (0 points)
- 🟡 **Yellow**: Some activity detected (medium risk)
- 🔴 **Red**: High-risk activity detected

**Click any card** to see detailed data in a popup modal.

### Audit Indicators Section
4 main indicators + 13 suspicious activities:
- **Status badges**: Shows if detected (red) or not detected (green)
- **Detection counts**: Number of occurrences
- **Risk levels**: High or Medium severity

### Activity Tables
Expandable sections showing:
- Failed sign-ins with error codes
- Off-hours activity breakdown
- Sign-in metrics by country, IP, application
- Audit activity categorization

---

## 🔍 Top 10 Indicators to Check First

1. **Multiple Locations** - Impossible travel patterns
2. **Brute-force Attacks** - Rapid failed login attempts
3. **Privileged Role Changes** - Unexpected permission elevations
4. **Risky Sign-ins** - Flagged by Identity Protection
5. **Account Lockouts** - Repeated lockout events
6. **Off-Hours Password Changes** - Changes outside work hours
7. **Update Application** - App registration modifications
8. **Disable Account** - Account disabling activity
9. **Session IP Mismatch** - Multiple IPs in same session
10. **Anonymous IP** - Sign-ins from Tor/VPN/proxy

---

## ⚙️ Working Hours Configuration

### Why It Matters
Off-hours activity detection relies on your working hours configuration:
- Helps identify suspicious after-hours access
- Reduces false positives for legitimate activity

### Two Ways to Set Working Hours

**Method 1: Command-line parameters**
```powershell
-Start 9 -End 17  # 9 AM to 5 PM
```

**Method 2: Interactive prompts**
The script will ask if not specified:
```
Enter working hours START (0-23): 8
Enter working hours END (0-23): 18
```

### Examples
- **Standard business**: `-Start 9 -End 17` (9 AM - 5 PM)
- **Early shift**: `-Start 7 -End 15` (7 AM - 3 PM)
- **Night shift**: `-Start 22 -End 6` (10 PM - 6 AM)
- **24/7 operations**: `-Start 0 -End 23` (always during hours)

---

## 🗂️ File Organization Tips

### Recommended Folder Structure
```
C:\SecurityAnalysis\
├── Scripts\
│   └── AccountSuspiciousBehaviorChecker.ps1
├── Exports\
│   ├── User1\
│   ├── User2\
│   └── User3\
└── Reports\
    ├── 2025-01-01\
    ├── 2025-01-02\
    └── 2025-01-03\
```

### Naming Convention for Outputs
The script automatically names files:
- `SignIn_Logs_20250104_143022.csv`
- `Audit_Logs_20250104_143022.csv`
- `Account_Suspicious_Behavior_Report_20250104_143022.html`

Format: `[Type]_[YYYYMMDD]_[HHMMSS].[ext]`

---

## ⏱️ Time Range Filtering

### Filter by Specific Dates
```powershell
-Start "2025-01-01" -End "2025-01-31"
```
**Use for**: Analyzing specific incident timeframe

### Filter by Hours (Working Hours)
```powershell
-Start 9 -End 17
```
**Use for**: Detecting off-hours activity

### Filter by Unix Epoch
```powershell
-Start 1704067200 -End 1735689599
```
**Use for**: Programmatic/scripted analysis

---

## 🚨 Troubleshooting Quick Fixes

### "Module not found"
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
Import-Module Microsoft.Graph
```

### "Access denied" when connecting to Entra ID
- Verify you have `AuditLog.Read.All` or `Directory.Read.All` permission
- Try running PowerShell as Administrator
- Check if Global Admin consent is required for your tenant

### "CSV file not found"
- Ensure CSV files are in the specified folder
- Check file naming matches: `SignIn_Logs_*.csv` and `Audit_Logs_*.csv`
- Verify path uses full path (not relative)

### Report not opening automatically
- Add `-Open` parameter explicitly
- Manually navigate to output folder and open HTML file
- Check default browser is configured

### No data in report
- Verify CSV files contain data (not empty)
- Check date range filters (may be excluding all data)
- Ensure user has actual sign-in/audit activity in the period

---

## 💡 Pro Tips

### Tip 1: Bookmark Critical Scores
Keep a baseline score for normal user behavior, investigate when significantly higher.

### Tip 2: Schedule Regular Runs
Create a scheduled task to run weekly analysis:
```powershell
# In Task Scheduler, set action to:
powershell.exe -File "C:\Scripts\AccountSuspiciousBehaviorChecker.ps1" -importCSVPath "C:\Logs" -Output "C:\Reports" -Start 9 -End 17
```

### Tip 3: Export from Entra Portal
For manual CSV exports:
1. Entra ID Portal → Users → Sign-in logs
2. Filter by user and date range
3. Download → CSV (all columns)
4. Repeat for Audit logs

### Tip 4: Compare Over Time
Run analysis monthly and compare scores to detect trends.

### Tip 5: Focus on High-Weight Indicators
Sign-in indicators worth 8.33% each - focus on those with 100-point scores first.

---

## 📞 Need Help?

### Before Asking for Help
1. ✅ Check you're running PowerShell 5.1+
2. ✅ Verify Microsoft.Graph module is installed
3. ✅ Confirm you have required permissions
4. ✅ Review error messages carefully
5. ✅ Try interactive mode first

### Error Message Reference

| Error | Cause | Solution |
|-------|-------|----------|
| "Cannot bind parameter" | Wrong parameter type | Check parameter format |
| "Access denied" | Insufficient permissions | Verify Entra ID roles |
| "File not found" | Invalid path | Use full paths |
| "No data to analyze" | Empty CSVs | Verify CSV content |

---

## ✅ Quick Checklist

Before running the script:
- [ ] PowerShell 5.1 or later installed
- [ ] Microsoft.Graph module installed (or will auto-install)
- [ ] Have CSV files OR Entra ID admin access
- [ ] Know your working hours for accurate off-hours detection
- [ ] Have output folder location ready

After running the script:
- [ ] Check overall risk score (top of report)
- [ ] Review red/critical indicators first
- [ ] Click cards to see detailed data
- [ ] Export specific tables if needed for further analysis
- [ ] Save report for compliance/documentation

---

## 🎓 Next Steps

After getting familiar with basic usage:

1. **Customize Thresholds**: Modify detection thresholds in script if needed for your environment
2. **Automate**: Set up scheduled tasks for regular analysis
3. **Integrate**: Export data to SIEM or ticketing system
4. **Train**: Share report interpretation with security team
5. **Refine**: Adjust working hours as organizational patterns change

---

## 📚 Additional Resources

- **Detailed Documentation**: [README.md](README.md) - Complete reference
- **Step-by-Step Guide**: [INSTRUCTIONS.md](INSTRUCTIONS.md) - Detailed walkthrough
- **Script Comments**: In-line documentation in the PowerShell script

---

**Questions?** Review the detailed [INSTRUCTIONS.md](INSTRUCTIONS.md) for comprehensive guidance.

**Last Updated**: January 4, 2026
