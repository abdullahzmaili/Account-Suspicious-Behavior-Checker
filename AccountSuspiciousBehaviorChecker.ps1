<#
    MIT License

    Copyright (c) Microsoft Corporation.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE
#>

<#
.SYNOPSIS
    A PowerShell tool for analyzing Entra ID (Azure AD) sign-in and audit logs to detect indicators of account suspicious behavior. 
    This script provides detailed risk assessment, suspicious activity detection, and generates professional HTML reports.

.DISCLAIMER
    This script has been thoroughly tested across various environments and scenarios, and all tests have passed successfully. However, by using this script, you acknowledge and agree that:
    1. You are responsible for how you use the script and any outcomes resulting from its execution.
    2. The entire risk arising out of the use or performance of the script remains with you.
    3. The author and contributors are not liable for any damages, including data loss, business interruption, or other losses, even if warned of the risks.    
    
.DESCRIPTION
    This script connects to Microsoft Graph, retrieves Entra ID sign-in logs and directory audit logs, analyzes them for indicators of suspicious behavior,
    and generates CSV and HTML reports. The script supports interactive and non-interactive modes via parameters.

.NOTES
    File Name      : EmailAuthChecker.ps1
    Author         : Abdullah Zmaili
    Version        : 1.0
    Date Created   : 2025-December-1
    Date Updated   : 2025-December-30
    
    Requirements:
    - Microsoft.Graph PowerShell module
    - Appropriate Entra ID permissions (AuditLog.Read.All or Directory.Read.All)
    - PowerShell 5.1 or later, Administrator privileges for some checks

.PARAMETER importCSVPath
    Path to an existing sign-in CSV file or folder containing CSV files to analyze.
    When provided the script will analyze existing CSV(s) instead of connecting to Graph.

.PARAMETER Output
    Folder path where exported CSVs and the generated HTML report will be saved.
    If not provided, the script will prompt for an output folder interactively.

.PARAMETER Open
    Switch. If specified, the script will attempt to open the generated HTML report automatically.

.PARAMETER EntraIDConnect
    UPN of the account to use for interactive Microsoft Graph authentication.
    When provided the script will connect to Graph, export sign-in and audit logs, and analyze them.

.PARAMETER AffectedUPN
    User Principal Name (UPN) of the target user to analyze (the affected account).
    If not provided, the script will prompt for the UPN interactively when connecting to Graph.

.PARAMETER Start
    Start of the time window. Accepts multiple formats:
      - Integer hours (0-23) to indicate working-hour start (script will treat Start/End as working hours when both are 0-23)
      - Unix epoch seconds or milliseconds
      - Date string parseable by [DateTime]::Parse (e.g., '2025-12-01' or '2025-12-01T00:00:00Z')
    When provided as dates or epoch values the script will apply date-range filters to Graph queries and CSV filtering.

.PARAMETER End
    End of the time window (same accepted formats as `-Start`). When both `-Start` and `-End` are valid 0-23 integers they are used as working hours instead of date filters.

.EXAMPLE
    .\AccountSuspiciousBehaviorChecker.ps1 -importCSVPath C:\temp\account -Output C:\temp\account -Open -Start 10 -End 13
    Analyze existing CSVs in C:\temp\account, treat 10-13 as working hours, generate an HTML report and open it.

.EXAMPLE
    .\AccountSuspiciousBehaviorChecker.ps1 -EntraIDConnect admin@contoso.onmicrosoft.com -AffectedUPN user@contoso.com -Output C:\out -Start '2025-12-01' -End '2025-12-31'
    Connect to Graph with interactive auth, export logs for the affected user, apply a date-range filter for December 2025, and save results to C:\out.

#>

param(
    [string]$importCSVPath = $null,
    [string]$Output = $null,
    [switch]$Open,
    [string]$EntraIDConnect = $null,
    [string]$AffectedUPN = $null,
    [string]$Start = $null,
    [string]$End = $null
)

#region Helper Functions

# Generate indicator disclaimer HTML
function Get-IndicatorDisclaimer {
    param(
        [string]$Icon,
        [string]$Color,
        [string]$BgColor,
        [string]$TextColor,
        [string]$Detection,
        [string]$RiskFormula,
        [string]$Weight = 'Varies by configuration',
        [string]$SecurityNote
    )
    
    $randomId = [guid]::NewGuid().ToString()
    return @"
<div style='background: $BgColor; border: 2px solid $Color; border-radius: 8px; margin-bottom: 16px; overflow: hidden;'>
    <div style='background: $Color; color: white; padding: 14px 16px; cursor: pointer; font-weight: 600; font-size: 14px; display: flex; align-items: center; justify-content: space-between;' onclick='toggleIndicatorDetails("$randomId")'>
        <div style='display: flex; align-items: center; gap: 8px;'>
            <span style='font-size: 18px;'>$Icon</span> How This Indicator is Measured
        </div>
        <button id='toggle-btn-$randomId' style='background: rgba(255,255,255,0.2); color: white; border: none; padding: 6px 12px; border-radius: 4px; font-size: 12px; cursor: pointer; font-weight: 600;'>Hide Details</button>
    </div>
    <div id='details-$randomId' style='padding: 16px; color: $TextColor;'>
        <div style='line-height: 1.9; margin-bottom: 14px;'><strong style='color: $Color;'>&#128200; Detection Method:</strong><br>$Detection</div>
        <div style='line-height: 1.9; margin-bottom: 14px;'><strong style='color: $Color;'>&#128161; Risk Calculation:</strong><br>$RiskFormula</div>
        <div style='background: $Color; color: white; padding: 16px 18px; border-radius: 8px; font-size: 13px; line-height: 1.9; box-shadow: 0 3px 8px rgba(0,0,0,0.15);'><strong style='font-size: 14px; display: block; margin-bottom: 8px;'>&#9888; Why This Matters:</strong> $SecurityNote</div>
    </div>
</div>
"@
}

# Generate detailed indicator disclaimer (for 4 main audit indicators)
function Get-DetailedIndicatorDisclaimer {
    param(
        [string]$Icon,
        [string]$Color,
        [string]$BgColor,
        [string]$TextColor,
        [string]$Detection,
        [string]$RiskFormula,
        [string]$RiskExplanation,
        [string]$Weight,
        [string]$SecurityNote
    )
    
    $randomId = [guid]::NewGuid().ToString()
    return @"
<div style='background: $BgColor; border: 2px solid $Color; border-radius: 8px; margin-bottom: 16px; overflow: hidden;'>
    <div style='background: $Color; color: white; padding: 14px 16px; cursor: pointer; font-weight: 600; font-size: 14px; display: flex; align-items: center; justify-content: space-between;' onclick='toggleIndicatorDetails("$randomId")'>
        <div style='display: flex; align-items: center; gap: 8px;'>
            <span style='font-size: 18px;'>$Icon</span> How This Indicator is Measured
        </div>
        <button id='toggle-btn-$randomId' style='background: rgba(255,255,255,0.2); color: white; border: none; padding: 6px 12px; border-radius: 4px; font-size: 12px; cursor: pointer; font-weight: 600;'>Hide Details</button>
    </div>
    <div id='details-$randomId' style='padding: 16px; color: $TextColor;'>
        <div style='line-height: 1.9; margin-bottom: 14px;'><strong style='color: $Color;'>&#128200; Detection Method:</strong><br>$Detection</div>
        <div style='line-height: 1.9; margin-bottom: 14px;'><strong style='color: $Color;'>&#128161; Risk Calculation:</strong><br>$RiskFormula<br>$RiskExplanation</div>
        <div style='background: $Color; color: white; padding: 16px 18px; border-radius: 8px; font-size: 13px; line-height: 1.9; box-shadow: 0 3px 8px rgba(0,0,0,0.15);'><strong style='font-size: 14px; display: block; margin-bottom: 8px;'>&#9888; Why This Matters:</strong> $SecurityNote</div>
    </div>
</div>
"@
}

#endregion

#region Function: Install-RequiredModules
# Function to check and install required modules
function Install-RequiredModules {
    Write-Host "Checking for required PowerShell modules..." -ForegroundColor Cyan
    
    $requiredModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Reports')
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Host "Module '$module' not found. Installing..." -ForegroundColor Yellow
            try {
                Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
                Write-Host "Module '$module' installed successfully." -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to install module '$module'. Error: $_" -ForegroundColor Red
                exit 1
            }
        }
        else {
            Write-Host "Module '$module' is already installed." -ForegroundColor Green
        }
    }
}
#endregion

# Helper: parse user-provided Start/End into UTC DateTime
function Convert-ToUtcDateTime {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    # If numeric (epoch seconds or milliseconds)
    if ($Value -match '^[0-9]+$') {
        try {
            $num = [long]$Value
            if ($num -gt 9999999999) {
                # milliseconds
                $dto = [DateTimeOffset]::FromUnixTimeMilliseconds($num)
            }
            else {
                # seconds
                $dto = [DateTimeOffset]::FromUnixTimeSeconds($num)
            }
            return $dto.UtcDateTime
        }
        catch {
            return $null
        }
    }

    # Try parse as DateTime
    try {
        $dt = [DateTime]::Parse($Value)
        return $dt.ToUniversalTime()
    }
    catch {
        return $null
    }
}

#endregion

#region Function: Get-OutputFolderPath
# Function to get folder path from user
function Get-OutputFolderPath {
    Write-Host "`nEnter the folder path where the CSV file will be saved:" -ForegroundColor Yellow
    $folderPath = Read-Host "Folder Path"
    
    # Validate the path
    if ([string]::IsNullOrWhiteSpace($folderPath)) {
        Write-Host "No folder path entered. Exiting script." -ForegroundColor Red
        exit 1
    }
    
    # Check if the path exists
    if (-not (Test-Path -Path $folderPath -PathType Container)) {
        Write-Host "The specified folder does not exist. Would you like to create it? (Y/N)" -ForegroundColor Yellow
        $createFolder = Read-Host
        
        if ($createFolder -eq 'Y' -or $createFolder -eq 'y') {
            try {
                New-Item -Path $folderPath -ItemType Directory -Force | Out-Null
                Write-Host "Folder created successfully." -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to create folder. Error: $_" -ForegroundColor Red
                exit 1
            }
        }
        else {
            Write-Host "Folder does not exist. Exiting script." -ForegroundColor Red
            exit 1
        }
    }
    
    return $folderPath
}
#endregion

#region Function: Get-RiskEventTypeMapping
# Function to map Risk Event Types v2 to their descriptions and detection types
function Get-RiskEventTypeMapping {
    return @{
        'riskyIPAddress' = @{ Description = 'Risky IP address'; DetectionType = 'Offline' }
        'adminConfirmedUserCompromised' = @{ Description = 'Admin confirmed user compromised'; DetectionType = 'Offline' }
        'anomalousToken' = @{ Description = 'Anomalous Token'; DetectionType = 'Offline' }
        'anonymizedIPAddress' = @{ Description = 'Anonymized IP address'; DetectionType = 'Real-time' }
        'unlikelyTravel' = @{ Description = 'Atypical travel'; DetectionType = 'Offline' }
        'mcasImpossibleTravel' = @{ Description = 'Impossible travel'; DetectionType = 'Offline' }
        'maliciousIPAddress' = @{ Description = 'Malicious IP address'; DetectionType = 'Offline' }
        'mcasFinSuspiciousFileAccess' = @{ Description = 'Suspicious file access'; DetectionType = 'Offline' }
        'investigationsThreatIntelligence' = @{ Description = 'Microsoft Entra threat intelligence'; DetectionType = 'Offline' }
        'newCountry' = @{ Description = 'New country'; DetectionType = 'Offline' }
        'passwordSpray' = @{ Description = 'Password spray'; DetectionType = 'Offline' }
        'suspiciousBrowser' = @{ Description = 'Suspicious browser'; DetectionType = 'Offline' }
        'suspiciousInboxForwarding' = @{ Description = 'Suspicious inbox forwarding'; DetectionType = 'Offline' }
        'mcasSuspiciousInboxManipulationRules' = @{ Description = 'Suspicious inbox manipulation rules'; DetectionType = 'Offline' }
        'tokenIssuerAnomaly' = @{ Description = 'Token Issuer Anomaly'; DetectionType = 'Offline' }
        'unfamiliarFeatures' = @{ Description = 'Unfamiliar sign-in properties'; DetectionType = 'Real-time' }
        'nationStateIP' = @{ Description = 'Nation state IP address'; DetectionType = 'Offline' }
        'anomalousUserActivity' = @{ Description = 'Anomalous user activity'; DetectionType = 'Offline' }
        'attackerinTheMiddle' = @{ Description = 'Attacker in the middle'; DetectionType = 'Real-time' }
        'leakedCredentials' = @{ Description = 'Leaked credentials'; DetectionType = 'Offline' }
        'attemptedPrtAccess' = @{ Description = 'Attempted PRT access'; DetectionType = 'Real-time' }
        'suspiciousAPITraffic' = @{ Description = 'Suspicious API traffic'; DetectionType = 'Offline' }
        'suspiciousSendingPatterns' = @{ Description = 'Suspicious sending patterns'; DetectionType = 'Offline' }
        'userReportedSuspiciousActivity' = @{ Description = 'User reported suspicious activity'; DetectionType = 'Offline' }
    }
}
#endregion

#region Function: Get-RiskEventEnrichment
# Function to enrich risk event types v2 with descriptions and detection types
function Get-RiskEventEnrichment {
    param(
        [string]$RiskEventTypesV2
    )
    
    if ([string]::IsNullOrWhiteSpace($RiskEventTypesV2)) {
        return @{ Descriptions = $null; DetectionTypes = $null }
    }
    
    $mapping = Get-RiskEventTypeMapping
    $riskTypes = $RiskEventTypesV2 -split ';' | ForEach-Object { $_.Trim() }
    
    $descriptions = @()
    $detectionTypes = @()
    
    foreach ($riskType in $riskTypes) {
        if ($mapping.ContainsKey($riskType)) {
            $descriptions += $mapping[$riskType].Description
            $detectionTypes += $mapping[$riskType].DetectionType
        }
    }
    
    return @{
        Descriptions = if ($descriptions.Count -gt 0) { ($descriptions | Select-Object -Unique) -join '; ' } else { $null }
        DetectionTypes = if ($detectionTypes.Count -gt 0) { ($detectionTypes | Select-Object -Unique) -join '; ' } else { $null }
    }
}
#endregion

#region Function: Get-WorkingHours
# Function to get working hours from user
function Get-WorkingHours {
    param(
        [int]$StartHourParam = $null,
        [int]$EndHourParam = $null
    )
    Write-Host "`n" -NoNewline
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  Configure Working Hours (UTC Timezone)" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "Off-hours activity will be calculated based on times outside your working hours." -ForegroundColor Yellow
    Write-Host "Please enter your working hours in 24-hour format (0-23)." -ForegroundColor Yellow
    Write-Host "`nExample: If you work 9 AM to 5 PM UTC, enter:" -ForegroundColor Gray
    Write-Host "  Start Hour: 9" -ForegroundColor Gray
    Write-Host "  End Hour: 17" -ForegroundColor Gray
    Write-Host "`n" -NoNewline
    
    do {
        try {
            if ($PSBoundParameters.ContainsKey('StartHourParam')) {
                $startHour = [int]$PSBoundParameters['StartHourParam']
            }
            else {
                [int]$startHour = Read-Host "Enter working hours START (0-23)"
            }
            if ($startHour -lt 0 -or $startHour -gt 23) {
                Write-Host "Invalid hour. Please enter a value between 0 and 23." -ForegroundColor Red
                continue
            }
            break
        }
        catch {
            Write-Host "Invalid input. Please enter a number between 0 and 23." -ForegroundColor Red
        }
    } while ($true)
    
    do {
        try {
            if ($PSBoundParameters.ContainsKey('EndHourParam')) {
                $endHour = [int]$PSBoundParameters['EndHourParam']
            }
            else {
                [int]$endHour = Read-Host "Enter working hours END (0-23)"
            }
            if ($endHour -lt 0 -or $endHour -gt 23) {
                Write-Host "Invalid hour. Please enter a value between 0 and 23." -ForegroundColor Red
                continue
            }
            if ($endHour -eq $startHour) {
                Write-Host "End hour cannot be the same as start hour." -ForegroundColor Red
                continue
            }
            break
        }
        catch {
            Write-Host "Invalid input. Please enter a number between 0 and 23." -ForegroundColor Red
        }
    } while ($true)
    
    Write-Host "`nWorking hours set:" -ForegroundColor Green
    Write-Host "  Start: $startHour:00 UTC" -ForegroundColor Green
    Write-Host "  End: $endHour:00 UTC" -ForegroundColor Green
    Write-Host "  Off-hours will be calculated for times outside this range." -ForegroundColor Green
    Write-Host "============================================`n" -ForegroundColor Cyan
    
    return @{
        StartHour = $startHour
        EndHour = $endHour
    }
}
#endregion

#region Function: Test-OffHours
# Function to check if a time is outside working hours
function Test-OffHours {
    param(
        [int]$Hour,
        [int]$WorkStartHour,
        [int]$WorkEndHour
    )
    
    if ($WorkStartHour -lt $WorkEndHour) {
        # Normal day shift (e.g., 9 AM to 5 PM)
        return ($Hour -lt $WorkStartHour -or $Hour -ge $WorkEndHour)
    }
    else {
        # Overnight shift (e.g., 11 PM to 7 AM)
        return ($Hour -ge $WorkEndHour -and $Hour -lt $WorkStartHour)
    }
}
#endregion


#region Function: Analyze-SignInLogs
# Function to analyze sign-in logs for indicators of suspicious behavior
function Analyze-SignInLogs {
    param (
        [Parameter(Mandatory=$true)]
        [string]$CsvFilePath,
        [Parameter(Mandatory=$true)]
        [string]$UserDisplayName,
        [Parameter(Mandatory=$true)]
        [string]$UserUPN,
        [Parameter(Mandatory=$false)]
        [hashtable]$WorkingHours = @{ StartHour = 9; EndHour = 17 }
    )
    
    # Import the CSV data
    $signInData = Import-Csv -Path $CsvFilePath
    
    if ($signInData.Count -eq 0) {
        Write-Host "No data to analyze." -ForegroundColor Yellow
        return $null
    }
    
    # Enrich data with Sign-in risk detection and Detection type if Risk Event Types v2 exists and enrichment columns don't
    if ($signInData[0].PSObject.Properties.Name -contains 'Risk Event Types v2' -and 
        $signInData[0].PSObject.Properties.Name -notcontains 'Sign-in risk detection') {
        $signInData = $signInData | ForEach-Object {
            $enrichment = Get-RiskEventEnrichment -RiskEventTypesV2 $_.'Risk Event Types v2'
            $_ | Add-Member -MemberType NoteProperty -Name 'Sign-in risk detection' -Value $enrichment.Descriptions -Force
            $_ | Add-Member -MemberType NoteProperty -Name 'Detection type' -Value $enrichment.DetectionTypes -Force
            $_
        }
    }
    
    # Initialize indicators
    # 12 total sign-in indicators = 100/12 = 8.33 per indicator
    $weightPerIndicator = [Math]::Round(100.0 / 12, 2)
    
    $indicators = @{
        'Multiple Locations' = @{ Score = 0; Weight = $weightPerIndicator; Details = @(); Count = 0 }
        'Failed/Interrupted Sign-ins' = @{ Score = 0; Weight = $weightPerIndicator; Details = @(); Count = 0 }
        'Brute-force' = @{ Score = 0; Weight = $weightPerIndicator; Details = @(); Count = 0 }
        'Password-spray' = @{ Score = 0; Weight = $weightPerIndicator; Details = @(); Count = 0 }
        'Account Lockout' = @{ Score = 0; Weight = $weightPerIndicator; Details = @(); Count = 0 }
        'Multiple IP Addresses' = @{ Score = 0; Weight = $weightPerIndicator; Details = @(); Count = 0 }
        'Risky Sign-ins' = @{ Score = 0; Weight = $weightPerIndicator; Details = @(); Count = 0 }
        'Suspicious User Agents' = @{ Score = 0; Weight = $weightPerIndicator; Details = @(); Count = 0 }
        'Off-hours Activity' = @{ Score = 0; Weight = $weightPerIndicator; Details = @(); Count = 0 }
        'Multiple Devices' = @{ Score = 0; Weight = $weightPerIndicator; Details = @(); Count = 0 }
        'Anonymous IP' = @{ Score = 0; Weight = $weightPerIndicator; Details = @(); Count = 0 }
        'Session IP Mismatch' = @{ Score = 0; Weight = $weightPerIndicator; Details = @(); Count = 0 }
    }
    
    # Analyze data
    $failedSignIns = $signInData | Where-Object { $_.'Status' -eq 'Failure' }
    $riskySignIns = $signInData | Where-Object { $_.'Risk State' -ne 'none' -and $_.'Risk State' -ne '' }
    
    # Multiple Locations - Check for 2+ unique locations within 24-hour windows
    $multipleLocationDetails = @()
    $multipleLocationRawData = @()
    
    # Sort all sign-ins by date for chronological analysis
    $sortedSignIns = $signInData | Where-Object { 
        $_.'User' -and 
        $_.'Date (UTC)' -and 
        $_.'Location - City' -and 
        $_.'Location - City' -ne '' 
    } | Sort-Object { 
        try { [DateTime]::Parse($_.'Date (UTC)') } 
        catch { [DateTime]::MinValue } 
    }
    
    $trackedLocationWindows = @{}
    
    for ($i = 0; $i -lt $sortedSignIns.Count; $i++) {
        $currentSignIn = $sortedSignIns[$i]
        
        try {
            $currentTime = [DateTime]::Parse($currentSignIn.'Date (UTC)')
            $currentLocation = ($currentSignIn.'Location - City').Trim()
            
            if ([string]::IsNullOrWhiteSpace($currentLocation)) { continue }
            
            # Use HashSet for O(1) lookups instead of O(n) array contains
            $locationsInWindow = [System.Collections.Generic.HashSet[string]]::new()
            [void]$locationsInWindow.Add($currentLocation)
            $endTime = $currentTime.AddHours(24)
            
            # Track location details (city, country) for building the detail string
            $locationDetailsMap = @{}
            $country = if ($currentSignIn.'Location - Country/Region') { $currentSignIn.'Location - Country/Region' } else { '' }
            $locationDetailsMap[$currentLocation] = $country
            
            # Check all subsequent sign-ins within 24 hours
            for ($j = $i + 1; $j -lt $sortedSignIns.Count; $j++) {
                $compareSignIn = $sortedSignIns[$j]
                
                try {
                    $compareTime = [DateTime]::Parse($compareSignIn.'Date (UTC)')
                    $compareLocation = ($compareSignIn.'Location - City').Trim()
                    
                    if ([string]::IsNullOrWhiteSpace($compareLocation)) { continue }
                    
                    # Stop if we've gone past 24 hours
                    if ($compareTime -gt $endTime) { break }
                    
                    # Add unique locations to the HashSet (automatically handles uniqueness)
                    if (-not $locationsInWindow.Contains($compareLocation)) {
                        [void]$locationsInWindow.Add($compareLocation)
                        $compareCountry = if ($compareSignIn.'Location - Country/Region') { $compareSignIn.'Location - Country/Region' } else { '' }
                        $locationDetailsMap[$compareLocation] = $compareCountry
                    }
                }
                catch {
                    continue
                }
            }
            
            # Flag if 2 or more unique locations found in this 24-hour window
            if ($locationsInWindow.Count -ge 2) {
                # Create unique key to avoid duplicate windows - convert HashSet to sorted array for consistent key
                $sortedLocations = $locationsInWindow | Sort-Object
                $windowKey = "$($currentTime.ToString('yyyy-MM-dd HH:mm:ss'))|$($sortedLocations -join ',')"
                
                if (-not $trackedLocationWindows.ContainsKey($windowKey)) {
                    $trackedLocationWindows[$windowKey] = $true
                    
                    # Build location list with format "City, Country"
                    $locationListParts = @()
                    foreach ($loc in $sortedLocations) {
                        $countryCode = $locationDetailsMap[$loc]
                        if ($countryCode) {
                            $locationListParts += "$loc, $countryCode"
                        } else {
                            $locationListParts += $loc
                        }
                    }
                    $locationList = $locationListParts -join ' and '
                    
                    $detail = "User: $($currentSignIn.'User') - Used $($locationsInWindow.Count) different locations within 24 hours starting $($currentSignIn.'Date (UTC)') - locations: $locationList"
                    $multipleLocationDetails += $detail
                    
                    # Store sign-ins from different locations in this window
                    for ($k = $i; $k -lt $sortedSignIns.Count; $k++) {
                        try {
                            $checkTime = [DateTime]::Parse($sortedSignIns[$k].'Date (UTC)')
                            if ($checkTime -le $endTime) {
                                $checkLocation = ($sortedSignIns[$k].'Location - City').Trim()
                                if ($locationsInWindow -contains $checkLocation) {
                                    $multipleLocationRawData += $sortedSignIns[$k]
                                }
                            } else { break }
                        } catch { continue }
                    }
                }
            }
        }
        catch {
            continue
        }
    }
    
    if ($multipleLocationDetails.Count -gt 0) {
        # Score based on number of 24-hour windows with multiple locations (30 points per incident, capped at 100)
        $indicators['Multiple Locations'].Score = [Math]::Min(100, $multipleLocationDetails.Count * 30)
        $indicators['Multiple Locations'].Count = $multipleLocationDetails.Count
        $indicators['Multiple Locations'].Details = $multipleLocationDetails
        # Store raw data for table display
        $indicators['Multiple Locations'].RawData = $multipleLocationRawData | Select-Object 'Date (UTC)', 'IP address', 'User', 'Application', 'Location - City', 'Status', 'Location - Country/Region' | Sort-Object 'Date (UTC)' -Descending
    }
    
    # Failed / Interrupted Sign-ins
    $failedAndInterruptedSignIns = $signInData | Where-Object { $_.'Status' -in @('Failure','Interrupted') }
    if ($failedAndInterruptedSignIns.Count -gt 0) {
        $failureRate = ($failedAndInterruptedSignIns.Count / $signInData.Count) * 100
        $indicators['Failed/Interrupted Sign-ins'].Score = [Math]::Min(100, $failureRate * 2)
        $indicators['Failed/Interrupted Sign-ins'].Count = $failedAndInterruptedSignIns.Count
        $indicators['Failed/Interrupted Sign-ins'].Details = $failedAndInterruptedSignIns | Select-Object -ExpandProperty 'Failure reason' | Where-Object { $_ }
        # Store raw data for table display
        $indicators['Failed/Interrupted Sign-ins'].RawData = $failedAndInterruptedSignIns | Select-Object 'Date (UTC)', 'IP address', 'User', 'Application', 'Failure reason', 'Sign-in error code', 'Status', 'Location - City' | Sort-Object 'Date (UTC)' -Descending
    }
    
    # Brute-force/Password-spray Detection
    $bruteForceDetails = [System.Collections.ArrayList]::new()
    $passwordSprayDetails = [System.Collections.ArrayList]::new()
    $bruteForceRawData = [System.Collections.ArrayList]::new()
    $passwordSprayRawData = [System.Collections.ArrayList]::new()
    
    if ($failedSignIns.Count -gt 0) {
        # Filter failures with error code 50126 (invalid username or password)
        $failed50126 = $failedSignIns | Where-Object { $_.'Sign-in error code' -eq '50126' }
        
        # Detect brute-force: 10+ failures with error code 50126 within 10 minutes
        if ($failed50126.Count -ge 10) {
            # Sort by time
            $sortedFailed50126 = $failed50126 | Sort-Object { [DateTime]$_.'Date (UTC)' }
            
            # Use sliding window approach to find clusters
            for ($i = 0; $i -lt $sortedFailed50126.Count - 9; $i++) {
                try {
                    $windowStart = [DateTime]$sortedFailed50126[$i].'Date (UTC)'
                    $windowEnd = $windowStart.AddMinutes(10)
                    
                    # Count failures within this 10-minute window - use ArrayList for performance
                    $failuresInWindow = [System.Collections.ArrayList]::new()
                    $uniqueIPsSet = [System.Collections.Generic.HashSet[string]]::new()
                    
                    for ($j = $i; $j -lt $sortedFailed50126.Count; $j++) {
                        $failTime = [DateTime]$sortedFailed50126[$j].'Date (UTC)'
                        if ($failTime -le $windowEnd) {
                            [void]$failuresInWindow.Add($sortedFailed50126[$j])
                            $failIP = ($sortedFailed50126[$j].'IP address').Trim()
                            if ($failIP) {
                                [void]$uniqueIPsSet.Add($failIP)
                            }
                        } else {
                            break
                        }
                    }
                    
                    # If 10+ failures with error code 50126 within 10 minutes, it's brute-force
                    if ($failuresInWindow.Count -ge 10) {
                        $actualTimeSpan = ([DateTime]$failuresInWindow[-1].'Date (UTC)' - [DateTime]$failuresInWindow[0].'Date (UTC)').TotalMinutes
                        $detail = "Brute-force attack detected: $($failuresInWindow.Count) failures (error code 50126) from $($uniqueIPsSet.Count) IP(s) in $([Math]::Round($actualTimeSpan, 1)) minutes (Start: $windowStart)"
                        
                        # Avoid duplicate detections by skipping overlapping windows
                        if ($bruteForceDetails -notcontains $detail) {
                            [void]$bruteForceDetails.Add($detail)
                            # Store all events from this window for display
                            foreach ($item in $failuresInWindow) { [void]$bruteForceRawData.Add($item) }
                            $i += 9  # Skip ahead to avoid overlapping windows
                        }
                    }
                }
                catch {
                    continue
                }
            }
        }
        
        # Detect password spray: 10+ failures with error code 50126 within 1 hour
        if ($failed50126.Count -ge 10) {
            # Sort by time
            $sortedFailed50126 = $failed50126 | Sort-Object { [DateTime]$_.'Date (UTC)' }
            
            # Use sliding window approach to find clusters
            for ($i = 0; $i -lt $sortedFailed50126.Count - 9; $i++) {
                try {
                    $windowStart = [DateTime]$sortedFailed50126[$i].'Date (UTC)'
                    $windowEnd = $windowStart.AddMinutes(60)
                    
                    # Count failures within this 60-minute window - use ArrayList for performance
                    $failuresInWindow = [System.Collections.ArrayList]::new()
                    $uniqueIPsSet = [System.Collections.Generic.HashSet[string]]::new()
                    
                    for ($j = $i; $j -lt $sortedFailed50126.Count; $j++) {
                        $failTime = [DateTime]$sortedFailed50126[$j].'Date (UTC)'
                        if ($failTime -le $windowEnd) {
                            [void]$failuresInWindow.Add($sortedFailed50126[$j])
                            $failIP = ($sortedFailed50126[$j].'IP address').Trim()
                            if ($failIP) {
                                [void]$uniqueIPsSet.Add($failIP)
                            }
                        } else {
                            break
                        }
                    }
                    
                    # If 10+ failures with error code 50126 within 1 hour, it's password spray
                    if ($failuresInWindow.Count -ge 10) {
                        $actualTimeSpan = ([DateTime]$failuresInWindow[-1].'Date (UTC)' - [DateTime]$failuresInWindow[0].'Date (UTC)').TotalMinutes
                        $detail = "Password spray attack detected: $($failuresInWindow.Count) failures (error code 50126) from $($uniqueIPsSet.Count) IP(s) in $([Math]::Round($actualTimeSpan, 1)) minutes (Start: $windowStart)"
                        
                        # Avoid duplicate detections by skipping overlapping windows
                        if ($passwordSprayDetails -notcontains $detail) {
                            [void]$passwordSprayDetails.Add($detail)
                            # Store all events from this window for display
                            foreach ($item in $failuresInWindow) { [void]$passwordSprayRawData.Add($item) }
                            $i += 9  # Skip ahead to avoid overlapping windows
                        }
                    }
                }
                catch {
                    continue
                }
            }
        }
    }
    
    # Calculate scores separately for each attack type
    if ($bruteForceDetails.Count -gt 0) {
        $bruteForceScore = [Math]::Min(100, $bruteForceDetails.Count * 50)
        $indicators['Brute-force'].Score = $bruteForceScore
        $indicators['Brute-force'].Count = $bruteForceDetails.Count
        $indicators['Brute-force'].Details = $bruteForceDetails
        # Store ALL events with error code 50126 for table display (not just those in detected windows)
        $indicators['Brute-force'].RawData = $failed50126 | Select-Object 'Date (UTC)', 'IP address', 'User', 'Application', 'Failure reason', 'Sign-in error code', 'Status', 'Location - City' | Sort-Object 'Date (UTC)' -Descending
    }
    
    if ($passwordSprayDetails.Count -gt 0) {
        $passwordSprayScore = [Math]::Min(100, $passwordSprayDetails.Count * 50)
        $indicators['Password-spray'].Score = $passwordSprayScore
        $indicators['Password-spray'].Count = $passwordSprayDetails.Count
        $indicators['Password-spray'].Details = $passwordSprayDetails
        # Store ALL events with error code 50126 for table display (not just those in detected windows)
        $indicators['Password-spray'].RawData = $failed50126 | Select-Object 'Date (UTC)', 'IP address', 'User', 'Application', 'Failure reason', 'Sign-in error code', 'Status', 'Location - City' | Sort-Object 'Date (UTC)' -Descending
    }
    
    # Account Lockout Detection: 3+ failures with error code 50053 within 24 hours
    $lockoutDetails = @()
    $lockoutRawData = @()
    $failed50053 = $failedSignIns | Where-Object { $_.'Sign-in error code' -eq '50053' }
    
    if ($failed50053.Count -gt 3) {
        # Sort by time
        $sortedFailed50053 = $failed50053 | Sort-Object { [DateTime]$_.'Date (UTC)' }
        
        # Use sliding window approach to find clusters within 24 hours
        for ($i = 0; $i -lt $sortedFailed50053.Count - 2; $i++) {
            try {
                $windowStart = [DateTime]$sortedFailed50053[$i].'Date (UTC)'
                $windowEnd = $windowStart.AddHours(24)
                
                # Count failures within this 24-hour window
                $failuresInWindow = @()
                $uniqueIPs = @()
                
                for ($j = $i; $j -lt $sortedFailed50053.Count; $j++) {
                    $failTime = [DateTime]$sortedFailed50053[$j].'Date (UTC)'
                    if ($failTime -le $windowEnd) {
                        $failuresInWindow += $sortedFailed50053[$j]
                        $failIP = ($sortedFailed50053[$j].'IP address').Trim()
                        if ($failIP -and $uniqueIPs -notcontains $failIP) {
                            $uniqueIPs += $failIP
                        }
                    } else {
                        break
                    }
                }
                
                # If more than 3 lockout failures within 24 hours, it's a risk
                if ($failuresInWindow.Count -gt 3) {
                    $actualTimeSpan = ([DateTime]$failuresInWindow[-1].'Date (UTC)' - [DateTime]$failuresInWindow[0].'Date (UTC)').TotalMinutes
                    $ipList = $uniqueIPs -join ', '
                    $detail = "Account lockout detected: $($failuresInWindow.Count) lockout failures (error code 50053) from $($uniqueIPs.Count) IP(s) in $([Math]::Round($actualTimeSpan, 1)) minutes (Start: $windowStart) - IPs: $ipList"
                    
                    # Avoid duplicate detections
                    if ($lockoutDetails -notcontains $detail) {
                        $lockoutDetails += $detail
                        # Store the first few events from this window for display
                        $lockoutRawData += $failuresInWindow | Select-Object -First 5
                        $i += 2  # Skip ahead to avoid overlapping windows
                    }
                }
            }
            catch {
                continue
            }
        }
    }
    
    if ($lockoutDetails.Count -gt 0) {
        $lockoutScore = [Math]::Min(100, $lockoutRawData.Count * 40)
        $indicators['Account Lockout'].Score = $lockoutScore
        $indicators['Account Lockout'].Count = $lockoutRawData.Count
        $indicators['Account Lockout'].Details = $lockoutDetails
        # Store raw data for table display
        $indicators['Account Lockout'].RawData = $lockoutRawData | Select-Object 'Date (UTC)', 'IP address', 'User', 'Application', 'Failure reason', 'Sign-in error code', 'Status', 'Location - City'
    }
    
    # Multiple IP Addresses - Check for 2+ unique IPs within 24-hour windows
    $multipleIPDetails = @()
    $multipleIPRawData = @()
    
    # Sort all sign-ins by date for chronological analysis
    $sortedSignIns = $signInData | Where-Object { 
        $_.'User' -and 
        $_.'Date (UTC)' -and 
        $_.'IP address' -and 
        $_.'IP address' -ne '' 
    } | Sort-Object { 
        try { [DateTime]::Parse($_.'Date (UTC)') } 
        catch { [DateTime]::MinValue } 
    }
    
    $trackedWindows = @{}
    
    for ($i = 0; $i -lt $sortedSignIns.Count; $i++) {
        $currentSignIn = $sortedSignIns[$i]
        
        try {
            $currentTime = [DateTime]::Parse($currentSignIn.'Date (UTC)')
            $currentIP = ($currentSignIn.'IP address').Trim()
            
            if ([string]::IsNullOrWhiteSpace($currentIP)) { continue }
            
            # Use HashSet for O(1) lookups instead of O(n) array contains
            $ipsInWindow = [System.Collections.Generic.HashSet[string]]::new()
            [void]$ipsInWindow.Add($currentIP)
            $endTime = $currentTime.AddHours(24)
            
            # Check all subsequent sign-ins within 24 hours
            for ($j = $i + 1; $j -lt $sortedSignIns.Count; $j++) {
                $compareSignIn = $sortedSignIns[$j]
                
                try {
                    $compareTime = [DateTime]::Parse($compareSignIn.'Date (UTC)')
                    $compareIP = ($compareSignIn.'IP address').Trim()
                    
                    if ([string]::IsNullOrWhiteSpace($compareIP)) { continue }
                    
                    # Stop if we've gone past 24 hours
                    if ($compareTime -gt $endTime) { break }
                    
                    # Add unique IPs to the HashSet (automatically handles uniqueness)
                    [void]$ipsInWindow.Add($compareIP)
                }
                catch {
                    continue
                }
            }
            
            # Flag if 2 or more unique IPs found in this 24-hour window
            if ($ipsInWindow.Count -ge 2) {
                # Create unique key to avoid duplicate windows - convert HashSet to sorted array for consistent key
                $sortedIPs = $ipsInWindow | Sort-Object
                $windowKey = "$($currentTime.ToString('yyyy-MM-dd HH:mm:ss'))|$($sortedIPs -join ',')"
                
                if (-not $trackedWindows.ContainsKey($windowKey)) {
                    $trackedWindows[$windowKey] = $true
                    $ipList = $ipsInWindow -join ', '
                    $detail = "User: $($currentSignIn.'User') - Used $($ipsInWindow.Count) different IPs within 24 hours starting $($currentSignIn.'Date (UTC)') - IPs: $ipList"
                    $multipleIPDetails += $detail
                    
                    # Store sign-ins from different IPs in this window (limit to first 10 per window)
                    for ($k = $i; $k -lt $sortedSignIns.Count; $k++) {
                        try {
                            $checkTime = [DateTime]::Parse($sortedSignIns[$k].'Date (UTC)')
                            if ($checkTime -le $endTime) {
                                $checkIP = ($sortedSignIns[$k].'IP address').Trim()
                                if ($ipsInWindow -contains $checkIP) {
                                    $multipleIPRawData += $sortedSignIns[$k]
                                }
                            } else { break }
                        } catch { continue }
                    }
                }
            }
        }
        catch {
            continue
        }
    }
    
    if ($multipleIPDetails.Count -gt 0) {
        # Score based on number of 24-hour windows with multiple IPs (30 points per incident, capped at 100)
        $indicators['Multiple IP Addresses'].Score = [Math]::Min(100, $multipleIPDetails.Count * 30)
        $indicators['Multiple IP Addresses'].Count = $multipleIPDetails.Count
        $indicators['Multiple IP Addresses'].Details = $multipleIPDetails
        # Store raw data for table display
        $indicators['Multiple IP Addresses'].RawData = $multipleIPRawData | Select-Object 'Date (UTC)', 'IP address', 'Location - City', 'Status'
    }
    
    # Risky Sign-ins
    if ($riskySignIns.Count -gt 0) {
        $indicators['Risky Sign-ins'].Score = 100
        $indicators['Risky Sign-ins'].Count = $riskySignIns.Count
        # Store raw data for table display in HTML report
        $indicators['Risky Sign-ins'].RawData = $riskySignIns | Select-Object 'Date (UTC)', 'IP address', 'User', 'Application', 'Location - City', 'Status', 'Risk State', 'Risk Detail', 'Risk Level Aggregated', 'Risk Event Types v2', 'Sign-in risk detection', 'Detection type'
        $riskDetails = $riskySignIns | Select-Object 'Date (UTC)', 'Risk State', 'Risk Detail', 'Risk Level Aggregated', 'Risk Event Types v2', 'Sign-in risk detection', 'Detection type', 'IP address', 'Location - City' | ForEach-Object {
            $riskDetection = if ($_.'Sign-in risk detection') { $_.'Sign-in risk detection' } else { 'N/A' }
            $detectionType = if ($_.'Detection type') { $_.'Detection type' } else { 'N/A' }
            $timestamp = if ($_.'Date (UTC)') { $_.'Date (UTC)' } else { 'N/A' }
            $ipAddress = if ($_.'IP address') { $_.'IP address' } else { 'N/A' }
            $location = if ($_.'Location - City') { $_.'Location - City' } else { 'N/A' }
            "[Time: $timestamp] [IP: $ipAddress] [Location: $location] State: $($_.'Risk State'), Level: $($_.'Risk Level Aggregated'), Detail: $($_.'Risk Detail') | Risk Detection: $riskDetection | Detection Type: $detectionType"
        }
        $indicators['Risky Sign-ins'].Details = $riskDetails
    }
    
    # Suspicious User Agents
    $suspiciousAgents = $signInData | Where-Object { 
        $_.'User agent' -match 'curl|wget|python|bot|scanner' -or 
        [string]::IsNullOrWhiteSpace($_.'User agent')
    }
    if ($suspiciousAgents.Count -gt 0) {
        $indicators['Suspicious User Agents'].Score = [Math]::Min(100, $suspiciousAgents.Count * 30)
        $indicators['Suspicious User Agents'].Count = $suspiciousAgents.Count
        $indicators['Suspicious User Agents'].Details = $suspiciousAgents | Select-Object -ExpandProperty 'User agent' -Unique
        # Store raw data for table display
        $indicators['Suspicious User Agents'].RawData = $suspiciousAgents | Select-Object 'Date (UTC)', 'IP address', 'User', 'Application', 'User agent', 'Status', 'Location - City' | Sort-Object 'Date (UTC)' -Descending
    }
    
    # Anonymous IP or TOR
    # First check Entra ID risk fields (if available)
    $anonymousIPs = $signInData | Where-Object { 
        ($_.'Risk Event Types v2' -match 'anonymousIP' -or 
         $_.'Risk Detail' -match 'anonymous') -or
        # Also check for common indicators in IP or location data
        ($_.'IP address' -match '^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\.' -and $_.'Location' -eq '') -or
        ($_.'Location' -match 'Anonymous|Proxy|VPN|TOR') -or
        # Check if ISP/Network info suggests proxy/VPN (if available in custom fields)
        ($_.'Network' -match 'VPN|Proxy|Anonymous|TOR|Hosting')
    }
    if ($anonymousIPs.Count -gt 0) {
        $indicators['Anonymous IP'].Score = 100
        $indicators['Anonymous IP'].Count = $anonymousIPs.Count
        $indicators['Anonymous IP'].Details = $anonymousIPs | Select-Object -ExpandProperty 'IP address' -Unique
        # Store raw data for table display
        $indicators['Anonymous IP'].RawData = $anonymousIPs | Select-Object 'Date (UTC)', 'IP address', 'User', 'Application', 'Location - City', 'Status' | Sort-Object 'Date (UTC)' -Descending
    }
    
    # Multiple Locations - Check for 2+ unique countries
    $multipleLocationDetails = @()
    $multipleLocationRawData = @()
    $countrySignIns = $signInData | Where-Object { $_.'Location - Country/Region' -and $_.'Location - Country/Region' -ne '' }
    
    if ($countrySignIns.Count -gt 0) {
        # Get unique countries
        $uniqueCountries = $countrySignIns | Select-Object -ExpandProperty 'Location - Country/Region' -Unique
        
        if ($uniqueCountries.Count -ge 2) {
            # Sort sign-ins by date to get start and end times
            $sortedCountrySignIns = $countrySignIns | Sort-Object { 
                try { [DateTime]::Parse($_.'Date (UTC)') } 
                catch { [DateTime]::MinValue } 
            }
            
            $startDate = $sortedCountrySignIns[0].'Date (UTC)'
            $endDate = $sortedCountrySignIns[-1].'Date (UTC)'
            $userName = if ($sortedCountrySignIns[0].'User') { $sortedCountrySignIns[0].'User' } else { 'Unknown User' }
            
            # Build the country list
            $countryList = $uniqueCountries -join ', '
            
            # Create the detail string
            $detail = "User: $userName - Accessed from $($uniqueCountries.Count) different countries starting $startDate - ending $endDate Countries: $countryList"
            $multipleLocationDetails += $detail
            
            # Set indicator values
            $indicators['Multiple Locations'].Score = [Math]::Min(100, ($uniqueCountries.Count - 1) * 30)
            $indicators['Multiple Locations'].Count = $uniqueCountries.Count
            $indicators['Multiple Locations'].Details = $multipleLocationDetails
            # Store raw data for table display
            $indicators['Multiple Locations'].RawData = $countrySignIns | Select-Object 'Date (UTC)', 'IP address', 'User', 'Application', 'Location - City', 'Location - Country/Region', 'Status' | Sort-Object 'Date (UTC)' -Descending
        }
    }
    
    # Off-hours Activity (based on user's working hours)
    $offHoursDetails = @()
    # Only consider successful sign-ins for Off-hours Activity scoring
    $offHoursSignIns = $signInData | Where-Object {
        if ($_.'Date (UTC)' -and $_.'Status' -and $_.'Status' -eq 'Success') {
            $hour = ([DateTime]$_.'Date (UTC)').Hour
            Test-OffHours -Hour $hour -WorkStartHour $WorkingHours.StartHour -WorkEndHour $WorkingHours.EndHour
        }
    }

    if ($offHoursSignIns.Count -gt 0) {
        # Collect detailed information about off-hours successful sign-ins
        foreach ($signIn in $offHoursSignIns) {
            $location = if ($signIn.'Location - City' -and $signIn.'Location - Country/Region') {
                "$($signIn.'Location - City'), $($signIn.'Location - Country/Region')"
            } elseif ($signIn.'Location - City') {
                $signIn.'Location - City'
            } elseif ($signIn.'Location - Country/Region') {
                $signIn.'Location - Country/Region'
            } else {
                "Unknown Location"
            }

            $detail = "Off-hours successful sign-in at $($signIn.'Date (UTC)') from $location - $($signIn.'IP address')"
            $offHoursDetails += $detail
        }

        # New simplified scoring: 2+ successful off-hours sign-ins = 100, 1 = 50, else 0
        if ($offHoursSignIns.Count -ge 2) {
            $score = 100
        } elseif ($offHoursSignIns.Count -eq 1) {
            $score = 50
        } else {
            $score = 0
        }

        $indicators['Off-hours Activity'].Score = $score
        $indicators['Off-hours Activity'].Count = $offHoursSignIns.Count
        $indicators['Off-hours Activity'].Details = $offHoursDetails
        # Store raw data for table display
        $indicators['Off-hours Activity'].RawData = $offHoursSignIns | Select-Object 'Date (UTC)', 'IP address', 'User', 'Application', 'Location - City', 'Status' | Sort-Object 'Date (UTC)' -Descending
    }
    
    # Multiple Devices - Check for 2+ unique Operating Systems
    $osSignIns = $signInData | Where-Object { $_.'Operating System' -and $_.'Operating System' -ne '' }
    
    if ($osSignIns.Count -gt 0) {
        # Get unique Operating Systems
        $uniqueOS = $osSignIns | Select-Object -ExpandProperty 'Operating System' -Unique
        
        if ($uniqueOS.Count -ge 2) {
            # Sort sign-ins by date to get start and end times
            $sortedOSSignIns = $osSignIns | Sort-Object { 
                try { [DateTime]::Parse($_.'Date (UTC)') } 
                catch { [DateTime]::MinValue } 
            }
            
            $startDate = $sortedOSSignIns[0].'Date (UTC)'
            $endDate = $sortedOSSignIns[-1].'Date (UTC)'
            $userName = if ($sortedOSSignIns[0].'User') { $sortedOSSignIns[0].'User' } else { 'Unknown User' }
            
            # Build the OS list
            $osList = $uniqueOS -join ', '
            
            # Create the detail string
            $detail = "User: $userName - Used $($uniqueOS.Count) different OSs starting $startDate - ending $endDate OSs: $osList"
            
            # Set indicator values
            $indicators['Multiple Devices'].Score = [Math]::Min(100, ($uniqueOS.Count - 1) * 30)
            $indicators['Multiple Devices'].Count = $uniqueOS.Count
            $indicators['Multiple Devices'].Details = @($detail)
            # Store raw data for table display
            $indicators['Multiple Devices'].RawData = $osSignIns | Select-Object 'Date (UTC)', 'IP address', 'User', 'Application', 'Operating System', 'Status', 'Location - City' | Sort-Object 'Date (UTC)' -Descending
        }
    }
    
    # Check for Session IP Mismatch (different IPs with same session ID)
    $sessionIPMismatch = @()
    $sessionIPMismatchRawData = @()
    $sessionGroups = $signInData | Where-Object { $_.'Session ID' -and $_.'Session ID' -ne '' } | Group-Object -Property 'Session ID'
    
    foreach ($session in $sessionGroups) {
        $uniqueIPsInSession = $session.Group | Where-Object { $_.'IP address' } | Select-Object -ExpandProperty 'IP address' -Unique
        
        if ($uniqueIPsInSession.Count -gt 1) {
            $sessionIPMismatch += $session
            $user = ($session.Group | Select-Object -First 1).'User'
            $ipList = $uniqueIPsInSession -join ', '
            $timestamp = ($session.Group | Select-Object -First 1).'Date (UTC)'
            
            $indicators['Session IP Mismatch'].Details += "Session ID: $($session.Name) - User: $user - Different IPs: $ipList (First seen: $timestamp)"
            # Store sign-ins from this session for display
            $sessionIPMismatchRawData += $session.Group
        }
    }
    
    if ($sessionIPMismatch.Count -gt 0) {
        # Score based on number of sessions with IP mismatches (indicates session hijacking)
        $indicators['Session IP Mismatch'].Score = [Math]::Min(100, $sessionIPMismatch.Count * 30)
        $indicators['Session IP Mismatch'].Count = $sessionIPMismatch.Count
        # Store raw data for table display
        $indicators['Session IP Mismatch'].RawData = $sessionIPMismatchRawData | Select-Object 'Date (UTC)', 'IP address', 'Session ID', 'Location - City' | Sort-Object 'Date (UTC)' -Descending
    }
    
    # Calculate overall risk score (weighted average)
    $totalWeightedScore = 0
    $totalWeight = 0
    
    foreach ($indicator in $indicators.GetEnumerator()) {
        $weightedScore = ($indicator.Value.Score * $indicator.Value.Weight) / 100
        $totalWeightedScore += $weightedScore
        $totalWeight += $indicator.Value.Weight
    }
    
    $overallScore = [Math]::Round(($totalWeightedScore / $totalWeight) * 100, 2)
    
    # Calculate success/failure/interrupted percentages
    $successfulSignIns = $signInData | Where-Object { $_.'Status' -eq 'Success' }
    $interruptedSignIns = $signInData | Where-Object { $_.'Status' -eq 'Interrupted' }
    $successPercentage = if ($signInData.Count -gt 0) { [Math]::Round(($successfulSignIns.Count / $signInData.Count) * 100, 1) } else { 0 }
    $failurePercentage = if ($signInData.Count -gt 0) { [Math]::Round(($failedSignIns.Count / $signInData.Count) * 100, 1) } else { 0 }
    $interruptedPercentage = if ($signInData.Count -gt 0) { [Math]::Round(($interruptedSignIns.Count / $signInData.Count) * 100, 1) } else { 0 }
    
    # Build detailed lists for modals (calculate these before the return statement)
    $detailedLocationsList = $signInData | Where-Object { $_.'Location - Country/Region' } | 
        Group-Object 'Location - Country/Region' | ForEach-Object {
            $country = $_.Name
            $firstEvent = $_.Group | Sort-Object { [DateTime]$_.'Date (UTC)' } | Select-Object -First 1
            [PSCustomObject]@{
                Country = $country
                Timestamp = $firstEvent.'Date (UTC)'
                Status = $firstEvent.'Status'
                User = $firstEvent.'User'
                Application = $firstEvent.'Application'
                City = $firstEvent.'Location - City'
                Count = $_.Count
            }
        }
    
    $detailedIPsList = $signInData | Where-Object { $_.'IP address' } | 
        Group-Object 'IP address' | ForEach-Object {
            $ipAddress = $_.Name
            $firstEvent = $_.Group | Sort-Object { [DateTime]$_.'Date (UTC)' } | Select-Object -First 1
            @{
                IPAddress = $ipAddress
                Timestamp = $firstEvent.'Date (UTC)'
                Status = $firstEvent.'Status'
                User = $firstEvent.'User'
                Application = $firstEvent.'Application'
                City = $firstEvent.'Location - City'
                Country = $firstEvent.'Location - Country/Region'
                Count = $_.Count
            }
        }
    
    $detailedSessionIdsList = $signInData | Where-Object { $_.'Session ID' -and $_.'Session ID' -ne '' } | 
        Group-Object 'Session ID' | ForEach-Object {
            $sessionId = $_.Name
            $firstEvent = $_.Group | Sort-Object { [DateTime]$_.'Date (UTC)' } | Select-Object -First 1
            @{
                SessionID = $sessionId
                Timestamp = $firstEvent.'Date (UTC)'
                Status = $firstEvent.'Status'
                User = $firstEvent.'User'
                Application = $firstEvent.'Application'
                City = $firstEvent.'Location - City'
                Count = $_.Count
            }
        }
    
    $detailedApplicationsList = $signInData | Where-Object { $_.'Application' } | 
        Group-Object 'Application' | ForEach-Object {
            $appName = $_.Name
            $firstEvent = $_.Group | Sort-Object { [DateTime]$_.'Date (UTC)' } | Select-Object -First 1
            @{
                Application = $appName
                Timestamp = $firstEvent.'Date (UTC)'
                Status = $firstEvent.'Status'
                User = $firstEvent.'User'
                City = $firstEvent.'Location - City'
                Count = $_.Count
            }
        }
    
    $detailedClientAppsList = $signInData | Where-Object { $_.'Client app' } | 
        Group-Object 'Client app' | ForEach-Object {
            $clientApp = $_.Name
            $firstEvent = $_.Group | Sort-Object { [DateTime]$_.'Date (UTC)' } | Select-Object -First 1
            @{
                ClientApp = $clientApp
                Timestamp = $firstEvent.'Date (UTC)'
                Status = $firstEvent.'Status'
                User = $firstEvent.'User'
                Application = $firstEvent.'Application'
                City = $firstEvent.'Location - City'
                Count = $_.Count
            }
        }
    
    $detailedResourcesList = $signInData | Where-Object { $_.'Resource' -or $_.'Resource ID' } | 
        Group-Object 'Resource' | ForEach-Object {
            $resource = $_.Name
            $firstEvent = $_.Group | Sort-Object { [DateTime]$_.'Date (UTC)' } | Select-Object -First 1
            @{
                Resource = $resource
                Timestamp = $firstEvent.'Date (UTC)'
                Status = $firstEvent.'Status'
                User = $firstEvent.'User'
                Application = $firstEvent.'Application'
                City = $firstEvent.'Location - City'
                Count = $_.Count
            }
        }
    
    $detailedOperatingSystemsList = $signInData | Where-Object { $_.'Operating System' } | 
        Group-Object 'Operating System' | ForEach-Object {
            $os = $_.Name
            $firstEvent = $_.Group | Sort-Object { [DateTime]$_.'Date (UTC)' } | Select-Object -First 1
            @{
                OperatingSystem = $os
                Timestamp = $firstEvent.'Date (UTC)'
                Status = $firstEvent.'Status'
                User = $firstEvent.'User'
                Application = $firstEvent.'Application'
                City = $firstEvent.'Location - City'
                Count = $_.Count
            }
        }
    
    return @{
        OverallScore = $overallScore
        Indicators = $indicators
        TotalSignIns = $signInData.Count
        SuccessfulSignIns = $successfulSignIns.Count
        SuccessPercentage = $successPercentage
        FailurePercentage = $failurePercentage
        InterruptedSignIns = $interruptedSignIns.Count
        InterruptedPercentage = $interruptedPercentage
        UniqueCountries = if ($detailedLocationsList) { $detailedLocationsList.Count } else { 0 }
        UniqueIPs = if ($detailedIPsList) { $detailedIPsList.Count } else { 0 }
        FailedSignIns = $failedSignIns.Count
        UniqueSessionIds = if ($detailedSessionIdsList) { $detailedSessionIdsList.Count } else { 0 }
        UniqueApplications = if ($detailedApplicationsList) { $detailedApplicationsList.Count } else { 0 }
        UniqueClientApps = if ($detailedClientAppsList) { $detailedClientAppsList.Count } else { 0 }
        UniqueResources = if ($detailedResourcesList) { $detailedResourcesList.Count } else { 0 }
        UniqueOperatingSystems = if ($detailedOperatingSystemsList) { $detailedOperatingSystemsList.Count } else { 0 }
        OffHoursSignIns = if ($offHoursSignIns) { $offHoursSignIns.Count } else { 0 }
        UserDisplayName = $UserDisplayName
        UserUPN = $UserUPN
        AnalysisDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        # Detailed lists for modal windows
        LocationsList = $detailedLocationsList
        LocationsRaw = $signInData | Where-Object { $_.'Location - Country/Region' -or $_.'Location - City' } | Select-Object 'Date (UTC)', 'User', 'Application', 'IP address', 'Location - City', 'Location - Country/Region', 'Status'
        IPsList = $detailedIPsList
        IPsRaw = $signInData | Where-Object { $_.'IP address' } | Select-Object 'Date (UTC)', 'User', 'Application', 'IP address', 'Location - City', 'Location - Country/Region', 'Status'
        SessionIdsList = $detailedSessionIdsList
        SessionIdsRaw = $signInData | Where-Object { $_.'Session ID' -and $_.'Session ID' -ne '' } | Select-Object 'Date (UTC)', 'User', 'Application', 'Session ID', 'Status', 'Location - City'
        ApplicationsList = $detailedApplicationsList
        ApplicationsRaw = $signInData | Where-Object { $_.'Application' } | Select-Object 'Date (UTC)', 'User', 'Application', 'Status', 'Location - City'
        ClientAppsList = $detailedClientAppsList
        ClientAppsRaw = $signInData | Where-Object { $_.'Client app' } | Select-Object 'Date (UTC)', 'User', 'Application', 'Client app', 'Status', 'Location - City'
        ResourcesList = $detailedResourcesList
        ResourcesRaw = $signInData | Where-Object { $_.'Resource' -or $_.'Resource ID' } | Select-Object 'Date (UTC)', 'User', 'Application', 'Resource', 'Status', 'Location - City'
        OperatingSystemsList = $detailedOperatingSystemsList
        OperatingSystemsRaw = $signInData | Where-Object { $_.'Operating System' } | Select-Object 'Date (UTC)', 'User', 'Application', 'Operating System', 'Status', 'Location - City'
        FailedSignInsList = $failedSignIns | Group-Object -Property @{Expression={"$($_.'User')|$($_.'Application')|$($_.'Resource')|$($_.'IP address')|$($_.'Location - City')|$($_.'Operating System')|$($_.'Sign-in error code')|$($_.'Failure reason')"}} | ForEach-Object {
            $firstEvent = $_.Group | Sort-Object { [DateTime]$_.'Date (UTC)' } | Select-Object -First 1
            @{
                Timestamp = $firstEvent.'Date (UTC)'
                User = $firstEvent.'User'
                Application = $firstEvent.'Application'
                Resource = $firstEvent.'Resource'
                IPAddress = $firstEvent.'IP address'
                City = $firstEvent.'Location - City'
                OperatingSystem = $firstEvent.'Operating System'
                ErrorCode = $firstEvent.'Sign-in error code'
                FailureReason = $firstEvent.'Failure reason'
                Count = $_.Count
            }
        }
        FailedSignInsRaw = $failedSignIns | Select-Object 'Date (UTC)', 'User', 'Application', 'Resource', 'IP address', 'Location - City', 'Operating System', 'Sign-in error code', 'Failure reason'
        InterruptedSignInsList = $interruptedSignIns | Group-Object -Property @{Expression={"$($_.'User')|$($_.'Application')|$($_.'Resource')|$($_.'IP address')|$($_.'Location - City')|$($_.'Operating System')|$($_.'Sign-in error code')|$($_.'Failure reason')"}} | ForEach-Object {
            $firstEvent = $_.Group | Sort-Object { [DateTime]$_.'Date (UTC)' } | Select-Object -First 1
            @{
                Timestamp = $firstEvent.'Date (UTC)'
                User = $firstEvent.'User'
                Application = $firstEvent.'Application'
                Resource = $firstEvent.'Resource'
                IPAddress = $firstEvent.'IP address'
                City = $firstEvent.'Location - City'
                OperatingSystem = $firstEvent.'Operating System'
                ErrorCode = $firstEvent.'Sign-in error code'
                FailureReason = $firstEvent.'Failure reason'
                Count = $_.Count
            }
        }
        InterruptedSignInsRaw = $interruptedSignIns | Select-Object 'Date (UTC)', 'User', 'Application', 'Resource', 'IP address', 'Location - City', 'Operating System', 'Sign-in error code', 'Failure reason'
        SuccessfulSignInsList = $successfulSignIns | Group-Object -Property @{Expression={"$($_.'User')|$($_.'Application')|$($_.'Resource')|$($_.'IP address')|$($_.'Location - City')|$($_.'Operating System')"}} | ForEach-Object {
            $firstEvent = $_.Group | Sort-Object { [DateTime]$_.'Date (UTC)' } | Select-Object -First 1
            @{
                Timestamp = $firstEvent.'Date (UTC)'
                User = $firstEvent.'User'
                Application = $firstEvent.'Application'
                Resource = $firstEvent.'Resource'
                IPAddress = $firstEvent.'IP address'
                City = $firstEvent.'Location - City'
                OperatingSystem = $firstEvent.'Operating System'
                Count = $_.Count
            }
        }
        SuccessfulSignInsRaw = $successfulSignIns | Select-Object 'Date (UTC)', 'User', 'Application', 'Resource', 'IP address', 'Location - City', 'Operating System'
        OffHoursSignInsList = if ($offHoursSignIns) { 
            $offHoursSignIns | Group-Object -Property @{Expression={"$($_.'User')|$($_.Application)|$($_.'IP address')|$($_.'Location - City')|$($_.'Location - Country/Region')"}} | ForEach-Object {
                $firstEvent = $_.Group | Sort-Object { [DateTime]$_.'Date (UTC)' } | Select-Object -First 1
                @{
                    Timestamp = $firstEvent.'Date (UTC)'
                    User = $firstEvent.'User'
                    Application = $firstEvent.Application
                    IPAddress = $firstEvent.'IP address'
                    City = $firstEvent.'Location - City'
                    Country = $firstEvent.'Location - Country/Region'
                    Status = $firstEvent.Status
                    Count = $_.Count
                }
            }
        } else { @() }
        OffHoursSignInsRaw = if ($offHoursSignIns) { $offHoursSignIns | Select-Object 'Date (UTC)', 'User', 'Application', 'IP address', 'Location - City', 'Location - Country/Region', 'Status' } else { @() }
    }
}
#endregion

#region Function: Analyze-AuditLogs
# Function to analyze audit logs for suspicious activities
function Analyze-AuditLogs {
    param (
        [Parameter(Mandatory=$true)]
        [string]$CsvFilePath,
        [Parameter(Mandatory=$true)]
        [string]$UserDisplayName,
        [Parameter(Mandatory=$true)]
        [string]$UserUPN,
        [Parameter(Mandatory=$false)]
        [hashtable]$WorkingHours = @{ StartHour = 9; EndHour = 17 }
    )
    
    # Check if audit log file exists
    if (-not (Test-Path -Path $CsvFilePath)) {
        Write-Host "Audit log file not found: $CsvFilePath" -ForegroundColor Yellow
        return $null
    }
    
    # Import the CSV data
    $auditData = Import-Csv -Path $CsvFilePath
    
    if ($auditData.Count -eq 0) {
        Write-Host "No audit data to analyze." -ForegroundColor Yellow
        return $null
    }
    
    # Initialize audit indicators
    # 4 main Audit Indicators of Suspicious Behavior, each at 25%
    $mainIndicatorWeight = 25.0  # 4 main indicators at 25% each = 100%
    $suspiciousPatternWeight = [Math]::Round(100.0 / 13, 2)  # 13 suspicious activities at ~7.69% each = 100%

    $auditIndicators = @{
        'Off-Hours Password Change/Reset' = @{ Score = 0; Weight = $mainIndicatorWeight; Details = @(); Count = 0 }
        'Off-Hours Audit Activity' = @{ Score = 0; Weight = $mainIndicatorWeight; Details = @(); Count = 0 }
        'Failed Audit Events' = @{ Score = 0; Weight = $mainIndicatorWeight; Details = @(); Count = 0 }
        'Authentication Info Changes' = @{ Score = 0; Weight = $mainIndicatorWeight; Details = @(); Count = 0 }
        # Suspicious Activities patterns - tracked separately
        'Consent to Application' = @{ Score = 0; Weight = $suspiciousPatternWeight; Details = @(); Count = 0 }
        'Password Change' = @{ Score = 0; Weight = $suspiciousPatternWeight; Details = @(); Count = 0 }
        'Password Reset' = @{ Score = 0; Weight = $suspiciousPatternWeight; Details = @(); Count = 0 }
        'Privileged Role Changes' = @{ Score = 0; Weight = $suspiciousPatternWeight; Details = @(); Count = 0 }
        'Policy Changes' = @{ Score = 0; Weight = $suspiciousPatternWeight; Details = @(); Count = 0 }
        'Bulk Deletions' = @{ Score = 0; Weight = $suspiciousPatternWeight; Details = @(); Count = 0 }
    }
    
    # Categorize activities
    $passwordChanges = $auditData | Where-Object { $_.Activity -match 'password|reset' }
    $roleChanges = $auditData | Where-Object { $_.Activity -match 'role|permission|privilege' }
    $userManagement = $auditData | Where-Object { $_.Activity -match 'Add user|Delete user|Update user|Disable account|Enable account' }
    $disableAccountActivities = $auditData | Where-Object { $_.Activity -match 'Disable account' }
    $appActivities = $auditData | Where-Object { $_.Activity -match 'application|app registration|consent|service principal' }
    $groupChanges = $auditData | Where-Object { $_.Activity -match 'group|member' }
    $deviceActivities = $auditData | Where-Object { $_.Activity -match 'device|registered|join' }
    $policyChanges = $auditData | Where-Object { $_.Activity -match 'policy|conditional access' }
    $dataExport = $auditData | Where-Object { $_.Activity -match 'export|download|backup' }
    $deletionActivities = $auditData | Where-Object { $_.Activity -match 'delete|remove' }
    $mfaChanges = $auditData | Where-Object { $_.Activity -match 'MFA|multi-factor|authentication method' }
    
    # Get unique categories
    $uniqueCategories = $auditData | Where-Object { $_.Category } | Select-Object -ExpandProperty Category -Unique
    $uniqueServices = $auditData | Where-Object { $_.Service } | Select-Object -ExpandProperty Service -Unique
    $uniqueActivities = $auditData | Where-Object { $_.Activity } | Select-Object -ExpandProperty Activity -Unique
    $uniqueIPAddresses = $auditData | Where-Object { $_.'Initiator IP' -and $_.'Initiator IP' -ne '' } | Select-Object -ExpandProperty 'Initiator IP' -Unique
    $uniqueTargets = $auditData | Where-Object { $_.'Target Display Name' -and $_.'Target Display Name' -ne '' } | Select-Object -ExpandProperty 'Target Display Name' -Unique
    
    # Successful activities
    $successfulActivities = $auditData | Where-Object { $_.Result -eq 'success' }
    
    # Failed activities (anything that's not success)
    $failedActivities = $auditData | Where-Object { $_.Result -ne 'success' -and $_.Result }
    
    # Time-based analysis
    $activitiesByHour = @{}
    foreach ($activity in $auditData) {
        if ($activity.Timestamp) {
            try {
                $hour = ([DateTime]$activity.Timestamp).Hour
                if (-not $activitiesByHour.ContainsKey($hour)) {
                    $activitiesByHour[$hour] = 0
                }
                $activitiesByHour[$hour]++
            } catch {}
        }
    }
    
    # Off-hours audit activities (based on user's working hours)
    $offHoursActivities = $auditData | Where-Object {
        if ($_.Timestamp) {
            try {
                $hour = ([DateTime]$_.Timestamp).Hour
                Test-OffHours -Hour $hour -WorkStartHour $WorkingHours.StartHour -WorkEndHour $WorkingHours.EndHour
            } catch { $false }
        }
    }
    
    # Suspicious activity detection
    $suspiciousActivities = @()
    $suspiciousPatterns = @(
        @{ Pattern = 'Update application'; RiskLevel = 'High'; Icon = '&#9999;'; DisplayName = 'Update Application' },
        @{ Pattern = 'Add service principal'; RiskLevel = 'High'; Icon = '&#128273;'; DisplayName = 'Add Service Principal' },
        @{ Pattern = 'Add app role assignment'; RiskLevel = 'High'; Icon = '&#128274;'; DisplayName = 'Add App Role Assignment' },
        @{ Pattern = 'Disable account'; RiskLevel = 'High'; Icon = '&#128683;'; DisplayName = 'Disable Account' },
        @{ Pattern = 'Bulk update user'; RiskLevel = 'High'; Icon = '&#128101;'; DisplayName = 'Bulk Update User' },
        @{ Pattern = 'Add owner to'; RiskLevel = 'High'; Icon = '&#128100;'; DisplayName = 'Add Owner to Application/Service Principal' },
        @{ Pattern = 'Update service principal'; RiskLevel = 'High'; Icon = '&#128295;'; DisplayName = 'Update Service Principal' }
    )
    
    $suspiciousPatternStatus = @()
    foreach ($patternObj in $suspiciousPatterns) {
        $pattern = $patternObj.Pattern
        $riskLevel = $patternObj.RiskLevel
        $displayName = $patternObj.DisplayName
        $matchedActivities = $auditData | Where-Object { $_.Activity -match [regex]::Escape($pattern) }
        
        # Create individual indicator for each pattern with suspicious pattern weight
        $indicatorKey = $displayName
        if (-not $auditIndicators.ContainsKey($indicatorKey)) {
            $auditIndicators[$indicatorKey] = @{ 
                Score = 0
                Weight = $suspiciousPatternWeight
                Details = @()
                Count = 0
                RiskLevel = $riskLevel
                Icon = $patternObj.Icon
                OriginalPattern = $pattern  # Store original pattern for filtering
            }
        }
        
        if ($matchedActivities.Count -gt 0) {
            $auditIndicators[$indicatorKey].Score = if ($riskLevel -eq 'High') { 100 } else { [Math]::Min(100, $matchedActivities.Count * 30) }
            $auditIndicators[$indicatorKey].Count = $matchedActivities.Count
            $auditIndicators[$indicatorKey].Details = $matchedActivities | Select-Object -First 5 -ExpandProperty Activity | Where-Object { $_ }
        }
        
        $suspiciousPatternStatus += @{
            Pattern = $pattern
            DisplayName = $displayName
            RiskLevel = $riskLevel
            Status = if ($matchedActivities.Count -gt 0) { 'Failed' } else { 'Passed' }
            Count = $matchedActivities.Count
        }
        
        $suspiciousActivities += $matchedActivities
    }
    $suspiciousActivities = $suspiciousActivities | Select-Object -Unique
    
    # Calculate Audit Indicators of Suspicious Behavior
    
    # Off-Hours Password Change/Reset: if any password change or reset occurs after working hours => 100
    $auditIndicators['Off-Hours Password Change/Reset'].Count = $passwordChanges.Count
    if ($passwordChanges.Count -gt 0) {
        # Determine if any password change/reset occurred during off-hours
        $offHoursPasswordEvents = $passwordChanges | Where-Object {
            if ($_.Timestamp) {
                try {
                    $hour = ([DateTime]$_.Timestamp).Hour
                    return (Test-OffHours -Hour $hour -WorkStartHour $WorkingHours.StartHour -WorkEndHour $WorkingHours.EndHour)
                } catch { return $false }
            }
            return $false
        }

        if ($offHoursPasswordEvents.Count -gt 0) {
            $auditIndicators['Off-Hours Password Change/Reset'].Score = 100
            $auditIndicators['Off-Hours Password Change/Reset'].Details = $offHoursPasswordEvents | Select-Object -First 10 | ForEach-Object { $_.Activity }
        }
        else {
            $auditIndicators['Off-Hours Password Change/Reset'].Score = 0
            $auditIndicators['Off-Hours Password Change/Reset'].Details = @()
        }
    }
    
    # Privileged Role Changes - count will be updated after grouping role changes list
    
    # Off-hours Audit Activity: each off-hours event = 10 points, capped at 100
    if ($offHoursActivities.Count -gt 0) {
        $auditIndicators['Off-Hours Audit Activity'].Score = [Math]::Min(100, $offHoursActivities.Count * 10)
        $auditIndicators['Off-Hours Audit Activity'].Count = $offHoursActivities.Count
    }
    
    # Failed Audit Events: more than 5 failures = high risk (100 score)
    if ($failedActivities.Count -gt 5) {
        $auditIndicators['Failed Audit Events'].Score = 100
        $auditIndicators['Failed Audit Events'].Count = $failedActivities.Count
        $auditIndicators['Failed Audit Events'].Details = $failedActivities | Select-Object -First 10 | ForEach-Object { "$($_.Activity) - Initiator: $($_.'Initiator User UPN')" }
    } elseif ($failedActivities.Count -gt 0) {
        # 1-5 failures: graduated scoring
        $auditIndicators['Failed Audit Events'].Score = $failedActivities.Count * 20
        $auditIndicators['Failed Audit Events'].Count = $failedActivities.Count
        $auditIndicators['Failed Audit Events'].Details = $failedActivities | Select-Object -First 10 | ForEach-Object { "$($_.Activity) - Initiator: $($_.'Initiator User UPN')" }
    }
    
    # Policy Changes
    if ($policyChanges.Count -gt 0) {
        $auditIndicators['Policy Changes'].Score = [Math]::Min(100, $policyChanges.Count * 20)
        $auditIndicators['Policy Changes'].Count = $policyChanges.Count
        $auditIndicators['Policy Changes'].Details = $policyChanges | Select-Object -First 5 | ForEach-Object { "$($_.Activity) - Result: $($_.Result) - Target: $($_.'Target Display Name')" }
    }
    
    # Authentication Info Changes: filter by Service = "Authentication Methods", >3 = high risk
    $authMethodChanges = $auditData | Where-Object { $_.Service -eq 'Authentication Methods' }
    if ($authMethodChanges.Count -gt 3) {
        $auditIndicators['Authentication Info Changes'].Score = 100
        $auditIndicators['Authentication Info Changes'].Count = $authMethodChanges.Count
        $auditIndicators['Authentication Info Changes'].Details = $authMethodChanges | Select-Object -First 10 | ForEach-Object { "$($_.Activity) - Initiator: $($_.'Initiator User UPN')" }
    } elseif ($authMethodChanges.Count -gt 0) {
        # 1-3 changes: graduated scoring
        $auditIndicators['Authentication Info Changes'].Score = $authMethodChanges.Count * 33
        $auditIndicators['Authentication Info Changes'].Count = $authMethodChanges.Count
        $auditIndicators['Authentication Info Changes'].Details = $authMethodChanges | Select-Object -First 10 | ForEach-Object { "$($_.Activity) - Initiator: $($_.'Initiator User UPN')" }
    }
    
    # Bulk Deletions
    if ($deletionActivities.Count -gt 5) {
        $auditIndicators['Bulk Deletions'].Score = [Math]::Min(100, ($deletionActivities.Count - 5) * 15)
        $auditIndicators['Bulk Deletions'].Count = $deletionActivities.Count
        $auditIndicators['Bulk Deletions'].Details = $deletionActivities | Select-Object -First 5 -ExpandProperty Activity | Where-Object { $_ }
    }
    
    # Consent to Application (Suspicious Activity)
    $consentActivities = $appActivities | Where-Object {
        $_.Activity -match 'Consent to application'
    }
    if ($consentActivities.Count -gt 0) {
        $auditIndicators['Consent to Application'].Score = [Math]::Min(100, $consentActivities.Count * 30)
        $auditIndicators['Consent to Application'].Count = $consentActivities.Count
        $auditIndicators['Consent to Application'].Details = $consentActivities | Select-Object -First 5 -ExpandProperty Activity | Where-Object { $_ }
    }
    
    # Update Service Principal (Suspicious Activity)
    $updateServicePrincipalActivities = $auditData | Where-Object {
        $_.Activity -match 'Update service principal'
    }
    if ($updateServicePrincipalActivities.Count -gt 0) {
        $auditIndicators['Update Service Principal'].Score = [Math]::Min(100, $updateServicePrincipalActivities.Count * 30)
        $auditIndicators['Update Service Principal'].Count = $updateServicePrincipalActivities.Count
        $auditIndicators['Update Service Principal'].Details = $updateServicePrincipalActivities | Select-Object -First 5 -ExpandProperty Activity | Where-Object { $_ }
    }
    
    # Add Owner to Application/Service Principal (Suspicious Activity)
    $addOwnerActivities = $auditData | Where-Object {
        $_.Activity -match 'Add owner to'
    }
    if ($addOwnerActivities.Count -gt 0) {
        $auditIndicators['Add Owner to Application/Service Principal'].Score = [Math]::Min(100, $addOwnerActivities.Count * 30)
        $auditIndicators['Add Owner to Application/Service Principal'].Count = $addOwnerActivities.Count
        $auditIndicators['Add Owner to Application/Service Principal'].Details = $addOwnerActivities | Select-Object -First 5 -ExpandProperty Activity | Where-Object { $_ }
    }
    
    # Add App Role Assignment (Suspicious Activity)
    $addAppRoleActivities = $auditData | Where-Object {
        $_.Activity -match 'Add app role assignment'
    }
    if ($addAppRoleActivities.Count -gt 0) {
        $auditIndicators['Add App Role Assignment'].Score = [Math]::Min(100, $addAppRoleActivities.Count * 30)
        $auditIndicators['Add App Role Assignment'].Count = $addAppRoleActivities.Count
        $auditIndicators['Add App Role Assignment'].Details = $addAppRoleActivities | Select-Object -First 5 -ExpandProperty Activity | Where-Object { $_ }
    }
    
    # Update Application (Suspicious Activity)
    $updateApplicationActivities = $auditData | Where-Object {
        $_.Activity -match 'Update application'
    }
    if ($updateApplicationActivities.Count -gt 0) {
        $auditIndicators['Update Application'].Score = [Math]::Min(100, $updateApplicationActivities.Count * 30)
        $auditIndicators['Update Application'].Count = $updateApplicationActivities.Count
        $auditIndicators['Update Application'].Details = $updateApplicationActivities | Select-Object -First 5 -ExpandProperty Activity | Where-Object { $_ }
    }
    
    # Add Service Principal (Suspicious Activity)
    $addServicePrincipalActivities = $auditData | Where-Object {
        $_.Activity -match 'Add service principal'
    }
    if ($addServicePrincipalActivities.Count -gt 0) {
        $auditIndicators['Add Service Principal'].Score = [Math]::Min(100, $addServicePrincipalActivities.Count * 30)
        $auditIndicators['Add Service Principal'].Count = $addServicePrincipalActivities.Count
        $auditIndicators['Add Service Principal'].Details = $addServicePrincipalActivities | Select-Object -First 5 -ExpandProperty Activity | Where-Object { $_ }
    }
    
    # Bulk Update User (Suspicious Activity)
    $bulkUpdateUserActivities = $auditData | Where-Object {
        $_.Activity -match 'Bulk update user'
    }
    if ($bulkUpdateUserActivities.Count -gt 0) {
        $auditIndicators['Bulk Update User'].Score = [Math]::Min(100, $bulkUpdateUserActivities.Count * 30)
        $auditIndicators['Bulk Update User'].Count = $bulkUpdateUserActivities.Count
        $auditIndicators['Bulk Update User'].Details = $bulkUpdateUserActivities | Select-Object -First 5 -ExpandProperty Activity | Where-Object { $_ }
    }
    
    # Password Change (Suspicious Activity)
    $passwordChangeActivities = $auditData | Where-Object {
        $_.Activity -match 'Change password'
    }
    if ($passwordChangeActivities.Count -gt 0) {
        $auditIndicators['Password Change'].Score = [Math]::Min(100, $passwordChangeActivities.Count * 30)
        $auditIndicators['Password Change'].Count = $passwordChangeActivities.Count
        $auditIndicators['Password Change'].Details = $passwordChangeActivities | Select-Object -First 5 -ExpandProperty Activity | Where-Object { $_ }
    }
    
    # Password Reset (Suspicious Activity)
    $passwordResetActivities = $auditData | Where-Object {
        $_.Activity -match '(?i)reset.*password'
    }
    if ($passwordResetActivities.Count -gt 0) {
        $auditIndicators['Password Reset'].Score = [Math]::Min(100, $passwordResetActivities.Count * 30)
        $auditIndicators['Password Reset'].Count = $passwordResetActivities.Count
        $auditIndicators['Password Reset'].Details = $passwordResetActivities | Select-Object -First 5 -ExpandProperty Activity | Where-Object { $_ }
    }
    
    # Suspicious App Activities removed from main audit indicators by configuration
    
    # Calculate overall audit risk score (weighted average) - Only from 4 main Audit Indicators of Suspicious Behavior
    $mainAuditIndicators = @('Off-Hours Password Change/Reset', 'Off-Hours Audit Activity', 'Failed Audit Events', 'Authentication Info Changes')
    $totalAuditWeightedScore = 0
    $totalAuditWeight = 0
    
    foreach ($indicatorName in $mainAuditIndicators) {
        if ($auditIndicators.ContainsKey($indicatorName)) {
            $indicator = $auditIndicators[$indicatorName]
            $weightedScore = ($indicator.Score * $indicator.Weight) / 100
            $totalAuditWeightedScore += $weightedScore
            $totalAuditWeight += $indicator.Weight
        }
    }
    
    $auditOverallScore = if ($totalAuditWeight -gt 0) { [Math]::Round(($totalAuditWeightedScore / $totalAuditWeight) * 100, 2) } else { 0 }
    
    # Calculate success percentage
    $successPercentage = if ($auditData.Count -gt 0) { [Math]::Round(($successfulActivities.Count / $auditData.Count) * 100, 1) } else { 0 }
    
    # Detailed activity lists for modals
    $passwordChangesList = $passwordChanges | Group-Object -Property 'Initiator User UPN', 'Target UPN' | ForEach-Object {
        $firstEvent = $_.Group | Sort-Object { [DateTime]$_.Timestamp } | Select-Object -First 1
        [PSCustomObject]@{
            Timestamp = $firstEvent.Timestamp
            Activity = $firstEvent.Activity
            Result = $firstEvent.Result
            OperationType = $firstEvent.'Operation Type'
            InitiatorUPN = $firstEvent.'Initiator User UPN'
            InitiatorDisplayName = $firstEvent.'Initiator Display Name'
            InitiatorIP = $firstEvent.'Initiator IP'
            TargetUPN = $firstEvent.'Target UPN'
            TargetDisplayName = $firstEvent.'Target Display Name'
            TargetType = $firstEvent.'Target Type'
            TargetID = $firstEvent.'Target ID'
            AdditionalDetails = $firstEvent.'Additional Details'
            Count = $_.Count
        }
    }
    $policyChangesList = $policyChanges | ForEach-Object { 
        @{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            Timestamp = $_.Timestamp
        }
    }
    $roleChangesList = $roleChanges | Group-Object -Property Activity, 'Initiator User UPN', 'Target Display Name' | ForEach-Object {
        $firstEvent = $_.Group | Sort-Object { [DateTime]$_.Timestamp } | Select-Object -First 1
        [PSCustomObject]@{
            Timestamp = $firstEvent.Timestamp
            Activity = $firstEvent.Activity
            Result = $firstEvent.Result
            OperationType = $firstEvent.'Operation Type'
            InitiatorUPN = $firstEvent.'Initiator User UPN'
            InitiatorDisplayName = $firstEvent.'Initiator Display Name'
            InitiatorIP = $firstEvent.'Initiator IP'
            TargetUPN = $firstEvent.'Target UPN'
            TargetDisplayName = $firstEvent.'Target Display Name'
            TargetType = $firstEvent.'Target Type'
            TargetID = $firstEvent.'Target ID'
            AdditionalDetails = $firstEvent.'Additional Details'
            Count = $_.Count
        }
    }
    
    # Update Privileged Role Changes count to match grouped list
    if ($roleChangesList.Count -gt 0) {
        $auditIndicators['Privileged Role Changes'].Score = [Math]::Min(100, $roleChangesList.Count * 20)
        $auditIndicators['Privileged Role Changes'].Count = $roleChangesList.Count
        $auditIndicators['Privileged Role Changes'].Details = $roleChangesList | Select-Object -First 5 | ForEach-Object { "$($_.Activity) - $($_.TargetDisplayName)" }
    }
    
    $userManagementList = $userManagement | Group-Object -Property Activity, 'Initiator User UPN', 'Target Display Name' | ForEach-Object {
        $firstEvent = $_.Group | Sort-Object { [DateTime]$_.Timestamp } | Select-Object -First 1
        [PSCustomObject]@{
            Timestamp = $firstEvent.Timestamp
            Activity = $firstEvent.Activity
            Result = $firstEvent.Result
            InitiatorUPN = $firstEvent.'Initiator User UPN'
            InitiatorDisplayName = $firstEvent.'Initiator Display Name'
            InitiatorIP = $firstEvent.'Initiator IP'
            TargetUPN = $firstEvent.'Target UPN'
            TargetDisplayName = $firstEvent.'Target Display Name'
            TargetType = $firstEvent.'Target Type'
            AdditionalDetails = $firstEvent.'Additional Details'
            Count = $_.Count
        }
    }
    $appActivitiesList = $appActivities | Group-Object -Property Activity, 'Initiator User UPN', 'Target Display Name' | ForEach-Object {
        $firstEvent = $_.Group | Sort-Object { [DateTime]$_.Timestamp } | Select-Object -First 1
        [PSCustomObject]@{
            Timestamp = $firstEvent.Timestamp
            Activity = $firstEvent.Activity
            Result = $firstEvent.Result
            InitiatorUPN = $firstEvent.'Initiator User UPN'
            InitiatorDisplayName = $firstEvent.'Initiator Display Name'
            InitiatorIP = $firstEvent.'Initiator IP'
            TargetUPN = $firstEvent.'Target UPN'
            TargetDisplayName = $firstEvent.'Target Display Name'
            TargetType = $firstEvent.'Target Type'
            AdditionalDetails = $firstEvent.'Additional Details'
            Count = $_.Count
        }
    }
    $groupChangesList = $groupChanges | Group-Object -Property Activity, 'Initiator User UPN', 'Target Display Name' | ForEach-Object {
        $firstEvent = $_.Group | Sort-Object { [DateTime]$_.Timestamp } | Select-Object -First 1
        [PSCustomObject]@{
            Timestamp = $firstEvent.Timestamp
            Activity = $firstEvent.Activity
            Result = $firstEvent.Result
            InitiatorUPN = $firstEvent.'Initiator User UPN'
            InitiatorDisplayName = $firstEvent.'Initiator Display Name'
            InitiatorIP = $firstEvent.'Initiator IP'
            TargetUPN = $firstEvent.'Target UPN'
            TargetDisplayName = $firstEvent.'Target Display Name'
            TargetType = $firstEvent.'Target Type'
            AdditionalDetails = $firstEvent.'Additional Details'
            Count = $_.Count
        }
    }
    $suspiciousActivityList = $suspiciousActivities | ForEach-Object { 
        @{
            Timestamp = $_.Timestamp
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            InitiatorDisplayName = $_.'Initiator Display Name'
            InitiatorIP = $_.'Initiator IP'
            TargetUPN = $_.'Target UPN'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            AdditionalDetails = $_.'Additional Details'
        }
    }
    $offHoursActivitiesList = $offHoursActivities | ForEach-Object {
        [PSCustomObject]@{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            InitiatorIP = $_.'Initiator IP'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            Timestamp = $_.Timestamp
            Count = 1
        }
    }
    $mfaChangesList = $mfaChanges | ForEach-Object { 
        @{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            Timestamp = $_.Timestamp
        }
    }
    $deletionActivitiesList = $deletionActivities | ForEach-Object { 
        @{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            InitiatorIP = $_.'Initiator IP'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            Timestamp = $_.Timestamp
        }
    }
    $disableAccountList = $disableAccountActivities | ForEach-Object {
        @{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            InitiatorIP = $_.'Initiator IP'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            Timestamp = $_.Timestamp
        }
    }
    $disableAccountList = $disableAccountActivities | ForEach-Object {
        @{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            InitiatorIP = $_.'Initiator IP'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            Timestamp = $_.Timestamp
        }
    }
    $consentToAppsList = $consentActivities | ForEach-Object { 
        @{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            InitiatorIP = $_.'Initiator IP'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            Timestamp = $_.Timestamp
        }
    }
    $updateServicePrincipalList = $updateServicePrincipalActivities | ForEach-Object { 
        @{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            InitiatorIP = $_.'Initiator IP'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            Timestamp = $_.Timestamp
        }
    }
    $addOwnerList = $addOwnerActivities | ForEach-Object { 
        @{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            InitiatorIP = $_.'Initiator IP'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            Timestamp = $_.Timestamp
        }
    }
    $addAppRoleList = $addAppRoleActivities | ForEach-Object { 
        @{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            InitiatorIP = $_.'Initiator IP'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            Timestamp = $_.Timestamp
        }
    }
    $updateApplicationList = $updateApplicationActivities | ForEach-Object { 
        @{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            InitiatorIP = $_.'Initiator IP'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            Timestamp = $_.Timestamp
        }
    }
    $addServicePrincipalList = $addServicePrincipalActivities | ForEach-Object { 
        @{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            InitiatorIP = $_.'Initiator IP'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            Timestamp = $_.Timestamp
        }
    }
    $addAuthMethodList = $addAuthMethodActivities | ForEach-Object { 
        @{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            InitiatorIP = $_.'Initiator IP'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            Timestamp = $_.Timestamp
        }
    }
    $deleteAuthMethodList = $deleteAuthMethodActivities | ForEach-Object { 
        @{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            InitiatorIP = $_.'Initiator IP'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            Timestamp = $_.Timestamp
        }
    }
    $bulkUpdateUserList = $bulkUpdateUserActivities | ForEach-Object { 
        @{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            InitiatorIP = $_.'Initiator IP'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            Timestamp = $_.Timestamp
        }
    }
    $passwordChangeList = $passwordChangeActivities | ForEach-Object { 
        @{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            InitiatorIP = $_.'Initiator IP'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            Timestamp = $_.Timestamp
        }
    }
    $passwordResetList = $passwordResetActivities | ForEach-Object { 
        @{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            InitiatorIP = $_.'Initiator IP'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            Timestamp = $_.Timestamp
        }
    }
    $suspiciousAppsList = $suspiciousApps | ForEach-Object { 
        @{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            InitiatorIP = $_.'Initiator IP'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            Timestamp = $_.Timestamp
        }
    }
    $authMethodChangesList = $authMethodChanges | ForEach-Object {
        [PSCustomObject]@{
            Activity = $_.Activity
            Result = $_.Result
            OperationType = $_.'Operation Type'
            InitiatorUPN = $_.'Initiator User UPN'
            InitiatorIP = $_.'Initiator IP'
            TargetDisplayName = $_.'Target Display Name'
            TargetType = $_.'Target Type'
            TargetID = $_.'Target ID'
            Timestamp = $_.Timestamp
            Count = 1
        }
    }

    # Create lists for Total and Successful Activities for modals
    $totalActivitiesList = $auditData | Group-Object -Property Activity, 'Initiator User UPN', 'Target Type', 'Target Display Name' | ForEach-Object {
        $firstEvent = $_.Group | Sort-Object { [DateTime]$_.Timestamp } | Select-Object -First 1
        [PSCustomObject]@{
            Timestamp = $firstEvent.Timestamp
            Activity = $firstEvent.Activity
            Result = $firstEvent.Result
            InitiatorUPN = $firstEvent.'Initiator User UPN'
            TargetType = $firstEvent.'Target Type'
            TargetDisplayName = $firstEvent.'Target Display Name'
            Count = $_.Count
        }
    }

    $successfulActivitiesList = $successfulActivities | Group-Object -Property Activity, 'Initiator User UPN', 'Target Type', 'Target Display Name' | ForEach-Object {
        $firstEvent = $_.Group | Sort-Object { [DateTime]$_.Timestamp } | Select-Object -First 1
        [PSCustomObject]@{
            Timestamp = $firstEvent.Timestamp
            Activity = $firstEvent.Activity
            InitiatorUPN = $firstEvent.'Initiator User UPN'
            TargetType = $firstEvent.'Target Type'
            TargetDisplayName = $firstEvent.'Target Display Name'
            Count = $_.Count
        }
    }
    
    return @{
        OverallScore = $auditOverallScore
        Indicators = $auditIndicators
        TotalActivities = $auditData.Count
        SuccessfulActivities = $successfulActivities.Count
        FailedActivities = $failedActivities.Count
        SuccessPercentage = $successPercentage
        
        PasswordChanges = $passwordChanges.Count
        RoleChanges = $roleChanges.Count
        UserManagement = $userManagement.Count
        AppActivities = $appActivities.Count
        GroupChanges = $groupChanges.Count
        DeviceActivities = $deviceActivities.Count
        PolicyChanges = $policyChanges.Count
        DataExport = $dataExport.Count
        DeletionActivities = $deletionActivities.Count
        MFAChanges = $mfaChanges.Count
        SuspiciousActivities = $suspiciousActivities.Count
        OffHoursActivities = $offHoursActivities.Count
        
        UniqueCategories = $uniqueCategories.Count
        UniqueServices = $uniqueServices.Count
        UniqueActivities = $uniqueActivities.Count
        UniqueIPAddresses = $uniqueIPAddresses.Count
        UniqueTargets = $uniqueTargets.Count
        
        UserDisplayName = $UserDisplayName
        UserUPN = $UserUPN
        AnalysisDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        # Detailed lists for modals
        CategoriesList = $uniqueCategories
        ServicesList = $uniqueServices
        ActivitiesList = $uniqueActivities
        IPAddressesList = $uniqueIPAddresses
        TargetsList = $uniqueTargets
        PasswordChangesList = $passwordChangesList
        RoleChangesList = $roleChangesList
        RoleChangesRaw = $roleChanges
        PolicyChangesList = $policyChangesList
        PolicyChangesRaw = $policyChanges
        UserManagementList = $userManagementList
        UserManagementRaw = $userManagement
        AppActivitiesList = $appActivitiesList
        AppActivitiesRaw = $appActivities
        GroupChangesList = $groupChangesList
        GroupChangesRaw = $groupChanges
        SuspiciousActivityList = $suspiciousActivityList
        OffHoursActivitiesList = $offHoursActivitiesList
        OffHoursActivitiesRaw = $offHoursActivities
        MFAChangesList = $mfaChangesList
        MFAChangesRaw = $mfaChanges
        DeletionActivitiesList = $deletionActivitiesList
        ConsentToAppsList = $consentToAppsList
        UpdateServicePrincipalList = $updateServicePrincipalList
        AddOwnerList = $addOwnerList
        AddAppRoleList = $addAppRoleList
        UpdateApplicationList = $updateApplicationList
        AddServicePrincipalList = $addServicePrincipalList
        AddAuthMethodList = $addAuthMethodList
        DeleteAuthMethodList = $deleteAuthMethodList
        BulkUpdateUserList = $bulkUpdateUserList
        DisableAccountList = $disableAccountList
        PasswordChangeList = $passwordChangeList
        PasswordChangesRaw = $passwordChanges
        PasswordResetList = $passwordResetList
        SuspiciousAppsList = $suspiciousAppsList
        AuthMethodChangesList = $authMethodChangesList
        TotalActivitiesList = $totalActivitiesList
        SuccessfulActivitiesList = $successfulActivitiesList
        FailedActivitiesList = $failedActivities | ForEach-Object {
            [PSCustomObject]@{
                Activity = $_.Activity
                Result = $_.Result
                OperationType = $_.'Operation Type'
                InitiatorUPN = $_.'Initiator User UPN'
                InitiatorIP = $_.'Initiator IP'
                TargetDisplayName = $_.'Target Display Name'
                TargetType = $_.'Target Type'
                TargetID = $_.'Target ID'
                Timestamp = $_.Timestamp
                Count = 1
            }
        }
    }
}
#endregion

#region Function: Generate-HTMLReport
# Function to generate HTML report
function Generate-HTMLReport {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$AnalysisResults,
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        [Parameter(Mandatory=$false)]
        [hashtable]$AuditAnalysisResults = $null
    )
    
    # Helper function to get badge class based on indicator score
    function Get-BadgeClass {
        param([int]$Score)
        if ($Score -ge 75) { "badge-critical" }
        elseif ($Score -ge 50) { "badge-high" }
        elseif ($Score -ge 25) { "badge-medium" }
        else { "badge-low" }
    }
    
    # Helper function to get badge class for UPPERCASE values
    function Get-BadgeClassUpper {
        param([int]$Score)
        if ($Score -ge 75) { "CRITICAL" }
        elseif ($Score -ge 50) { "HIGH" }
        elseif ($Score -ge 25) { "MEDIUM" }
        else { "LOW" }
    }
    
    # Helper function to get progress color based on indicator score
    function Get-ProgressColor {
        param([int]$Score, [string]$ColorScheme = 'default')
        
        if ($ColorScheme -eq 'audit') {
            # Audit color scheme (purple for medium)
            if ($Score -ge 75) { "#e74c3c" }
            elseif ($Score -ge 50) { "#f39c12" }
            elseif ($Score -ge 25) { "#9b59b6" }
            else { "#2ecc71" }
        }
        else {
            # Default color scheme (blue for medium)
            if ($Score -ge 75) { "#e74c3c" }
            elseif ($Score -ge 50) { "#f39c12" }
            elseif ($Score -ge 25) { "#3498db" }
            else { "#2ecc71" }
        }
    }
    
    # Calculate combined risk score from both sign-in and audit indicators
    $signInScore = $AnalysisResults.OverallScore
    $auditScore = if ($AuditAnalysisResults -and $AuditAnalysisResults.OverallScore) { $AuditAnalysisResults.OverallScore } else { 0 }
    
    # Combined score: 50% Sign-In Indicators Risk + 50% Audit Risk Assessment = 100%
    # Note: Suspicious Activities are tracked separately and not included in Account Suspicious Behavior Score
    if ($auditScore -gt 0) {
        $score = [Math]::Round(($signInScore * 0.5) + ($auditScore * 0.5), 2)
    } else {
        $score = $signInScore
    }
    
    $riskLevel = if ($score -ge 75) { "CRITICAL" } elseif ($score -ge 50) { "HIGH" } elseif ($score -ge 25) { "MEDIUM" } else { "LOW" }
    $riskColor = if ($score -ge 75) { "#c0392b" } elseif ($score -ge 50) { "#e67e22" } elseif ($score -ge 25) { "#3498db" } else { "#27ae60" }
    
    # Calculate Sign-In Indicators risk score for the chart (similar to Audit Indicators Risk Score)
    $signInRiskScore = [Math]::Round($signInScore, 0)
    $signInRiskLevel = if ($signInRiskScore -ge 75) { "CRITICAL" } elseif ($signInRiskScore -ge 50) { "HIGH" } elseif ($signInRiskScore -ge 25) { "MEDIUM" } else { "LOW" }
    $signInRiskColor = if ($signInRiskScore -ge 75) { "#e74c3c" } elseif ($signInRiskScore -ge 50) { "#f39c12" } elseif ($signInRiskScore -ge 25) { "#3498db" } else { "#2ecc71" }
    
    $smallDonutCircumference = 2 * 3.14159 * 50
    $signInDashOffset = $smallDonutCircumference - (($signInRiskScore / 100) * $smallDonutCircumference)
    
    # Calculate risk circle for smaller view
    $smallCircumference = 2 * 3.14159 * 60
    $smallDashOffset = $smallCircumference - (($score / 100) * $smallCircumference)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Account Suspicious Behavior Report</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .dashboard {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.07);
        }
        
        .header h1 {
            font-size: 28px;
            color: #2c3e50;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .header .subtitle {
            color: #7f8c8d;
            font-size: 14px;
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }
        
        .grid.stats-grid {
            grid-template-columns: repeat(5, 1fr);
            gap: 12px;
        }
        
        .charts-top-section {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }
        
        .chart-card {
            background: white;
            border-radius: 12px;
            padding: 16px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.08);
            transition: transform 0.2s, box-shadow 0.2s;
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        
        .chart-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 12px rgba(0,0,0,0.1);
        }
        
        .stats-section {
            margin-bottom: 24px;
        }
        
        .section-header {
            background: white;
            border-radius: 12px 12px 0 0;
            padding: 20px 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.08);
            margin-bottom: 0;
        }
        
        .section-header h2 {
            margin: 0;
            font-size: 22px;
            font-weight: 600;
            color: #2c3e50;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .stats-grid-container {
            background: white;
            border-radius: 0 0 12px 12px;
            padding: 24px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.08);
        }
        
        @media (max-width: 1400px) {
            .charts-top-section {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        @media (max-width: 768px) {
            .charts-top-section {
                grid-template-columns: 1fr;
            }
            .grid.stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        .card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.08);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .stat-card.card {
            padding: 16px;
            border-radius: 10px;
            display: flex;
            flex-direction: column;
            min-height: 110px;
            justify-content: center;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: var(--accent-color);
            border-radius: 10px 0 0 10px;
        }
        
        .card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 12px rgba(0,0,0,0.1);
        }
        
        .stat-card {
            position: relative;
            overflow: hidden;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: var(--accent-color);
        }
        
        .stat-card .icon {
            width: 36px;
            height: 36px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
            margin-bottom: 10px;
        }
        
        .stat-card .label {
            font-size: 10px;
            color: #7f8c8d;
            margin-bottom: 6px;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }
        
        .stat-card .value {
            font-size: 28px;
            font-weight: 700;
            color: #2c3e50;
            line-height: 1;
        }
        
        .stat-card .view-details {
            font-size: 10px;
            color: white;
            margin-top: 12px;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 6px 12px;
            background: var(--accent-color);
            border-radius: 16px;
            transition: all 0.3s ease;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .stat-card:hover .view-details {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
            gap: 8px;
        }
        
        .stat-card .view-details::after {
            content: '\2192';
            font-size: 14px;
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover .view-details::after {
            transform: translateX(3px);
        }
        
        .assessment-card {
            grid-column: span 1;
            height: 100%;
            display: flex;
            flex-direction: column;
        }
        
        .assessment-card .section-title {
            font-size: 16px;
            margin-bottom: 12px;
        }
        
        .circular-progress {
            position: relative;
            width: 180px;
            height: 180px;
            margin: 10px auto;
            cursor: pointer;
            transition: transform 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .circular-progress:hover {
            transform: scale(1.05);
        }
        
        .circular-progress svg {
            transform: rotate(-90deg);
            filter: drop-shadow(0 2px 4px rgba(0,0,0,0.1));
        }
        
        .circular-progress:hover svg {
            filter: drop-shadow(0 4px 8px rgba(0,0,0,0.15));
        }
        
        .circular-progress-bg {
            fill: none;
            stroke: #ecf0f1;
            stroke-width: 12;
            transition: all 0.3s ease;
        }
        
        .circular-progress:hover .circular-progress-bg {
            stroke: #d5dbdb;
        }
        
        .circular-progress-bar {
            fill: none;
            stroke: $riskColor;
            stroke-width: 12;
            stroke-linecap: round;
            stroke-dasharray: $circumference;
            stroke-dashoffset: $dashOffset;
            transition: all 0.6s ease;
            animation: progressAnimation 1.5s ease-out;
        }
        
        @keyframes progressAnimation {
            from {
                stroke-dashoffset: $circumference;
            }
            to {
                stroke-dashoffset: $dashOffset;
            }
        }
        
        .circular-progress:hover .circular-progress-bar {
            stroke-width: 14;
            filter: brightness(1.1);
        }
        
        /* Interactive Donut Chart Styles */
        .donut-segment {
            transition: all 0.3s ease;
            cursor: pointer;
        }
        
        .donut-segment:hover {
            stroke-width: 16;
            filter: brightness(1.15) drop-shadow(0 0 8px currentColor);
            transform-origin: center;
        }
        
        .chart-tooltip {
            position: absolute;
            background: rgba(44, 62, 80, 0.95);
            color: white;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 12px;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.2s ease;
            z-index: 1000;
            white-space: nowrap;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }
        
        .chart-tooltip.show {
            opacity: 1;
        }
        
        .chart-tooltip::after {
            content: '';
            position: absolute;
            top: 100%;
            left: 50%;
            transform: translateX(-50%);
            border: 6px solid transparent;
            border-top-color: rgba(44, 62, 80, 0.95);
        }
        
        .chart-card:hover {
            transform: translateY(-6px);
            box-shadow: 0 12px 24px rgba(0,0,0,0.15);
        }
        
        .chart-legend {
            display: flex;
            flex-direction: column;
            gap: 8px;
            margin-top: 12px;
            padding: 12px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 11px;
            transition: all 0.2s ease;
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
        }
        
        .legend-item:hover {
            background: white;
            transform: translateX(4px);
        }
        
        .legend-color {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            transition: all 0.2s ease;
        }
        
        .legend-item:hover .legend-color {
            transform: scale(1.3);
            box-shadow: 0 2px 8px currentColor;
        }
        
        .legend-label {
            flex: 1;
            font-weight: 500;
            color: #2c3e50;
        }
        
        .legend-value {
            font-weight: 700;
            color: #7f8c8d;
        }
        
        .progress-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
            line-height: 1.2;
        }
        
        .progress-text .score {
            font-size: 28px;
            font-weight: 700;
            color: $riskColor;
            line-height: 1;
            margin-bottom: 4px;
        }
        
        .progress-text .label {
            font-size: 11px;
            color: #7f8c8d;
            margin-top: 4px;
            line-height: 1.2;
        }
        
        .risk-badge {
            display: inline-block;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 14px;
            background: $riskColor;
            color: white;
            margin-top: 12px;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .risk-badge:hover {
            transform: translateY(-2px) scale(1.05);
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
            filter: brightness(1.1);
        }
        
        .section-title {
            font-size: 18px;
            font-weight: 600;
            color: #2c3e50;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .indicators-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }
        
        .indicator-card {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.06);
            transition: all 0.2s;
        }
        
        .indicator-card:hover {
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        
        .indicator-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }
        
        .indicator-name {
            font-size: 15px;
            font-weight: 600;
            color: #2c3e50;
        }
        
        .indicator-badge {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 13px;
            font-weight: 600;
            color: white;
        }
        
        .badge-critical { background: #e74c3c; }
        .badge-high { background: #f39c12; }
        .badge-medium { background: #3498db; }
        .badge-low { background: #2ecc71; }
        
        .progress-container {
            position: relative;
            height: 8px;
            background: #ecf0f1;
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 8px;
        }
        
        .progress-bar {
            height: 100%;
            border-radius: 4px;
            transition: width 1s ease;
        }
        
        .indicator-meta {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 13px;
            color: #7f8c8d;
            margin-top: 8px;
        }
        
        .recommendations {
            background: white;
            border-radius: 16px;
            padding: 24px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.07);
        }
        
        .recommendation-item {
            padding: 14px 18px;
            margin: 8px 0;
            background: white;
            border-radius: 8px;
            border-left: 4px solid #3498db;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08);
            transition: all 0.2s ease;
            cursor: pointer;
        }
        
        .recommendation-item:hover {
            box-shadow: 0 2px 8px rgba(0,0,0,0.12);
            transform: translateY(-2px);
        }
        
        .recommendation-item.expanded {
            background: #f8f9fa;
        }
        
        .recommendation-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
        }
        
        .recommendation-left {
            display: flex;
            align-items: center;
            gap: 12px;
            flex: 1;
        }
        
        .recommendation-right {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-shrink: 0;
        }
        
        .recommendation-expand-text {
            font-size: 11px;
            font-weight: 600;
            color: #667eea;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: all 0.3s ease;
            padding: 6px 12px;
            border-radius: 6px;
            background: rgba(102, 126, 234, 0.08);
            cursor: pointer;
            order: 1;
        }
        
        .recommendation-item:hover .recommendation-expand-text {
            color: #5568d3;
            background: rgba(102, 126, 234, 0.15);
            transform: translateY(-1px);
        }
        
        .priority-badge {
            order: 2;
        }
        
        .recommendation-icon {
            font-size: 20px;
            flex-shrink: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            width: 36px;
            height: 36px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 8px;
            color: white;
            box-shadow: 0 2px 6px rgba(102,126,234,0.25);
        }
        
        .recommendation-text {
            flex: 1;
        }
        
        .recommendation-title {
            font-weight: 600;
            font-size: 14px;
            color: #1e3a8a;
        }
        
        .immediate-action-text {
            background: linear-gradient(135deg, #ff0844 0%, #ff6b35 50%, #ff0844 100%);
            background-size: 200% auto;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-weight: 800;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            display: inline-block;
            animation: shimmer 3s linear infinite;
            text-shadow: 0 0 10px rgba(255, 8, 68, 0.5);
            filter: drop-shadow(0 2px 4px rgba(255, 8, 68, 0.3));
        }
        
        @keyframes shimmer {
            0% { background-position: 0% center; }
            100% { background-position: 200% center; }
        }
        
        .recommendation-item.expanded .recommendation-expand-text::after {
            content: ' \25B2';
        }
        
        .recommendation-item:not(.expanded) .recommendation-expand-text::after {
            content: ' \25BC';
        }
        
        .recommendation-details {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
            font-size: 13px;
            color: #4a5568;
            line-height: 1.6;
            padding-left: 48px;
        }
        
        .recommendation-item.expanded .recommendation-details {
            max-height: 500px;
            margin-top: 12px;
        }
        
        .disclaimer-box {
            background: linear-gradient(135deg, #fff9e6 0%, #fffef7 100%);
            border: 2px solid #f1c40f;
            border-radius: 16px;
            padding: 24px;
            margin: 20px 0;
            box-shadow: 0 4px 16px rgba(241,196,15,0.2);
            position: relative;
            overflow: hidden;
        }
        
        .disclaimer-box::before {
            content: '\26A0';
            position: absolute;
            top: -20px;
            right: -20px;
            font-size: 120px;
            opacity: 0.05;
            transform: rotate(-15deg);
        }
        
        .disclaimer-title {
            font-weight: 800;
            font-size: 20px;
            color: #d68910;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .disclaimer-title::before {
            content: '\26A0';
            font-size: 28px;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.1); }
        }
        
        .checkbox-container {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-top: 20px;
            padding: 16px;
            background: rgba(255,255,255,0.7);
            border-radius: 12px;
            border: 2px dashed #f1c40f;
        }
        
        .checkbox-container input[type="checkbox"] {
            width: 24px;
            height: 24px;
            cursor: pointer;
            accent-color: #f1c40f;
        }
        
        .checkbox-container label {
            font-size: 14px;
            font-weight: 600;
            color: #333;
            cursor: pointer;
            user-select: none;
        }
        
        .action-button {
            margin-left: 12px;
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            transition: all 0.3s ease;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .action-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        
        .action-button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        
        .hide-btn {
            background: linear-gradient(135deg, #f1c40f 0%, #f39c12 100%);
            color: white;
        }
        
        .show-btn {
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
            color: white;
        }
        
        .notice-box {
            margin-top: 16px;
            padding: 16px;
            background: linear-gradient(135deg, #e8f5e9 0%, #f1f8e9 100%);
            border-left: 4px solid #4caf50;
            border-radius: 8px;
            font-size: 14px;
            color: #2e7d32;
            box-shadow: 0 2px 8px rgba(76,175,80,0.2);
        }
        
        .footer {
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #7f8c8d;
            font-size: 12px;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .card {
            animation: fadeIn 0.5s ease-out;
        }
        
        @media (max-width: 768px) {
            .grid {
                grid-template-columns: 1fr;
            }
            .grid.stats-grid {
                grid-template-columns: 1fr;
            }
            .indicators-grid {
                grid-template-columns: 1fr;
            }
        }
        
        /* Modal Styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(4px);
            animation: fadeIn 0.3s ease;
        }
        
        .modal-content {
            background-color: white;
            margin: 5% auto;
            padding: 0;
            border-radius: 16px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 1200px;
            max-height: 80vh;
            animation: slideIn 0.3s ease;
            display: flex;
            flex-direction: column;
        }
        
        @keyframes slideIn {
            from {
                transform: translateY(-50px);
                opacity: 0;
            }
            to {
                transform: translateY(0);
                opacity: 1;
            }
        }
        
        .modal-header {
            padding: 24px 30px;
            border-bottom: 1px solid #ecf0f1;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 16px 16px 0 0;
        }
        
        .modal-header h2 {
            margin: 0;
            color: white;
            font-size: 22px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .modal-close {
            background: rgba(255, 255, 255, 0.2);
            color: white;
            border: none;
            font-size: 28px;
            cursor: pointer;
            width: 36px;
            height: 36px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s;
            line-height: 1;
        }
        
        .modal-close:hover {
            background: rgba(255, 255, 255, 0.3);
            transform: rotate(90deg);
        }
        
        .modal-body {
            padding: 30px;
            overflow-y: auto;
            max-height: calc(80vh - 140px);
        }
        
        .modal-body::-webkit-scrollbar {
            width: 8px;
        }
        
        .modal-body::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 10px;
        }
        
        .modal-body::-webkit-scrollbar-thumb {
            background: #888;
            border-radius: 10px;
        }
        
        .modal-body::-webkit-scrollbar-thumb:hover {
            background: #555;
        }
        
        .modal-item {
            padding: 12px 16px;
            margin: 8px 0;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid var(--modal-color, #3498db);
            font-size: 14px;
            color: #2c3e50;
            transition: all 0.2s;
        }
        
        .modal-item:hover {
            background: #e9ecef;
            transform: translateX(4px);
        }
        
        .modal-footer {
            padding: 20px 30px;
            border-top: 1px solid #ecf0f1;
            text-align: center;
            background: #f8f9fa;
            border-radius: 0 0 16px 16px;
        }
        
        .modal-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        
        .modal-stat-box {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 16px;
            border-radius: 12px;
            text-align: center;
            color: white;
        }
        
        .modal-stat-box .stat-value {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 4px;
        }
        
        .modal-stat-box .stat-label {
            font-size: 12px;
            opacity: 0.9;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .stat-card {
            cursor: pointer;
        }
        
        .stat-card:active {
            transform: scale(0.98);
        }
        
        .empty-state {
            text-align: center;
            padding: 40px;
            color: #7f8c8d;
        }
        
        .empty-state-icon {
            font-size: 48px;
            margin-bottom: 16px;
            opacity: 0.5;
        }
        
        /* Suspicious Activities Table Styles */
        .suspicious-activities-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
        }
        
        .suspicious-activities-table thead {
            background: linear-gradient(135deg, #e67e22 0%, #f39c12 100%);
            color: white;
        }
        
        .suspicious-activities-table thead th {
            padding: 16px 20px;
            text-align: left;
            font-weight: 600;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .suspicious-activities-table tbody tr {
            border-bottom: 1px solid #ecf0f1;
            transition: all 0.2s ease;
            cursor: pointer;
        }
        
        .suspicious-activities-table tbody tr:hover {
            background: #f8f9fa;
            transform: scale(1.01);
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        
        .suspicious-activities-table tbody tr:last-child {
            border-bottom: none;
        }
        
        .suspicious-activities-table tbody td {
            padding: 18px 20px;
            font-size: 14px;
            color: #2c3e50;
        }
        
        .activity-name-cell {
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .activity-icon {
            font-size: 20px;
            width: 32px;
            height: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 8px;
            flex-shrink: 0;
        }
        
        .risk-level-badge {
            display: inline-block;
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .risk-critical {
            background: #ffe5e5;
            color: #e74c3c;
        }
        
        .risk-high {
            background: #fff3e0;
            color: #f39c12;
        }
        
        .risk-medium {
            background: #e3f2fd;
            color: #3498db;
        }
        
        .risk-low {
            background: #e8f5e9;
            color: #2ecc71;
        }
        
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .status-failed {
            background: #ffe5e5;
            color: #e74c3c;
        }
        
        .status-passed {
            background: #e8f5e9;
            color: #2ecc71;
        }
        
        /* Chart Animation Keyframes */
        @keyframes drawSuccess {
            from {
                stroke-dashoffset: $smallDonutCircumference;
            }
            to {
                stroke-dashoffset: $smallSuccessDashOffset;
            }
        }
        
        @keyframes drawFailure {
            from {
                stroke-dashoffset: $smallDonutCircumference;
            }
            to {
                stroke-dashoffset: $smallFailureDashOffset;
            }
        }
        
        @keyframes pulse {
            0%, 100% {
                transform: scale(1);
            }
            50% {
                transform: scale(1.05);
            }
        }
        
        .circular-progress:hover {
            animation: pulse 2s ease-in-out infinite;
        }
        
        /* Navigation Menu Styles */
        .nav-container {
            position: sticky;
            top: 20px;
            z-index: 999;
            margin-bottom: 20px;
        }
        
        .nav-menu {
            background: white;
            border-radius: 16px;
            padding: 16px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            display: flex;
            gap: 8px;
            overflow-x: auto;
            flex-wrap: wrap;
            justify-content: center;
        }
        
        .nav-menu::-webkit-scrollbar {
            height: 6px;
        }
        
        .nav-menu::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 10px;
        }
        
        .nav-menu::-webkit-scrollbar-thumb {
            background: #888;
            border-radius: 10px;
        }
        
        .nav-item {
            padding: 12px 24px;
            border-radius: 10px;
            background: #f8f9fa;
            color: #2c3e50;
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            border: 2px solid transparent;
            white-space: nowrap;
        }
        
        .nav-item:hover {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
        }
        
        .nav-item.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
        }
        
        .nav-item .nav-icon {
            font-size: 18px;
        }
        
        .section-wrapper {
            scroll-margin-top: 120px;
        }
        
        @media (max-width: 768px) {
            .nav-menu {
                justify-content: flex-start;
            }
            
            .nav-item {
                font-size: 12px;
                padding: 10px 16px;
            }
        }
        
        .detections-count {
            font-weight: 700;
            font-size: 20px;
            color: #2c3e50;
        }
        
        .weight-cell {
            font-weight: 600;
            color: #7f8c8d;
        }
        
        .view-details-link {
            font-size: 11px;
            color: #3498db;
            display: flex;
            align-items: center;
            gap: 4px;
            margin-top: 4px;
        }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <h1>
                <span style="font-size: 32px;">&#128274;</span>
                Account Suspicious Behavior Report
            </h1>
            <div class="subtitle">
                <strong>User:</strong> $($AnalysisResults.UserDisplayName) ($($AnalysisResults.UserUPN)) | 
                <strong>Analysis Date:</strong> $($AnalysisResults.AnalysisDate) | 
                <strong>Sign-In Events:</strong> $($AnalysisResults.TotalSignIns)$(if ($AuditAnalysisResults) { " | <strong>Audit Events:</strong> $($AuditAnalysisResults.TotalActivities)" })
            </div>
        </div>
        
        <!-- Navigation Menu -->
        <div class="nav-container">
            <nav class="nav-menu">
                <a class="nav-item active" href="#section-summary" onclick="scrollToSection('section-summary', this)">
                    <span class="nav-icon">&#128200;</span>
                    <span>Summary</span>
                </a>
                <a class="nav-item" href="#section-signin-metrics" onclick="scrollToSection('section-signin-metrics', this)">
                    <span class="nav-icon">&#128100;</span>
                    <span>Sign-In Metrics</span>
                </a>
                $(if ($AuditAnalysisResults) { @"
                <a class="nav-item" href="#section-audit-metrics" onclick="scrollToSection('section-audit-metrics', this)">
                    <span class="nav-icon">&#128196;</span>
                    <span>Audit Metrics</span>
                </a>
                <a class="nav-item" href="#section-audit-indicators" onclick="scrollToSection('section-audit-indicators', this)">
                    <span class="nav-icon">&#128681;</span>
                    <span>Audit Indicators</span>
                </a>
"@ })
                <a class="nav-item" href="#section-signin-indicators" onclick="scrollToSection('section-signin-indicators', this)">
                    <span class="nav-icon">&#128274;</span>
                    <span>Sign-In Indicators</span>
                </a>
                <a class="nav-item" href="#section-suspicious" onclick="scrollToSection('section-suspicious', this)">
                    <span class="nav-icon">&#128681;</span>
                    <span>Suspicious Activities</span>
                </a>
                <a class="nav-item" href="#section-recommendations" onclick="scrollToSection('section-recommendations', this)">
                    <span class="nav-icon">&#128161;</span>
                    <span>Recommendations</span>
                </a>
            </nav>
        </div>
        
        <!-- Summary Section -->
        <div id="section-summary" class="section-wrapper">
        <!-- Top Charts Section -->
        <div class="charts-top-section">
            <div class="chart-card">
                <div class="section-title" style="margin-bottom: 12px; font-size: 14px;">&#128200; Account Suspicious Behavior Score</div>
                <div class="circular-progress" style="transition: transform 0.3s ease;" onmouseenter="showChartTooltip(event, 'Combined Risk Score: $score%'); this.style.transform='scale(1.05)';" onmouseleave="hideChartTooltip(); this.style.transform='scale(1)';">
                    <svg width="180" height="180" viewBox="0 0 180 180">
                        <defs>
                            <linearGradient id="riskGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                                <stop offset="0%" style="stop-color:$riskColor;stop-opacity:1" />
                                <stop offset="100%" style="stop-color:$riskColor;stop-opacity:0.7" />
                            </linearGradient>
                            <filter id="glow">
                                <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
                                <feMerge>
                                    <feMergeNode in="coloredBlur"/>
                                    <feMergeNode in="SourceGraphic"/>
                                </feMerge>
                            </filter>
                        </defs>
                        <circle class="circular-progress-bg" cx="90" cy="90" r="75" style="stroke-width: 16;"></circle>
                        <circle class="circular-progress-bar" cx="90" cy="90" r="75" 
                                style="stroke: url(#riskGradient); stroke-width: 16; stroke-dasharray: $smallCircumference; stroke-dashoffset: $smallDashOffset; filter: url(#glow); transition: all 0.6s ease;"></circle>
                    </svg>
                    <div class="progress-text">
                        <div class="score" style="font-size: 32px; line-height: 1; margin-bottom: 4px; font-weight: bold; transition: all 0.3s ease;">$score%</div>
                        <div class="label" style="font-size: 13px; line-height: 1.2; margin-top: 4px;">Combined Risk</div>
                    </div>
                </div>
                <div style="text-align: center; margin-top: 12px;">
                    <div class="risk-badge" style="font-size: 11px; padding: 6px 12px;">$riskLevel RISK</div>
                </div>
            </div>
            
            <div class="chart-card">
                <div class="section-title" style="margin-bottom: 12px; font-size: 14px; color: #3498db;">&#128202; Sign-In Indicators Risk Score</div>
                <div class="circular-progress" style="transition: transform 0.3s ease;" onmouseenter="showChartTooltip(event, 'Sign-In Indicators Risk Score: $signInRiskScore%'); this.style.transform='scale(1.05)';" onmouseleave="hideChartTooltip(); this.style.transform='scale(1)';">
                    <svg width="180" height="180" viewBox="0 0 180 180">
                        <defs>
                            <linearGradient id="signInRiskGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                                <stop offset="0%" style="stop-color:#3498db;stop-opacity:1" />
                                <stop offset="100%" style="stop-color:#3498db;stop-opacity:0.7" />
                            </linearGradient>
                            <filter id="blueGlow">
                                <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
                                <feMerge>
                                    <feMergeNode in="coloredBlur"/>
                                    <feMergeNode in="SourceGraphic"/>
                                </feMerge>
                            </filter>
                        </defs>
                        <circle cx="90" cy="90" r="65" fill="none" stroke="#ecf0f1" stroke-width="18"></circle>
                        <circle class="circular-progress-bar" cx="90" cy="90" r="65" fill="none" stroke="url(#signInRiskGradient)" stroke-width="18" 
                                stroke-dasharray="$smallDonutCircumference" stroke-dashoffset="$signInDashOffset" 
                                stroke-linecap="round" style="transition: all 0.6s ease; animation: progressAnimation 1.5s ease-out; filter: url(#blueGlow);"></circle>
                    </svg>
                    <div class="progress-text">
                        <div class="score" style="font-size: 32px; line-height: 1; margin-bottom: 4px; color: $signInRiskColor; font-weight: bold; transition: all 0.3s ease;">$signInRiskScore%</div>
                        <div class="label" style="font-size: 13px; line-height: 1.2; margin-top: 4px;">Risk Score</div>
                    </div>
                </div>
                <div style="text-align: center; margin-top: 12px;">
                    <div class="risk-badge" style="font-size: 11px; padding: 6px 12px; background: $signInRiskColor;">$signInRiskLevel RISK</div>
                </div>
            </div>
            
AUDIT_CHART_PLACEHOLDER
        </div>
        </div>
        <!-- End Summary Section -->
        
        <!-- Sign-In Statistics Section -->
        <div id="section-signin-metrics" class="section-wrapper">
        <div class="stats-section">
            <div class="section-header" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
                <h2 style="color: white;"><span style="font-size: 24px;">&#128100;</span> Sign-In Activity Metrics</h2>
            </div>
            <div class="stats-grid-container">
                <div class="grid stats-grid">
                    <div class="card stat-card" style="--accent-color: #6c5ce7; --accent-light: #f0ecff;" onclick="openModal('modal-signins')">
                        <div class="icon" style="background: #f0ecff; color: #6c5ce7;">&#128100;</div>
                        <div class="label">Sign-In Events</div>
                        <div class="value">$($AnalysisResults.TotalSignIns)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #2ecc71; --accent-light: #e8f8f5;" onclick="openModal('modal-success')">
                        <div class="icon" style="background: #e8f8f5; color: #2ecc71;">&#9989;</div>
                        <div class="label">Successful Sign-Ins</div>
                        <div class="value">$($AnalysisResults.SuccessfulSignIns)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #d63031; --accent-light: #ffe8e8;" onclick="openModal('modal-failed')">
                        <div class="icon" style="background: #ffe8e8; color: #d63031;">&#9888;</div>
                        <div class="label">Failed Sign-ins</div>
                        <div class="value">$($AnalysisResults.FailedSignIns)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #f39c12; --accent-light: #fff3e0;" onclick="openModal('modal-interrupted')">
                        <div class="icon" style="background: #fff3e0; color: #f39c12;">&#9888;&#65039;</div>
                        <div class="label">Interrupted Sign-Ins</div>
                        <div class="value">$($AnalysisResults.InterruptedSignIns)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #00b894; --accent-light: #e8f8f5;" onclick="openModal('modal-countries')">
                        <div class="icon" style="background: #e8f8f5; color: #00b894;">&#127758;</div>
                        <div class="label">Unique Countries</div>
                        <div class="value">$($AnalysisResults.UniqueCountries)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #0984e3; --accent-light: #e3f2fd;" onclick="openModal('modal-ips')">
                        <div class="icon" style="background: #e3f2fd; color: #0984e3;">&#128187;</div>
                        <div class="label">Unique IP Addresses</div>
                        <div class="value">$($AnalysisResults.UniqueIPs)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #fdcb6e; --accent-light: #fff8e1;" onclick="openModal('modal-sessions')">
                        <div class="icon" style="background: #fff8e1; color: #fdcb6e;">&#128274;</div>
                        <div class="label">Session IDs</div>
                        <div class="value">$($AnalysisResults.UniqueSessionIds)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #a29bfe; --accent-light: #f3f2ff;" onclick="openModal('modal-apps')">
                        <div class="icon" style="background: #f3f2ff; color: #a29bfe;">&#128230;</div>
                        <div class="label">Applications</div>
                        <div class="value">$($AnalysisResults.UniqueApplications)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #e17055; --accent-light: #ffebe6;" onclick="openModal('modal-clientapps')">
                        <div class="icon" style="background: #ffebe6; color: #e17055;">&#128241;</div>
                        <div class="label">Client Apps</div>
                        <div class="value">$($AnalysisResults.UniqueClientApps)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #74b9ff; --accent-light: #e8f4ff;" onclick="openModal('modal-resources')">
                        <div class="icon" style="background: #e8f4ff; color: #74b9ff;">&#128194;</div>
                        <div class="label">Resources</div>
                        <div class="value">$($AnalysisResults.UniqueResources)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #00cec9; --accent-light: #e0f7f7;" onclick="openModal('modal-os')">
                        <div class="icon" style="background: #e0f7f7; color: #00cec9;">&#128187;</div>
                        <div class="label">Operating Systems</div>
                        <div class="value">$($AnalysisResults.UniqueOperatingSystems)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #d35400; --accent-light: #ffe0cc;" onclick="openModal('modal-signin-offhours-metrics')">
                        <div class="icon" style="background: #ffe0cc; color: #d35400;">&#127769;</div>
                        <div class="label">Off-Hours Sign-Ins</div>
                        <div class="value">$($AnalysisResults.OffHoursSignIns)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                </div>
            </div>
        </div>
"@
    
    # Add Audit Log Section if available
    if ($AuditAnalysisResults) {
        # Calculate suspicious activities statistics - using the unified suspicious activities list
        $suspiciousActivities = @('Policy Changes', 'Bulk Deletions', 'Privileged Role Changes', 
                                 'Consent to Application', 'Password Change', 'Password Reset',
                                 'Update Application', 
                                 'Add Service Principal', 'Add App Role Assignment',
                                 'Disable Account', 'Bulk Update User',
                                 'Add Owner to Application/Service Principal', 'Update Service Principal')
        
        # Shared modal ID mapping for all audit indicators and suspicious activities
        $modalIdMap = @{
            'Off-Hours Password Change/Reset' = 'modal-indicator-password-changes'
            'Privileged Role Changes' = 'modal-indicator-role-changes'
            'Off-Hours Audit Activity' = 'modal-indicator-offhours'
            'Failed Audit Events' = 'modal-indicator-failed-audit'
            'Authentication Info Changes' = 'modal-indicator-authmethod'
            'Policy Changes' = 'modal-indicator-policy'
            'Bulk Deletions' = 'modal-indicator-deletions'
            'Consent to Application' = 'modal-indicator-consent'
            'Password Change' = 'modal-suspicious-password-change'
            'Password Reset' = 'modal-suspicious-password-reset'
            'Update Application' = 'modal-hr-update-app'
            'Add Service Principal' = 'modal-hr-add-principal'
            'Add App Role Assignment' = 'modal-hr-add-app-role'
            'Update Policy' = 'modal-hr-update-policy'
            'Disable Account' = 'modal-hr-disable-account'
            'Bulk Update User' = 'modal-hr-bulk-update-user'
            'Add Owner to Application/Service Principal' = 'modal-hr-add-owner'
            'Update Service Principal' = 'modal-hr-update-service-principal'
        }
        
        # Shared modal ID mapping for Sign-In indicators
        $signInModalIdMap = @{
            'Multiple Locations' = 'modal-signin-multiple-locations'
            'Failed/Interrupted Sign-ins' = 'modal-signin-failed'
            'Brute-force' = 'modal-signin-bruteforce'
            'Password-spray' = 'modal-signin-passwordspray'
            'Account Lockout' = 'modal-signin-lockout'
            'Multiple IP Addresses' = 'modal-signin-multiple-ips'
            'Risky Sign-ins' = 'modal-signin-risky'
            'Suspicious User Agents' = 'modal-signin-user-agents'
            'Off-hours Activity' = 'modal-signin-offhours'
            'Multiple Devices' = 'modal-signin-devices'
            'Anonymous IP' = 'modal-signin-anonymous'
            'Session IP Mismatch' = 'modal-signin-session-mismatch'
        }
        
        $totalSuspiciousActivities = 0
        $detectedSuspiciousActivities = 0
        
        foreach ($activity in $suspiciousActivities) {
            if ($AuditAnalysisResults.Indicators.ContainsKey($activity)) {
                $totalSuspiciousActivities++
                if ($AuditAnalysisResults.Indicators[$activity].Count -gt 0) {
                    $detectedSuspiciousActivities++
                }
            }
        }
        
        $detectedPercentage = if ($totalSuspiciousActivities -gt 0) { [Math]::Round(($detectedSuspiciousActivities / $totalSuspiciousActivities) * 100, 1) } else { 0 }
        
        # Calculate suspicious activities score - Based on detected patterns: 100% = all patterns detected (high risk), 0% = no patterns detected (low risk)
        $suspiciousRiskScore = [Math]::Round($detectedPercentage, 0)
        $suspiciousRiskLevel = if ($suspiciousRiskScore -ge 75) { "CRITICAL" } elseif ($suspiciousRiskScore -ge 50) { "HIGH" } elseif ($suspiciousRiskScore -ge 25) { "MEDIUM" } else { "LOW" }
        $suspiciousRiskColor = if ($suspiciousRiskScore -ge 75) { "#e74c3c" } elseif ($suspiciousRiskScore -ge 50) { "#f39c12" } elseif ($suspiciousRiskScore -ge 25) { "#3498db" } else { "#2ecc71" }
        
        $suspiciousCircumference = 2 * 3.14159 * 50
        $suspiciousDashOffset = $suspiciousCircumference - (($suspiciousRiskScore / 100) * $suspiciousCircumference)
        
        # Create suspicious activities chart
        $suspiciousChart = @"
            <div class="chart-card" onclick="scrollToSection('section-suspicious', document.querySelector('[href=\"#section-suspicious\"]'))" style="cursor: pointer; transition: transform 0.3s;" onmouseenter="this.style.transform='translateY(-8px) scale(1.02)'" onmouseleave="this.style.transform='translateY(0) scale(1)'">
                <div class="section-title" style="margin-bottom: 12px; font-size: 14px; color: $suspiciousRiskColor;">&#9888; Suspicious Activities Score</div>
                <div class="circular-progress" onmouseenter="showChartTooltip(event, 'Detected: $detectedSuspiciousActivities / $totalSuspiciousActivities patterns ($suspiciousRiskScore%)')" onmouseleave="hideChartTooltip()">
                    <svg width="180" height="180" viewBox="0 0 180 180">
                        <defs>
                            <linearGradient id="suspiciousRiskGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                                <stop offset="0%" style="stop-color:$suspiciousRiskColor;stop-opacity:1" />
                                <stop offset="100%" style="stop-color:$suspiciousRiskColor;stop-opacity:0.7" />
                            </linearGradient>
                            <filter id="orangeGlow">
                                <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
                                <feMerge>
                                    <feMergeNode in="coloredBlur"/>
                                    <feMergeNode in="SourceGraphic"/>
                                </feMerge>
                            </filter>
                        </defs>
                        <circle cx="90" cy="90" r="65" fill="none" stroke="#ecf0f1" stroke-width="18"></circle>
                        <circle class="circular-progress-bar" cx="90" cy="90" r="65" fill="none" stroke="url(#suspiciousRiskGradient)" stroke-width="18" 
                                stroke-dasharray="$suspiciousCircumference" stroke-dashoffset="$suspiciousDashOffset" 
                                stroke-linecap="round" style="transition: all 0.6s ease; animation: progressAnimation 1.5s ease-out; filter: url(#orangeGlow);"></circle>
                    </svg>
                    <div class="progress-text">
                        <div class="score" style="font-size: 32px; line-height: 1; margin-bottom: 4px; color: $suspiciousRiskColor; font-weight: bold; transition: all 0.3s ease;">$suspiciousRiskScore%</div>
                        <div class="label" style="font-size: 13px; line-height: 1.2; margin-top: 4px;">Risk Score</div>
                    </div>
                </div>
                <div style="text-align: center; margin-top: 12px;">
                    <div class="risk-badge" style="font-size: 11px; padding: 6px 12px; background: $suspiciousRiskColor; cursor: pointer; transition: all 0.3s ease; box-shadow: 0 2px 4px rgba(0,0,0,0.1);" onmouseenter="this.style.transform='translateY(-2px) scale(1.05)'; this.style.boxShadow='0 4px 12px rgba(0,0,0,0.2)'; this.style.filter='brightness(1.1)';" onmouseleave="this.style.transform='translateY(0) scale(1)'; this.style.boxShadow='0 2px 4px rgba(0,0,0,0.1)'; this.style.filter='brightness(1)';">$suspiciousRiskLevel RISK</div>
                </div>
            </div>
"@
        
        # Calculate audit activity donut chart - showing risk score
        $auditRiskScore = $AuditAnalysisResults.OverallScore
        $auditRiskLevel = if ($auditRiskScore -ge 75) { "CRITICAL" } elseif ($auditRiskScore -ge 50) { "HIGH" } elseif ($auditRiskScore -ge 25) { "MEDIUM" } else { "LOW" }
        $auditRiskColor = if ($auditRiskScore -ge 75) { "#e74c3c" } elseif ($auditRiskScore -ge 50) { "#f39c12" } elseif ($auditRiskScore -ge 25) { "#3498db" } else { "#2ecc71" }
        
        $auditCircumference = 2 * 3.14159 * 50
        $auditDashOffset = $auditCircumference - (($auditRiskScore / 100) * $auditCircumference)
        
        # Replace the audit chart placeholder in the top section
        $auditChart = @"
            <div class="chart-card">
                <div class="section-title" style="margin-bottom: 12px; font-size: 14px; color: #e74c3c;">&#128196; Audit Indicators Risk Score</div>
                <div class="circular-progress" style="transition: transform 0.3s ease;" onmouseenter="showChartTooltip(event, 'Audit Risk Score: $auditRiskScore%'); this.style.transform='scale(1.05)';" onmouseleave="hideChartTooltip(); this.style.transform='scale(1)';">
                    <svg width="180" height="180" viewBox="0 0 180 180">
                        <defs>
                            <linearGradient id="auditRiskGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                                <stop offset="0%" style="stop-color:#e74c3c;stop-opacity:1" />
                                <stop offset="100%" style="stop-color:#e74c3c;stop-opacity:0.7" />
                            </linearGradient>
                            <filter id="redGlow">
                                <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
                                <feMerge>
                                    <feMergeNode in="coloredBlur"/>
                                    <feMergeNode in="SourceGraphic"/>
                                </feMerge>
                            </filter>
                        </defs>
                        <circle cx="90" cy="90" r="65" fill="none" stroke="#ecf0f1" stroke-width="18"></circle>
                        <circle class="circular-progress-bar" cx="90" cy="90" r="65" fill="none" stroke="url(#auditRiskGradient)" stroke-width="18" 
                                stroke-dasharray="$auditCircumference" stroke-dashoffset="$auditDashOffset" 
                                stroke-linecap="round" style="transition: all 0.6s ease; animation: progressAnimation 1.5s ease-out; filter: url(#redGlow);"></circle>
                    </svg>
                    <div class="progress-text">
                        <div class="score" style="font-size: 32px; line-height: 1; margin-bottom: 4px; color: $auditRiskColor; font-weight: bold; transition: all 0.3s ease;">$auditRiskScore%</div>
                        <div class="label" style="font-size: 13px; line-height: 1.2; margin-top: 4px;">Audit Risk</div>
                    </div>
                </div>
                <div style="text-align: center; margin-top: 12px;">
                    <div class="risk-badge" style="font-size: 11px; padding: 6px 12px; background: $auditRiskColor;">$auditRiskLevel RISK</div>
                </div>
            </div>
"@
        $html = $html -replace 'AUDIT_CHART_PLACEHOLDER', ($auditChart + "`n" + $suspiciousChart)
        
        # Add Audit Log Statistics Section
        $html += @"
        
        <!-- Audit Log Statistics Section -->
        <div id="section-audit-metrics" class="section-wrapper">
        <div class="stats-section">
            <div class="section-header" style="background: linear-gradient(135deg, #8e44ad 0%, #9b59b6 100%); color: white;">
                <h2 style="color: white;"><span style="font-size: 24px;">&#128196;</span> Audit Log Activity Metrics</h2>
            </div>
            <div class="stats-grid-container">
                <div class="grid stats-grid">
                    <div class="card stat-card" style="--accent-color: #2c3e50; --accent-light: #ecf0f1;" onclick="openModal('modal-audit-total')">
                        <div class="icon" style="background: #ecf0f1; color: #2c3e50;">&#128202;</div>
                        <div class="label">Total Audit Activities</div>
                        <div class="value">$($AuditAnalysisResults.TotalActivities)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #27ae60; --accent-light: #d5f4e6;" onclick="openModal('modal-audit-success')">
                        <div class="icon" style="background: #d5f4e6; color: #27ae60;">&#9989;</div>
                        <div class="label">Successful Activities</div>
                        <div class="value">$($AuditAnalysisResults.SuccessfulActivities)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #e74c3c; --accent-light: #fadbd8;" onclick="openModal('modal-audit-failed')">
                        <div class="icon" style="background: #fadbd8; color: #e74c3c;">&#10060;</div>
                        <div class="label">Failed Activities</div>
                        <div class="value">$($AuditAnalysisResults.FailedActivities)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #e67e22; --accent-light: #fff3e0;" onclick="openModal('modal-audit-password')">
                        <div class="icon" style="background: #fff3e0; color: #e67e22;">&#128273;</div>
                        <div class="label">Password Changes</div>
                        <div class="value">$($AuditAnalysisResults.PasswordChanges)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #9b59b6; --accent-light: #f3e5f5;" onclick="openModal('modal-audit-roles')">
                        <div class="icon" style="background: #f3e5f5; color: #9b59b6;">&#128081;</div>
                        <div class="label">Role Changes</div>
                        <div class="value">$($AuditAnalysisResults.RoleChanges)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #3498db; --accent-light: #e3f2fd;" onclick="openModal('modal-audit-users')">
                        <div class="icon" style="background: #e3f2fd; color: #3498db;">&#128100;</div>
                        <div class="label">User Management</div>
                        <div class="value">$($AuditAnalysisResults.UserManagement)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #16a085; --accent-light: #e0f2f1;" onclick="openModal('modal-audit-apps')">
                        <div class="icon" style="background: #e0f2f1; color: #16a085;">&#128230;</div>
                        <div class="label">App Activities</div>
                        <div class="value">$($AuditAnalysisResults.AppActivities)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #f39c12; --accent-light: #fff8e1;" onclick="openModal('modal-audit-groups')">
                        <div class="icon" style="background: #fff8e1; color: #f39c12;">&#128101;</div>
                        <div class="label">Group Changes</div>
                        <div class="value">$($AuditAnalysisResults.GroupChanges)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                    
                    <div class="card stat-card" style="--accent-color: #d35400; --accent-light: #ffe0cc;" onclick="openModal('modal-audit-offhours')">
                        <div class="icon" style="background: #ffe0cc; color: #d35400;">&#127769;</div>
                        <div class="label">Off-Hours Activities</div>
                        <div class="value">$($AuditAnalysisResults.OffHoursActivities)</div>
                        <div class="view-details">&#128269; View Details</div>
                    </div>
                </div>
            </div>
        </div>
        </div>
        <!-- End Audit Metrics Section -->
        
        <!-- Audit Indicators of Suspicious Behavior -->
        <div id="section-audit-indicators" class="section-wrapper">
        <div class="stats-section">
            <div class="section-header" style="background: linear-gradient(135deg, #8e44ad 0%, #9b59b6 100%); color: white;">
                <h2 style="color: white;"><span style="font-size: 24px;">&#128681;</span> Audit Indicators of Suspicious Behavior</h2>
            </div>
            <div class="stats-grid-container">
                <div class="indicators-grid">
"@
    
    # Sort audit indicators by score (highest first), excluding all suspicious activities (they're displayed in their own section)
    if ($AuditAnalysisResults -and $AuditAnalysisResults.Indicators) {
        $excludedActivities = @('Policy Changes', 'Bulk Deletions', 'Privileged Role Changes', 
                               'Consent to Application', 'Password Change', 'Password Reset',
                               'Update Application', 
                               'Add Service Principal', 'Add App Role Assignment',
                               'Disable Account', 'Bulk Update User',
                               'Add Owner to Application/Service Principal', 'Update Service Principal')
        $sortedAuditIndicators = $AuditAnalysisResults.Indicators.GetEnumerator() | 
            Where-Object { $_.Key -notin $excludedActivities } |
            Sort-Object { $_.Value.Score } -Descending
        
        foreach ($indicator in $sortedAuditIndicators) {
            $name = $indicator.Key
            $data = $indicator.Value
            $indicatorScore = [Math]::Round($data.Score, 0)
            
            $badgeClass = Get-BadgeClass -Score $indicatorScore
            $progressColor = Get-ProgressColor -Score $indicatorScore -ColorScheme 'audit'
            
            # Get modal ID from shared mapping
            $modalId = if ($modalIdMap.ContainsKey($name)) { $modalIdMap[$name] } else { '' }
            
            $clickableStyle = if ($modalId) { " style='cursor: pointer;' onclick='openModal(`"$modalId`")'" } else { "" }
            
            $html += @"
                <div class="indicator-card"$clickableStyle style="--indicator-color: $progressColor;">
                    <div class="indicator-header">
                        <span class="indicator-name">$name</span>
                        <span class="indicator-badge $badgeClass">$indicatorScore%</span>
                    </div>
                    <div class="progress-container">
                        <div class="progress-bar" style="width: $indicatorScore%; background-color: $progressColor;"></div>
                    </div>
                    <div class="indicator-meta">
                        <span>Weight: $($data.Weight)%</span>
                        <span>Count: $($data.Count)</span>
                    </div>
"@
            
            # Add click instruction for all indicators
            if ($modalId) {
                $html += "<div style='text-align: center; margin-top: 8px; font-size: 12px; color: #7f8c8d;'>&#128269; Click to view details</div>"
            }
            
            $html += "</div>"
        }
    } else {
        $html += @"
                <div style="text-align: center; padding: 40px; color: #7f8c8d;">
                    <div style="font-size: 48px; margin-bottom: 16px;">&#128196;</div>
                    <div style="font-size: 16px;">No audit log data available for analysis</div>
                    <div style="font-size: 14px; margin-top: 8px;">Run audit log export to analyze administrative activities</div>
                </div>
"@
    }
    
    $html += @"
                </div>
            </div>
        </div>
"@
    } else {
        # No audit data - remove placeholder
        $html = $html -replace 'AUDIT_CHART_PLACEHOLDER', ''
    }
    
    $html += @"
        </div>
        <!-- End Audit Indicators Section -->
        
        <!-- Sign-In Indicators Section -->
        <div id="section-signin-indicators" class="section-wrapper">
        <div class="stats-section">
            <div class="section-header" style="background: linear-gradient(135deg, #3498db 0%, #5dade2 100%); color: white;">
                <h2 style="color: white;"><span style="font-size: 24px;">&#128202;</span> Sign-In Indicators of Suspicious Behavior</h2>
            </div>
            <div class="stats-grid-container">
                <div class="indicators-grid">
"@
    
    # Sort indicators by score (highest first)
    $sortedIndicators = $AnalysisResults.Indicators.GetEnumerator() | Sort-Object { $_.Value.Score } -Descending
    
    foreach ($indicator in $sortedIndicators) {
        $name = $indicator.Key
        $data = $indicator.Value
        $indicatorScore = [Math]::Round($data.Score, 0)
        
        $badgeClass = Get-BadgeClass -Score $indicatorScore
        $progressColor = Get-ProgressColor -Score $indicatorScore
        
        # Get modal ID from shared Sign-In mapping
        $modalId = if ($signInModalIdMap.ContainsKey($name)) { $signInModalIdMap[$name] } else { '' }
        
        $clickableStyle = if ($modalId) { " style='cursor: pointer;' onclick='openModal(`"$modalId`")'" } else { "" }
        
        $html += @"
                <div class="indicator-card"$clickableStyle style="--indicator-color: $progressColor;">
                    <div class="indicator-header">
                        <span class="indicator-name">$name</span>
                        <span class="indicator-badge $badgeClass">$indicatorScore%</span>
                    </div>
                    <div class="progress-container">
                        <div class="progress-bar" style="width: $indicatorScore%; background-color: $progressColor;"></div>
                    </div>
                    <div class="indicator-meta">
                        <span>Weight: $($data.Weight)%</span>
                        <span>Count: $($data.Count)</span>
                    </div>
"@
        
        # Add click instruction for all indicators
        if ($modalId) {
            $html += "<div style='text-align: center; margin-top: 8px; font-size: 12px; color: #7f8c8d;'>&#128269; Click to view details</div>"
        }
        
        $html += "</div>"
    }
    
    $html += @"
                </div>
            </div>
        </div>
        </div>
        <!-- End Sign-In Indicators Section -->
"@
    
    # Add Suspicious Activities section after Sign-In Indicators
    if ($AuditAnalysisResults) {
        $html += @"
        
        <!-- Suspicious Activities -->
        <div id="section-suspicious" class="section-wrapper">
        <div class="stats-section">
            <div class="section-header" style="background: linear-gradient(135deg, #e67e22 0%, #f39c12 100%); color: white;">
                <h2 style="color: white;"><span style="font-size: 24px;">&#9888;</span> Suspicious Activities</h2>
            </div>
            <div class="stats-grid-container">
"@
        
        # Display Suspicious Activities section
        if ($AuditAnalysisResults.Indicators) {
            # All suspicious activities in one unified array
            $suspiciousActivities = @(
                @{ Name = 'Policy Changes'; Icon = '&#128221;'; IconBg = '#e3f2fd'; IconColor = '#3498db' },
                @{ Name = 'Bulk Deletions'; Icon = '&#128465;'; IconBg = '#ffebee'; IconColor = '#e74c3c' },
                @{ Name = 'Privileged Role Changes'; Icon = '&#128081;'; IconBg = '#f3e5f5'; IconColor = '#9b59b6' },
                @{ Name = 'Consent to Application'; Icon = '&#9989;'; IconBg = '#fff3e0'; IconColor = '#e67e22' },
                @{ Name = 'Password Change'; Icon = '&#128272;'; IconBg = '#e3f2fd'; IconColor = '#3498db' },
                @{ Name = 'Password Reset'; Icon = '&#128260;'; IconBg = '#fff3e0'; IconColor = '#f39c12' },
                @{ Name = 'Update Application'; Icon = '&#128295;'; IconBg = '#fff3e0'; IconColor = '#f39c12' },
                @{ Name = 'Add Service Principal'; Icon = '&#128100;'; IconBg = '#fff3e0'; IconColor = '#f39c12' },
                @{ Name = 'Add App Role Assignment'; Icon = '&#128273;'; IconBg = '#fff3e0'; IconColor = '#f39c12' },
                @{ Name = 'Disable Account'; Icon = '&#128683;'; IconBg = '#ffebee'; IconColor = '#e74c3c' },
                @{ Name = 'Bulk Update User'; Icon = '&#128101;'; IconBg = '#fff3e0'; IconColor = '#f39c12' },
                @{ Name = 'Add Owner to Application/Service Principal'; Icon = '&#128100;'; IconBg = '#fff3e0'; IconColor = '#f39c12' },
                @{ Name = 'Update Service Principal'; Icon = '&#128295;'; IconBg = '#fff3e0'; IconColor = '#f39c12' }
            )
            
            $html += @"
                <table class="suspicious-activities-table">
                    <thead>
                        <tr>
                            <th style="width: 35%;">Activity Name</th>
                            <th style="width: 15%;">Risk Level</th>
                            <th style="width: 15%; text-align: center;">Detections Count</th>
                            <th style="width: 10%; text-align: center;">Weight</th>
                            <th style="width: 10%; text-align: center;">Actions</th>
                            <th style="width: 15%;">Status</th>
                        </tr>
                    </thead>
                    <tbody>
"@
            
            foreach ($activity in $suspiciousActivities) {
                $activityName = $activity.Name
                if ($AuditAnalysisResults.Indicators.ContainsKey($activityName)) {
                    $data = $AuditAnalysisResults.Indicators[$activityName]
                    $indicatorScore = [Math]::Round($data.Score, 0)
                    
                    # Determine risk level
                    $riskLevel = if ($indicatorScore -ge 75) { "Critical" } 
                                 elseif ($indicatorScore -ge 50) { "High" } 
                                 elseif ($indicatorScore -ge 25) { "Medium" } 
                                 else { "Low" }
                    
                    $riskClass = if ($indicatorScore -ge 75) { "risk-critical" } 
                                 elseif ($indicatorScore -ge 50) { "risk-high" } 
                                 elseif ($indicatorScore -ge 25) { "risk-medium" } 
                                 else { "risk-low" }
                    
                    # Determine status based on count
                    $status = if ($data.Count -gt 0) { "Failed" } else { "Passed" }
                    $statusClass = if ($data.Count -gt 0) { "status-failed" } else { "status-passed" }
                    $statusIcon = if ($data.Count -gt 0) { "&#10060;" } else { "&#9989;" }
                    
                    # Get modal ID from shared mapping
                    $modalId = if ($modalIdMap.ContainsKey($activityName)) { $modalIdMap[$activityName] } else { '' }
                    
                    $html += @"
                        <tr onclick="openModal('$modalId')" style="cursor: pointer; transition: all 0.2s ease;" 
                            onmouseenter="this.style.backgroundColor='#f8f9fa'; this.style.transform='scale(1.01)'; this.style.boxShadow='0 4px 8px rgba(0,0,0,0.1)';" 
                            onmouseleave="this.style.backgroundColor=''; this.style.transform='scale(1)'; this.style.boxShadow='';"
                            title="Click to view detailed information about $activityName">
                            <td>
                                <div class="activity-name-cell">
                                    <div class="activity-icon" style="background: $($activity.IconBg); color: $($activity.IconColor); transition: all 0.2s;">$($activity.Icon)</div>
                                    <div>
                                        <div style="font-weight: 500;">$activityName</div>
                                    </div>
                                </div>
                            </td>
                            <td>
                                <span class="risk-level-badge $riskClass" style="transition: all 0.2s;">$riskLevel</span>
                            </td>
                            <td style="text-align: center;">
                                <span class="detections-count" style="font-weight: 600; color: $(if ($data.Count -gt 0) { '#e74c3c' } else { '#2ecc71' });">$($data.Count)</span>
                            </td>
                            <td style="text-align: center;">
                                <span class="weight-cell" style="color: #7f8c8d;">$($data.Weight)%</span>
                            </td>
                            <td style="text-align: center;">
                                <span style="font-size: 18px; color: #3498db; transition: all 0.2s;" class="view-icon">&#128269;</span>
                            </td>
                            <td>
                                <span class="status-badge $statusClass" style="transition: all 0.2s;">$statusIcon $status</span>
                            </td>
                        </tr>
"@
                }
            }
            
            $html += @"
                    </tbody>
                </table>
"@
        } else {
            $html += @"
                <div style="text-align: center; padding: 40px; color: #7f8c8d;">
                    <div style="font-size: 48px; margin-bottom: 16px;">&#128196;</div>
                    <div style="font-size: 16px;">No audit log data available for analysis</div>
                    <div style="font-size: 14px; margin-top: 8px;">Run audit log export to analyze suspicious activities</div>
                </div>
"@
        }
        
        $html += @"
            </div>
        </div>
        </div>
        <!-- End Suspicious Activities Section -->
"@
    }
    
    # Show Security Recommendations section for all risk levels
    $html += @"
        
        <!-- Recommendations Section -->
        <div id="section-recommendations" class="section-wrapper">
        <div class="recommendations">
            <div class="section-title">&#128161; Security Recommendations & Best Practices</div>
            
            <!-- Disclaimer Box -->
            <div class="disclaimer-box">
                <div class="disclaimer-title">Disclaimer / Authorized Test</div>
                <div id="authorizedTestInfo" style="font-size: 15px; color: #555; line-height: 1.8; margin-bottom: 8px;">
"@
    
    # Add appropriate disclaimer based on risk level
    if ($suspiciousRiskScore -ge 50 -or $score -ge 50) {
        # High/Critical risk - show immediate action disclaimer
        $html += @"
                    <p style="margin: 0 0 12px 0;"><strong>&#9889; If the account is confirmed to be compromised:</strong> Follow the recommendations below immediately to secure the account and reduce risk exposure.</p>
                    <p style="margin: 0;"><strong>&#128274; If authorized testing:</strong> These activities may be part of an approved red team exercise or penetration test. You can hide recommendations after confirming, however ensure all security controls are properly reviewed and applied where appropriate.</p>
"@
    } else {
        # Low/Medium risk - show preventive disclaimer
        $html += @"
                    <p style="margin: 0 0 12px 0; background-color: #e8f5e9; padding: 12px; border-radius: 6px; border-left: 4px solid #4caf50;"><strong style="color: #2e7d32;">&#9432; Information Notice:</strong> Although the Account Suspicious Behavior Score and Suspicious Activities Score are not at high or critical levels, we recommend reviewing the following security recommendations and best practices to ensure your account protection remains strong.</p>
                    <p style="margin: 12px 0 0 0;"><strong>&#128274; If authorized testing:</strong> These activities may be part of an approved red team exercise or penetration test. You can hide recommendations after confirming, however ensure all security controls are properly reviewed and applied where appropriate.</p>
"@
    }
    
    $html += @"
                </div>
                <div class="checkbox-container">
                    <input type="checkbox" id="authorizedTestCheckbox">
                    <label for="authorizedTestCheckbox">I confirm this is an authorized security test (Red Team / Penetration Test)</label>
                    <button id="applySkipBtn" class="action-button hide-btn" disabled>Hide Recommendations</button>
                    <button id="restoreRecommendationsBtn" class="action-button show-btn" style="display:none;">Show Recommendations</button>
                </div>
                <div id="skipNotice" class="notice-box" style="display:none;">
                    &#10003; Recommendations are currently hidden because this report is marked as part of an authorized test. Ensure you have reviewed and applied the recommendations where appropriate.
                </div>
            </div>
            
            <div id="recommendationsContent">
"@
        $html += @"
            <!-- CRITICAL Priority -->
            <div class="recommendation-item" style="border-left-color: #e74c3c;" onclick="toggleRecommendation(this)">
                <div class="recommendation-header">
                    <div class="recommendation-left">
                        <div class="recommendation-icon">&#128274;</div>
                        <div class="recommendation-text">
                            <div class="recommendation-title"><span class="immediate-action-text">IMMEDIATE ACTION:</span> Revoke User Tokens</div>
                        </div>
                    </div>
                    <div class="recommendation-right">
                        <span class="recommendation-expand-text">Show Details</span>
                        <span class="priority-badge" style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); color: white; padding: 4px 10px; border-radius: 12px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; box-shadow: 0 2px 4px rgba(231, 76, 60, 0.3);">&#128680; CRITICAL</span>
                    </div>
                </div>
                <div class="recommendation-details">
                    <strong style="color: #e74c3c;">Immediate Action Required</strong><br>
                        Once a refresh token is revoked, it is no longer valid. When the associated access token expires, the user will be prompted to re-authenticate. It is crucial to use the Entra ID portal, Microsoft Graph, or Entra ID PowerShell in addition to resetting passwords to complete the revocation process.<br><br>
                        &#128218; <a href="https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access" target="_blank" style="color: #667eea; font-weight: 600;">Learn more about Revoking Access &rarr;</a>
                </div>
            </div>
            <div class="recommendation-item" style="border-left-color: #e74c3c;" onclick="toggleRecommendation(this)">
                <div class="recommendation-header">
                    <div class="recommendation-left">
                        <div class="recommendation-icon">&#128273;</div>
                        <div class="recommendation-text">
                            <div class="recommendation-title"><span class="immediate-action-text">IMMEDIATE ACTION:</span> Reset User Password</div>
                        </div>
                    </div>
                    <div class="recommendation-right">
                        <span class="recommendation-expand-text">Show Details</span>
                        <span class="priority-badge" style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); color: white; padding: 4px 10px; border-radius: 12px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; box-shadow: 0 2px 4px rgba(231, 76, 60, 0.3);">&#128680; CRITICAL</span>
                    </div>
                </div>
                <div class="recommendation-details">
                    <strong style="color: #e74c3c;">Immediate Action Required</strong><br>
                        Immediately reset the user's password to prevent unauthorized access. Ensure the new password is strong, unique, and follows your organization's password policy.<br><br>
                        &#128218; <a href="https://learn.microsoft.com/en-us/entra/fundamentals/users-reset-password-azure-portal" target="_blank" style="color: #667eea; font-weight: 600;">Password Reset Instructions &rarr;</a>
                </div>
            </div>
            
            <!-- HIGH Priority -->
            <div class="recommendation-item" style="border-left-color: #f39c12;" onclick="toggleRecommendation(this)">
                <div class="recommendation-header">
                    <div class="recommendation-left">
                        <div class="recommendation-icon">&#9889;</div>
                        <div class="recommendation-text">
                            <div class="recommendation-title">Enable Continuous Access Evaluation (CAE)</div>
                        </div>
                    </div>
                    <div class="recommendation-right">
                        <span class="recommendation-expand-text">Show Details</span>
                        <span class="priority-badge" style="background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); color: white; padding: 4px 10px; border-radius: 12px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; box-shadow: 0 2px 4px rgba(243, 156, 18, 0.3);">&#9888; HIGH</span>
                    </div>
                </div>
                <div class="recommendation-details">
                    <strong style="color: #f39c12;">High Priority Recommendation</strong><br>
                        Revoking refresh tokens does not immediately invalidate access tokens (they may remain valid up to an hour). Entra ID supports continuous access evaluation for Exchange, SharePoint and Teams, allowing near-real-time revocation after critical events. This significantly reduces the delay between token revocation and access token expiry.<br><br>
                        &#128218; <a href="https://learn.microsoft.com/azure/active-directory/conditional-access/concept-continuous-access-evaluation" target="_blank" style="color: #667eea; font-weight: 600;">About Continuous Access Evaluation &rarr;</a>
                    </div>
                </div>
            </div>
            <div class="recommendation-item" style="border-left-color: #f39c12;" onclick="toggleRecommendation(this)">
                <div class="recommendation-header">
                    <div class="recommendation-left">
                        <div class="recommendation-icon">&#128737;</div>
                        <div class="recommendation-text">
                            <div class="recommendation-title">Implement MFA with Conditional Access</div>
                        </div>
                    </div>
                    <div class="recommendation-right">
                        <span class="recommendation-expand-text">Show Details</span>
                        <span class="priority-badge" style="background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); color: white; padding: 4px 10px; border-radius: 12px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; box-shadow: 0 2px 4px rgba(243, 156, 18, 0.3);">&#9888; HIGH</span>
                    </div>
                </div>
                <div class="recommendation-details">
                    <strong style="color: #f39c12;">High Priority Recommendation</strong><br>
                        Use Multi-Factor Authentication with Conditional Access to evaluate sign-ins using identity-driven signals including user/group membership, IP location, device compliance status, and risk levels. This provides an additional layer of security beyond just passwords.<br><br>
                        &#128218; <a href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-mfa-strength" target="_blank" style="color: #667eea; font-weight: 600;">Configure MFA + Conditional Access &rarr;</a>
                </div>
            </div>
            <div class="recommendation-item" style="border-left-color: #f39c12;" onclick="toggleRecommendation(this)">
                <div class="recommendation-header">
                    <div class="recommendation-left">
                        <div class="recommendation-icon">&#128737;</div>
                        <div class="recommendation-text">
                            <div class="recommendation-title">Enable Identity Protection</div>
                        </div>
                    </div>
                    <div class="recommendation-right">
                        <span class="recommendation-expand-text">Show Details</span>
                        <span class="priority-badge" style="background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); color: white; padding: 4px 10px; border-radius: 12px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; box-shadow: 0 2px 4px rgba(243, 156, 18, 0.3);">&#9888; HIGH</span>
                    </div>
                </div>
                <div class="recommendation-details">
                    <strong style="color: #f39c12;">High Priority Recommendation</strong><br>
                        Microsoft Entra ID Identity Protection uses machine learning to detect and automatically respond to identity-based risks. It provides risk-based conditional access policies, automated remediation, and comprehensive risk investigation tools to protect your organization.<br><br>
                        &#128218; <a href="https://learn.microsoft.com/en-us/entra/id-protection/overview-identity-protection" target="_blank" style="color: #667eea; font-weight: 600;">Identity Protection Overview &rarr;</a>
                </div>
            </div>
            
            <!-- MEDIUM Priority -->
            <div class="recommendation-item" style="border-left-color: #3498db;" onclick="toggleRecommendation(this)">
                <div class="recommendation-header">
                    <div class="recommendation-left">
                        <div class="recommendation-icon">&#128274;</div>
                        <div class="recommendation-text">
                            <div class="recommendation-title">Enable Token Protection</div>
                        </div>
                    </div>
                    <div class="recommendation-right">
                        <span class="recommendation-expand-text">Show Details</span>
                        <span class="priority-badge" style="background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); color: white; padding: 4px 10px; border-radius: 12px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; box-shadow: 0 2px 4px rgba(52, 152, 219, 0.3);">&#128259; MEDIUM</span>
                    </div>
                </div>
                <div class="recommendation-details">
                    <strong style="color: #3498db;">Medium Priority Recommendation</strong><br>
                        Token Protection binds tokens to the device they were issued to, preventing token theft and replay attacks. When enabled, tokens can only be used from the device they were originally issued to, significantly reducing the risk of stolen credentials.<br><br>
                        &#128218; <a href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection" target="_blank" style="color: #667eea; font-weight: 600;">Learn about Token Protection &rarr;</a>
                </div>
            </div>
            <div class="recommendation-item" style="border-left-color: #3498db;" onclick="toggleRecommendation(this)">
                <div class="recommendation-header">
                    <div class="recommendation-left">
                        <div class="recommendation-icon">&#127760;</div>
                        <div class="recommendation-text">
                            <div class="recommendation-title">Deploy Global Secure Access (GSA)</div>
                        </div>
                    </div>
                    <div class="recommendation-right">
                        <span class="recommendation-expand-text">Show Details</span>
                        <span class="priority-badge" style="background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); color: white; padding: 4px 10px; border-radius: 12px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; box-shadow: 0 2px 4px rgba(52, 152, 219, 0.3);">&#128259; MEDIUM</span>
                    </div>
                </div>
                <div class="recommendation-details">
                    <strong style="color: #3498db;">Medium Priority Recommendation</strong><br>
                        Enable Conditional Access with Global Secure Access to provide secure access to all apps and resources from anywhere. GSA offers unified security service edge (SSE) capabilities including secure web gateway, cloud access security broker, and private access.<br><br>
                        &#128218; <a href="https://learn.microsoft.com/en-us/entra/global-secure-access/concept-universal-conditional-access" target="_blank" style="color: #667eea; font-weight: 600;">About Global Secure Access &rarr;</a>
                </div>
            </div>
            <div class="recommendation-item" style="border-left-color: #3498db;" onclick="toggleRecommendation(this)">
                <div class="recommendation-header">
                    <div class="recommendation-left">
                        <div class="recommendation-icon">&#128272;</div>
                        <div class="recommendation-text">
                            <div class="recommendation-title">Implement Passwordless Authentication</div>
                        </div>
                    </div>
                    <div class="recommendation-right">
                        <span class="recommendation-expand-text">Show Details</span>
                        <span class="priority-badge" style="background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); color: white; padding: 4px 10px; border-radius: 12px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; box-shadow: 0 2px 4px rgba(52, 152, 219, 0.3);">&#128259; MEDIUM</span>
                    </div>
                </div>
                <div class="recommendation-details">
                    <strong style="color: #3498db;">Medium Priority Recommendation</strong><br>
                        Make MFA phish-resistant by using FIDO2 security keys, Windows Hello for Business, or certificate-based authentication. Passwordless authentication eliminates the risk of password-based attacks including phishing, credential stuffing, and password spray attacks.<br><br>
                        &#128218; <a href="https://www.microsoft.com/en-us/security/business/solutions/passwordless-authentication" target="_blank" style="color: #667eea; font-weight: 600;">Passwordless Authentication Options &rarr;</a>
                </div>
            </div>
            
            <!-- LOW Priority -->
            <div class="recommendation-item" style="border-left-color: #27ae60;" onclick="toggleRecommendation(this)">
                <div class="recommendation-header">
                    <div class="recommendation-left">
                        <div class="recommendation-icon">&#9201;</div>
                        <div class="recommendation-text">
                            <div class="recommendation-title">Optimize Token Lifetime Settings</div>
                        </div>
                    </div>
                    <div class="recommendation-right">
                        <span class="recommendation-expand-text">Show Details</span>
                        <span class="priority-badge" style="background: linear-gradient(135deg, #27ae60 0%, #229954 100%); color: white; padding: 4px 10px; border-radius: 12px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; box-shadow: 0 2px 4px rgba(39, 174, 96, 0.3);">&#9989; LOW</span>
                    </div>
                </div>
                <div class="recommendation-details">
                    <strong style="color: #27ae60;">Low Priority Recommendation</strong><br>
                        Consider reducing token lifetime for high-risk users or applications. Shorter token lifetimes reduce the window of opportunity for attackers to exploit stolen tokens. Balance security requirements with user experience when configuring these settings.<br><br>
                        &#128218; <a href="https://learn.microsoft.com/en-us/entra/identity-platform/configurable-token-lifetimes" target="_blank" style="color: #667eea; font-weight: 600;">Configure Token Lifetimes &rarr;</a>
                </div>
            </div>
            </div>
        </div>
    </div>
"@
    
    $html += @"
    
    <!-- Modal Windows -->
    <!-- Sign-In Events Modal -->
    <div id="modal-signins" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: middle;">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                        <circle cx="12" cy="7" r="4"></circle>
                    </svg>
                    All Sign-In Events
                </h2>
                <button class="modal-close" onclick="closeModal('modal-signins')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box">
                        <div class="stat-value">$($AnalysisResults.TotalSignIns)</div>
                        <div class="stat-label">Total Events</div>
                    </div>
                    <div class="modal-stat-box">
                        <div class="stat-value">$($AnalysisResults.SuccessfulSignIns)</div>
                        <div class="stat-label">Successful</div>
                    </div>
                    <div class="modal-stat-box">
                        <div class="stat-value">$($AnalysisResults.FailedSignIns)</div>
                        <div class="stat-label">Failed</div>
                    </div>
                </div>
                <p style="color: #7f8c8d; font-size: 14px; margin-bottom: 20px;">
                    Complete list of all sign-in events analyzed for user <strong>$($AnalysisResults.UserDisplayName)</strong>
                </p>
"@
    
    if ($AnalysisResults.TotalSignIns -gt 0) {
        $html += "<div style='background: #f8f9fa; padding: 16px; border-radius: 8px; text-align: center;'>"
        $html += "<p style='margin: 0; color: #2c3e50;'><svg width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' style='vertical-align: middle;'><path d='M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z'></path><polyline points='13 2 13 9 20 9'></polyline></svg> For detailed event information, please refer to the CSV export file.</p>"
        $html += "</div>"
    }
    
    $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-signins')" style="background: #667eea; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    
    <!-- Countries Modal -->
    <div id="modal-countries" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: middle;">
                        <circle cx="12" cy="12" r="10"></circle>
                        <line x1="2" y1="12" x2="22" y2="12"></line>
                        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                    </svg>
                    Unique Countries
                </h2>
                <button class="modal-close" onclick="closeModal('modal-countries')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box">
                        <div class="stat-value">$($AnalysisResults.UniqueCountries)</div>
                        <div class="stat-label">Total Countries</div>
                    </div>
                </div>
"@
    
    if ($AnalysisResults.LocationsList -and $AnalysisResults.LocationsList.Count -gt 0) {
        $html += @"
                <div style='margin-top: 20px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#127758; Countries List:</div>
                        <button onclick="exportIndicatorData('modal-countries', 'Countries')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-countries' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #00b894;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>User</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Application</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>City</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Status</th>
                            </tr>
                        </thead>
                        <tbody>
"@
        foreach ($locationInfo in ($AnalysisResults.LocationsList | Sort-Object Country)) {
            $statusBadge = if ($locationInfo.Status -eq 'Success') { "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>" } else { "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>" }
            $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($locationInfo.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($locationInfo.User)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($locationInfo.Application)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($locationInfo.City)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 600;'>$($locationInfo.Count)</td>
                                <td style='padding: 10px 8px;'>$statusBadge</td>
                            </tr>
"@
        }
        $html += @"
                        </tbody>
                    </table>
                </div>
"@
    } else {
        $html += "<div class='empty-state'><div class='empty-state-icon'><svg width='48' height='48' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><circle cx='11' cy='11' r='8'></circle><path d='m21 21-4.35-4.35'></path></svg></div><p>No location data available</p></div>"
    }
    
    $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-countries')" style="background: #00b894; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    
    <!-- IP Addresses Modal -->
    <div id="modal-ips" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: middle;">
                        <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
                        <line x1="8" y1="21" x2="16" y2="21"></line>
                        <line x1="12" y1="17" x2="12" y2="21"></line>
                    </svg>
                    Unique IP Addresses
                </h2>
                <button class="modal-close" onclick="closeModal('modal-ips')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box">
                        <div class="stat-value">$($AnalysisResults.UniqueIPs)</div>
                        <div class="stat-label">Total IP Addresses</div>
                    </div>
                </div>
"@
    
    if ($AnalysisResults.IPsList -and $AnalysisResults.IPsList.Count -gt 0) {
        $html += @"
                <div style='margin-top: 20px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#128187; IP Addresses List:</div>
                        <button onclick="exportIndicatorData('modal-ips', 'IP_Addresses')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-ips' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #0984e3;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>User</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Application</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>IP Address</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>City</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Status</th>
                            </tr>
                        </thead>
                        <tbody>
"@
        foreach ($ipInfo in ($AnalysisResults.IPsList | Sort-Object IPAddress)) {
            $statusBadge = if ($ipInfo.Status -eq 'Success') { "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>" } else { "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>" }
            $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($ipInfo.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($ipInfo.User)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($ipInfo.Application)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($ipInfo.IPAddress)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($ipInfo.City)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 600;'>$($ipInfo.Count)</td>
                                <td style='padding: 10px 8px;'>$statusBadge</td>
                            </tr>
"@
        }
        $html += @"
                        </tbody>
                    </table>
                </div>
"@
    } else {
        $html += "<div class='empty-state'><div class='empty-state-icon'><svg width='48' height='48' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><circle cx='11' cy='11' r='8'></circle><path d='m21 21-4.35-4.35'></path></svg></div><p>No IP address data available</p></div>"
    }
    
    $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-ips')" style="background: #0984e3; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    
    <!-- Failed Sign-Ins Modal -->
    <div id="modal-failed" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>&#9888; Failed Sign-ins</h2>
                <button class="modal-close" onclick="closeModal('modal-failed')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box">
                        <div class="stat-value">$($AnalysisResults.FailedSignIns)</div>
                        <div class="stat-label">Failed Attempts</div>
                    </div>
                    <div class="modal-stat-box">
                        <div class="stat-value">$($AnalysisResults.FailurePercentage)%</div>
                        <div class="stat-label">Failure Rate</div>
                    </div>
                </div>
"@
    
    if ($AnalysisResults.FailedSignInsList -and $AnalysisResults.FailedSignInsList.Count -gt 0) {
        $html += @"
                <div style='margin-top: 20px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#9888; Failed Sign-ins List:</div>
                        <button onclick="exportIndicatorData('modal-failed', 'Failed_Sign_Ins')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-failed' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #d63031;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>User</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Application</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Resource</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>IP Address</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>City</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>OS</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Error Code</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Failure Reason</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                            </tr>
                        </thead>
                        <tbody>
"@
        foreach ($failed in $AnalysisResults.FailedSignInsList) {
            $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($failed.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($failed.User)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($failed.Application)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($failed.Resource)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($failed.IPAddress)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($failed.City)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($failed.OperatingSystem)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($failed.ErrorCode)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($failed.FailureReason)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 600;'>$($failed.Count)</td>
                            </tr>
"@
        }
        $html += @"
                        </tbody>
                    </table>
                </div>
"@
    } else {
        $html += "<div class='empty-state'><div class='empty-state-icon'>&#9989;</div><p>No failed or interrupted sign-ins detected</p></div>"
    }
    
    $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-failed')" style="background: #d63031; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    
    <!-- Interrupted Sign-Ins Modal -->
    <div id="modal-interrupted" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>&#9888;&#65039; Interrupted Sign-Ins</h2>
                <button class="modal-close" onclick="closeModal('modal-interrupted')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box">
                        <div class="stat-value">$($AnalysisResults.InterruptedSignIns)</div>
                        <div class="stat-label">Interrupted Attempts</div>
                    </div>
                    <div class="modal-stat-box">
                        <div class="stat-value">$($AnalysisResults.InterruptedPercentage)%</div>
                        <div class="stat-label">Interrupted Rate</div>
                    </div>
                </div>
"@
    
    if ($AnalysisResults.InterruptedSignInsList -and $AnalysisResults.InterruptedSignInsList.Count -gt 0) {
        $html += @"
                <div style='margin-top: 20px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#9888;&#65039; Interrupted Sign-Ins List:</div>
                        <button onclick="exportIndicatorData('modal-interrupted', 'Interrupted_Sign_Ins')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-interrupted' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #f39c12;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>User</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Application</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Resource</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>IP Address</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>City</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>OS</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Error Code</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Reason</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                            </tr>
                        </thead>
                        <tbody>
"@
        foreach ($interrupted in $AnalysisResults.InterruptedSignInsList) {
            $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($interrupted.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($interrupted.User)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($interrupted.Application)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($interrupted.Resource)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($interrupted.IPAddress)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($interrupted.City)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($interrupted.OperatingSystem)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($interrupted.ErrorCode)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($interrupted.FailureReason)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 600;'>$($interrupted.Count)</td>
                            </tr>
"@
        }
        $html += @"
                        </tbody>
                    </table>
                </div>
"@
    } else {
        $html += "<div class='empty-state'><div class='empty-state-icon'>&#9989;</div><p>No interrupted sign-ins detected</p></div>"
    }
    
    $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-interrupted')" style="background: #f39c12; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    
    <!-- Session IDs Modal -->
    <div id="modal-sessions" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>&#128274; Session IDs</h2>
                <button class="modal-close" onclick="closeModal('modal-sessions')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box">
                        <div class="stat-value">$($AnalysisResults.UniqueSessionIds)</div>
                        <div class="stat-label">Unique Sessions</div>
                    </div>
                </div>
"@
    
    if ($AnalysisResults.SessionIdsList -and $AnalysisResults.SessionIdsList.Count -gt 0) {
        $html += @"
                <div style='margin-top: 20px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#128274; Session IDs List:</div>
                        <button onclick="exportIndicatorData('modal-sessions', 'Session_IDs')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-sessions' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #fdcb6e;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>User</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Application</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>City</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Session ID</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Status</th>
                            </tr>
                        </thead>
                        <tbody>
"@
        foreach ($sessionInfo in ($AnalysisResults.SessionIdsList | Sort-Object SessionID)) {
            $statusBadge = if ($sessionInfo.Status -eq 'Success') { "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>" } else { "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>" }
            $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($sessionInfo.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($sessionInfo.User)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($sessionInfo.Application)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($sessionInfo.City)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-family: monospace; font-size: 11px;'>$($sessionInfo.SessionID)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 600;'>$($sessionInfo.Count)</td>
                                <td style='padding: 10px 8px;'>$statusBadge</td>
                            </tr>
"@
        }
        $html += @"
                        </tbody>
                    </table>
                </div>
"@
    } else {
        $html += "<div class='empty-state'><div class='empty-state-icon'>&#128269;</div><p>No session ID data available</p></div>"
    }
    
    $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-sessions')" style="background: #fdcb6e; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    
    <!-- Applications Modal -->
    <div id="modal-apps" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>&#128230; Applications</h2>
                <button class="modal-close" onclick="closeModal('modal-apps')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box">
                        <div class="stat-value">$($AnalysisResults.UniqueApplications)</div>
                        <div class="stat-label">Unique Apps</div>
                    </div>
                </div>
"@
    
    if ($AnalysisResults.ApplicationsList -and $AnalysisResults.ApplicationsList.Count -gt 0) {
        $html += @"
                <div style='margin-top: 20px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#128230; Applications List:</div>
                        <button onclick="exportIndicatorData('modal-apps', 'Applications')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-apps' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #a29bfe;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>User</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Application</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>City</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Status</th>
                            </tr>
                        </thead>
                        <tbody>
"@
        foreach ($appInfo in ($AnalysisResults.ApplicationsList | Sort-Object Application)) {
            $statusBadge = if ($appInfo.Status -eq 'Success') { "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>" } else { "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>" }
            $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($appInfo.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($appInfo.User)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($appInfo.Application)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($appInfo.City)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 600;'>$($appInfo.Count)</td>
                                <td style='padding: 10px 8px;'>$statusBadge</td>
                            </tr>
"@
        }
        $html += @"
                        </tbody>
                    </table>
                </div>
"@
    } else {
        $html += "<div class='empty-state'><div class='empty-state-icon'>&#128269;</div><p>No application data available</p></div>"
    }
    
    $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-apps')" style="background: #a29bfe; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    
    <!-- Successful Sign-Ins Modal -->
    <div id="modal-success" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>&#9989; Successful Sign-Ins</h2>
                <button class="modal-close" onclick="closeModal('modal-success')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box">
                        <div class="stat-value">$($AnalysisResults.SuccessfulSignIns)</div>
                        <div class="stat-label">Successful Logins</div>
                    </div>
                    <div class="modal-stat-box">
                        <div class="stat-value">$($AnalysisResults.SuccessPercentage)%</div>
                        <div class="stat-label">Success Rate</div>
                    </div>
                </div>
"@
    
    if ($AnalysisResults.SuccessfulSignInsList -and $AnalysisResults.SuccessfulSignInsList.Count -gt 0) {
        $html += @"
                <div style='margin-top: 20px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#9989; Successful Sign-Ins List:</div>
                        <button onclick="exportIndicatorData('modal-success', 'Successful_Sign_Ins')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-success' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #2ecc71;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>User</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Application</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Resource</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>IP Address</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>City</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>OS</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                            </tr>
                        </thead>
                        <tbody>
"@
        foreach ($success in $AnalysisResults.SuccessfulSignInsList) {
            $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($success.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($success.User)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($success.Application)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($success.Resource)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($success.IPAddress)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($success.City)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($success.OperatingSystem)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 600;'>$($success.Count)</td>
                            </tr>
"@
        }
        $html += @"
                        </tbody>
                    </table>
                </div>
"@
    } else {
        $html += "<div class='empty-state'><div class='empty-state-icon'>&#128269;</div><p>No successful sign-in data available</p></div>"
    }
    
    $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-success')" style="background: #2ecc71; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    
    <!-- Client Apps Modal -->
    <div id="modal-clientapps" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>&#128241; Client Apps</h2>
                <button class="modal-close" onclick="closeModal('modal-clientapps')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box">
                        <div class="stat-value">$($AnalysisResults.UniqueClientApps)</div>
                        <div class="stat-label">Unique Client Apps</div>
                    </div>
                </div>
"@
    
    if ($AnalysisResults.ClientAppsList -and $AnalysisResults.ClientAppsList.Count -gt 0) {
        $html += @"
                <div style='margin-top: 20px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#128241; Client Apps List:</div>
                        <button onclick="exportIndicatorData('modal-clientapps', 'Client_Apps')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-clientapps' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #e17055;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>User</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Application</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>City</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Client App</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Status</th>
                            </tr>
                        </thead>
                        <tbody>
"@
        foreach ($clientAppInfo in ($AnalysisResults.ClientAppsList | Sort-Object ClientApp)) {
            $statusBadge = if ($clientAppInfo.Status -eq 'Success') { "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>" } else { "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>" }
            $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($clientAppInfo.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($clientAppInfo.User)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($clientAppInfo.Application)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($clientAppInfo.City)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($clientAppInfo.ClientApp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 600;'>$($clientAppInfo.Count)</td>
                                <td style='padding: 10px 8px;'>$statusBadge</td>
                            </tr>
"@
        }
        $html += @"
                        </tbody>
                    </table>
                </div>
"@
    } else {
        $html += "<div class='empty-state'><div class='empty-state-icon'>&#128269;</div><p>No client app data available</p></div>"
    }
    
    $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-clientapps')" style="background: #e17055; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    
    <!-- Resources Modal -->
    <div id="modal-resources" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>&#128194; Resources</h2>
                <button class="modal-close" onclick="closeModal('modal-resources')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box">
                        <div class="stat-value">$($AnalysisResults.UniqueResources)</div>
                        <div class="stat-label">Unique Resources</div>
                    </div>
                </div>
"@
    
    if ($AnalysisResults.ResourcesList -and $AnalysisResults.ResourcesList.Count -gt 0) {
        $html += @"
                <div style='margin-top: 20px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#128194; Resources List:</div>
                        <button onclick="exportIndicatorData('modal-resources', 'Resources')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-resources' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #74b9ff;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>User</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Application</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>City</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Resource</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Status</th>
                            </tr>
                        </thead>
                        <tbody>
"@
        foreach ($resourceInfo in ($AnalysisResults.ResourcesList | Sort-Object Resource)) {
            $statusBadge = if ($resourceInfo.Status -eq 'Success') { "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>" } else { "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>" }
            $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($resourceInfo.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($resourceInfo.User)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($resourceInfo.Application)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($resourceInfo.City)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($resourceInfo.Resource)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 600;'>$($resourceInfo.Count)</td>
                                <td style='padding: 10px 8px;'>$statusBadge</td>
                            </tr>
"@
        }
        $html += @"
                        </tbody>
                    </table>
                </div>
"@
    } else {
        $html += "<div class='empty-state'><div class='empty-state-icon'>&#128269;</div><p>No resource data available</p></div>"
    }
    
    $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-resources')" style="background: #74b9ff; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    
    <!-- Operating Systems Modal -->
    <div id="modal-os" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>&#128187; Operating Systems</h2>
                <button class="modal-close" onclick="closeModal('modal-os')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box">
                        <div class="stat-value">$($AnalysisResults.UniqueOperatingSystems)</div>
                        <div class="stat-label">Unique OS</div>
                    </div>
                </div>
"@
    
    if ($AnalysisResults.OperatingSystemsList -and $AnalysisResults.OperatingSystemsList.Count -gt 0) {
        $html += @"
                <div style='margin-top: 20px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#128187; Operating Systems List:</div>
                        <button onclick="exportIndicatorData('modal-os', 'Operating_Systems')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-os' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #00cec9;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>User</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Application</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>City</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Operating System</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Status</th>
                            </tr>
                        </thead>
                        <tbody>
"@
        foreach ($osInfo in ($AnalysisResults.OperatingSystemsList | Sort-Object OperatingSystem)) {
            $statusBadge = if ($osInfo.Status -eq 'Success') { "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>" } else { "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>" }
            $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($osInfo.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($osInfo.User)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($osInfo.Application)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($osInfo.City)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($osInfo.OperatingSystem)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 600;'>$($osInfo.Count)</td>
                                <td style='padding: 10px 8px;'>$statusBadge</td>
                            </tr>
"@
        }
        $html += @"
                        </tbody>
                    </table>
                </div>
"@
    } else {
        $html += "<div class='empty-state'><div class='empty-state-icon'>&#128269;</div><p>No operating system data available</p></div>"
    }
    
    $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-os')" style="background: #00cec9; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    
    <!-- Off-Hours Sign-Ins Modal -->
    <div id="modal-signin-offhours" class="modal">
        <div class="modal-content">
            <div class="modal-header" style="background: linear-gradient(135deg, #d35400 0%, #e67e22 100%);">
                <h2>&#127769; Off-Hours Sign-Ins</h2>
                <button class="modal-close" onclick="closeModal('modal-signin-offhours')">&times;</button>
            </div>
            <div class="modal-body">
"@
    
    # Add Indicator Assessment section for Off-Hours Sign-Ins
    if ($AnalysisResults.Indicators.ContainsKey('Off-hours Activity')) {
        $indicator = $AnalysisResults.Indicators['Off-hours Activity']
        $indicatorScore = [Math]::Round($indicator.Score, 0)
        $badgeClass = Get-BadgeClassUpper -Score $indicatorScore
        $badgeColor = Get-ProgressColor -Score $indicatorScore
        
        $html += @"
                <div style='background: $($badgeColor)15; border-left: 4px solid $badgeColor; padding: 16px; margin-bottom: 20px; border-radius: 8px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <h3 style='margin: 0; color: #2c3e50; font-size: 18px;'>Indicator Assessment</h3>
                        <span style='background: $badgeColor; color: white; padding: 6px 16px; border-radius: 6px; font-size: 13px; font-weight: 600;'>$badgeClass - $indicatorScore%</span>
                    </div>
                    <div style='display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 12px;'>
                        <div style='background: white; padding: 12px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                            <div style='font-size: 11px; color: #7f8c8d; margin-bottom: 4px; text-transform: uppercase;'>Risk Score</div>
                            <div style='font-size: 24px; font-weight: 700; color: $badgeColor;'>$indicatorScore%</div>
                        </div>
                        <div style='background: white; padding: 12px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                            <div style='font-size: 11px; color: #7f8c8d; margin-bottom: 4px; text-transform: uppercase;'>Weight</div>
                            <div style='font-size: 24px; font-weight: 700; color: #2c3e50;'>$($indicator.Weight)%</div>
                        </div>
                        <div style='background: white; padding: 12px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                            <div style='font-size: 11px; color: #7f8c8d; margin-bottom: 4px; text-transform: uppercase;'>Detections</div>
                            <div style='font-size: 24px; font-weight: 700; color: #2c3e50;'>$($indicator.Count)</div>
                        </div>
                    </div>
                    <div style='width: 100%; background: #e0e0e0; height: 10px; border-radius: 5px; overflow: hidden;'>
                        <div style='width: $indicatorScore%; background: $badgeColor; height: 100%; transition: width 0.3s ease;'></div>
                    </div>
                </div>
"@
    }
    
    # Add disclaimer for Off-Hours Sign-Ins
    $html += Get-IndicatorDisclaimer -Icon '&#127769;' -Color '#d35400' `
        -BgColor '#fff9f0' -TextColor '#6b4a1a' `
        -Detection 'Counts successful sign-ins occurring outside configured working hours (default: M-F 8 AM - 6 PM, local time).' `
        -RiskFormula '<span style="background: white; padding: 3px 6px; border-radius: 4px; font-family: monospace; font-size: 11px;">If Count >= 2 -> Score = 100% | If Count = 1 -> Score = 50%</span> - Two or more off-hours sign-ins trigger maximum risk.' `
        -SecurityNote 'Off-hours access often correlates with compromise, especially when unusual for the user. Verify legitimacy of activity outside normal working hours.'
    
    $html += @"
                <div style='margin-top: 20px;'>
"@

    if ($AnalysisResults.OffHoursSignInsList -and $AnalysisResults.OffHoursSignInsList.Count -gt 0) {
        $html += @"
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#127769; Off-Hours Sign-Ins List:</div>
                        <button onclick="exportIndicatorData('modal-signin-offhours', 'OffHours_SignIns')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-signin-offhours' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #d35400;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50; width: 40px;'>#</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>User</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Application</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>IP Address</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>City</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Country</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Status</th>
                            </tr>
                        </thead>
                        <tbody>
"@
        $rowNumber = 1
        foreach ($item in $AnalysisResults.OffHoursSignInsList) {
            $statusBadge = if ($item.Status -eq 'Success') { "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>" } else { "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>" }
            $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #7f8c8d; font-weight: 600;'>$rowNumber</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($item.User)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Application)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($item.IPAddress)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($item.City)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Country)</td>
                                <td style='padding: 10px 8px;'>$statusBadge</td>
                            </tr>
"@
            $rowNumber++
        }
        $html += @"
                        </tbody>
                    </table>
"@
    } else {
        $html += "<div class='empty-state'><div class='empty-state-icon'>&#127769;</div><p>No off-hours sign-ins detected</p></div>"
    }

    $html += @"
                </div>
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-signin-offhours')" style="background: #d35400; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    
    <!-- Off-Hours Sign-Ins Modal for Sign-In Activity Metrics -->
    <div id="modal-signin-offhours-metrics" class="modal">
        <div class="modal-content">
            <div class="modal-header" style="background: linear-gradient(135deg, #d35400 0%, #e67e22 100%);">
                <h2>&#127769; Off-Hours Sign-Ins</h2>
                <button class="modal-close" onclick="closeModal('modal-signin-offhours-metrics')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box" style="background: linear-gradient(135deg, #d35400 0%, #e67e22 100%);">
                        <div class="stat-value">$($AnalysisResults.OffHoursSignIns)</div>
                        <div class="stat-label">Off-Hours Sign-Ins</div>
                    </div>
                </div>
                <div style='margin-top: 20px;'>
"@

    if ($AnalysisResults.OffHoursSignInsList -and $AnalysisResults.OffHoursSignInsList.Count -gt 0) {
        $html += @"
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#127769; Off-Hours Sign-Ins List:</div>
                        <button onclick="exportIndicatorData('modal-signin-offhours-metrics', 'OffHours_SignIns_Metrics')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-signin-offhours-metrics' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #d35400;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50; width: 40px;'>#</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>User</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Application</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>IP Address</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>City</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Country</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Status</th>
                            </tr>
                        </thead>
                        <tbody>
"@
        $rowNumber = 1
        foreach ($item in $AnalysisResults.OffHoursSignInsList) {
            $statusBadge = if ($item.Status -eq 'Success') { "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>" } else { "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>" }
            $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #7f8c8d; font-weight: 600;'>$rowNumber</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($item.User)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Application)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($item.IPAddress)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($item.City)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Country)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 600;'>$($item.Count)</td>
                                <td style='padding: 10px 8px;'>$statusBadge</td>
                            </tr>
"@
            $rowNumber++
        }
        $html += @"
                        </tbody>
                    </table>
"@
    } else {
        $html += "<div class='empty-state'><div class='empty-state-icon'>&#127769;</div><p>No off-hours sign-ins detected</p></div>"
    }

    $html += @"
                </div>
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-signin-offhours-metrics')" style="background: #d35400; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
"@
    
    # Add Audit Log Modals if available
    if ($AuditAnalysisResults) {
        $html += @"
    
    <!-- Audit Log Modals -->
    <!-- Total Audit Activities Modal -->
    <div id="modal-audit-total" class="modal">
        <div class="modal-content">
            <div class="modal-header" style="background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);">
                <h2>&#128202; Total Audit Activities</h2>
                <button class="modal-close" onclick="closeModal('modal-audit-total')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box" style="background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);">
                        <div class="stat-value">$($AuditAnalysisResults.TotalActivities)</div>
                        <div class="stat-label">Total Activities</div>
                    </div>
                </div>
                <div style='margin-top: 20px;'>
"@
        if ($AuditAnalysisResults.TotalActivitiesList -and $AuditAnalysisResults.TotalActivitiesList.Count -gt 0) {
            $html += @"
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#128202; All Audit Activities:</div>
                        <button onclick="exportIndicatorData('modal-audit-total', 'Total_Audit_Activities')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-audit-total' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #2c3e50;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Activity</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator UPN</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target Type</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target Name</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Result</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($activity in $AuditAnalysisResults.TotalActivitiesList) {
                $resultBadge = if ($activity.Result -eq 'success') { "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>" } else { "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>" }
                $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($activity.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($activity.Activity)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($activity.InitiatorUPN)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($activity.TargetType)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($activity.TargetDisplayName)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 600;'>$($activity.Count)</td>
                                <td style='padding: 10px 8px;'>$resultBadge</td>
                            </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
"@
        } else {
            $html += "<div class='empty-state'><div class='empty-state-icon'>&#128202;</div><p>No audit activities found</p></div>"
        }
        $html += @"
                </div>
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-audit-total')" style="background: #2c3e50; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>

    <!-- Successful Activities Modal -->
    <div id="modal-audit-success" class="modal">
        <div class="modal-content">
            <div class="modal-header" style="background: linear-gradient(135deg, #27ae60 0%, #229954 100%);">
                <h2>&#9989; Successful Activities</h2>
                <button class="modal-close" onclick="closeModal('modal-audit-success')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box" style="background: linear-gradient(135deg, #27ae60 0%, #229954 100%);">
                        <div class="stat-value">$($AuditAnalysisResults.SuccessfulActivities)</div>
                        <div class="stat-label">Successful Activities</div>
                    </div>
                </div>
                <div style='margin-top: 20px;'>
"@
        if ($AuditAnalysisResults.SuccessfulActivitiesList -and $AuditAnalysisResults.SuccessfulActivitiesList.Count -gt 0) {
            $html += @"
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#9989; Successful Activities:</div>
                        <button onclick="exportIndicatorData('modal-audit-success', 'Successful_Audit_Activities')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-audit-success' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #27ae60;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Activity</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator UPN</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target Type</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target Name</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($activity in $AuditAnalysisResults.SuccessfulActivitiesList) {
                $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($activity.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($activity.Activity)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($activity.InitiatorUPN)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($activity.TargetType)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($activity.TargetDisplayName)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($activity.Count)</td>
                            </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
"@
        } else {
            $html += "<div class='empty-state'>No successful activities found</div>"
        }
        $html += @"
                </div>
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-audit-success')" style="background: #27ae60; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>

    <!-- Failed Activities Modal -->
    <div id="modal-audit-failed" class="modal">
        <div class="modal-content">
            <div class="modal-header" style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);">
                <h2>&#10060; Failed Activities</h2>
                <button class="modal-close" onclick="closeModal('modal-audit-failed')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box" style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);">
                        <div class="stat-value">$($AuditAnalysisResults.FailedActivities)</div>
                        <div class="stat-label">Failed Activities</div>
                    </div>
                </div>
                <div style='margin-top: 20px;'>
"@
        if ($AuditAnalysisResults.FailedActivitiesList -and $AuditAnalysisResults.FailedActivitiesList.Count -gt 0) {
            $html += @"
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#10060; Failed Activities:</div>
                        <button onclick="exportIndicatorData('modal-audit-failed', 'Failed_Audit_Activities')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-audit-failed' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #e74c3c;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Activity</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator UPN</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target Type</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target Name</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Result Reason</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($activity in $AuditAnalysisResults.FailedActivitiesList) {
                $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($activity.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($activity.Activity)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($activity.InitiatorUPN)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($activity.TargetType)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($activity.TargetDisplayName)</td>
                                <td style='padding: 10px 8px; color: #e74c3c; font-size: 12px;'>$($activity.FailureReason)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($activity.Count)</td>
                            </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
"@
        } else {
            $html += "<div class='empty-state'>No failed activities found</div>"
        }
        $html += @"
                </div>
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-audit-failed')" style="background: #e74c3c; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>


    <!-- Password Changes Modal -->
    <div id="modal-audit-password" class="modal">
        <div class="modal-content">
            <div class="modal-header" style="background: linear-gradient(135deg, #e67e22 0%, #d35400 100%);">
                <h2>&#128273; Password Changes</h2>
                <button class="modal-close" onclick="closeModal('modal-audit-password')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box" style="background: linear-gradient(135deg, #e67e22 0%, #d35400 100%);">
                        <div class="stat-value">$($AuditAnalysisResults.PasswordChanges)</div>
                        <div class="stat-label">Password Changes</div>
                    </div>
                </div>
                <div style='margin-top: 20px;'>
"@
        if ($AuditAnalysisResults.PasswordChangesList -and $AuditAnalysisResults.PasswordChangesList.Count -gt 0) {
            $html += @"
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#128273; Password Changes List:</div>
                        <button onclick="exportIndicatorData('modal-audit-password', 'Password_Changes')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-audit-password' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #e67e22;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator UPN</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator Name</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator IP</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target Type</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target UPN</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Result</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($item in $AuditAnalysisResults.PasswordChangesList) {
                $resultBadge = if ($item.Result -eq 'success') { "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>" } else { "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>" }
                $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($item.InitiatorUPN)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.InitiatorDisplayName)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d; font-family: monospace;'>$($item.InitiatorIP)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($item.TargetType)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($item.TargetUPN)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Count)</td>
                                <td style='padding: 10px 8px;'>$resultBadge</td>
                            </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
"@
        }
    } else {
        $html += "<div class='empty-state'><div class='empty-state-icon'>&#9989;</div><p>No password changes detected</p></div>"
    }
    
    $html += "</div>"
        
        $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-audit-password')" style="background: #e67e22; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    
    <!-- Role Changes Modal -->
    <div id="modal-audit-roles" class="modal">
        <div class="modal-content">
            <div class="modal-header" style="background: linear-gradient(135deg, #9b59b6 0%, #8e44ad 100%);">
                <h2>&#128081; Role Changes</h2>
                <button class="modal-close" onclick="closeModal('modal-audit-roles')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box" style="background: linear-gradient(135deg, #9b59b6 0%, #8e44ad 100%);">
                        <div class="stat-value">$($AuditAnalysisResults.RoleChanges)</div>
                        <div class="stat-label">Role Changes</div>
                    </div>
                </div>
                <div style='margin-top: 20px;'>
"@
        if ($AuditAnalysisResults.RoleChangesList -and $AuditAnalysisResults.RoleChangesList.Count -gt 0) {
            $html += @"
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#128081; Role Changes List:</div>
                        <button onclick="exportIndicatorData('modal-audit-roles', 'Role_Changes')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-audit-roles' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #9b59b6;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Activity</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator UPN</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator Name</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator IP</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target Type</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target Name</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Result</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($item in $AuditAnalysisResults.RoleChangesList) {
                $resultBadge = if ($item.Result -eq 'success') { "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>" } else { "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>" }
                $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($item.Activity)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($item.InitiatorUPN)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.InitiatorDisplayName)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d; font-family: monospace;'>$($item.InitiatorIP)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($item.TargetType)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.TargetDisplayName)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Count)</td>
                                <td style='padding: 10px 8px;'>$resultBadge</td>
                            </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
"@
        } else {
            $html += "<div class='empty-state'><div class='empty-state-icon'>&#9989;</div><p>No role changes detected</p></div>"
        }
        
        $html += "</div>"
        
        $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-audit-roles')" style="background: #9b59b6; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    
    <!-- User Management Modal -->
    <div id="modal-audit-users" class="modal">
        <div class="modal-content">
            <div class="modal-header" style="background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);">
                <h2>&#128100; User Management Activities</h2>
                <button class="modal-close" onclick="closeModal('modal-audit-users')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box" style="background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);">
                        <div class="stat-value">$($AuditAnalysisResults.UserManagement)</div>
                        <div class="stat-label">User Management Activities</div>
                    </div>
                </div>
                <div style='margin-top: 20px;'>
"@
        if ($AuditAnalysisResults.UserManagementList -and $AuditAnalysisResults.UserManagementList.Count -gt 0) {
            $html += @"
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#128100; User Management List:</div>
                        <button onclick="exportIndicatorData('modal-audit-users', 'User_Management')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-audit-users' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #3498db;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Activity</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator UPN</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator Name</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator IP</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target Type</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target UPN</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Result</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($item in $AuditAnalysisResults.UserManagementList) {
                $resultBadge = if ($item.Result -eq 'success') { "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>" } else { "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>" }
                $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($item.Activity)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($item.InitiatorUPN)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.InitiatorDisplayName)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d; font-family: monospace;'>$($item.InitiatorIP)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($item.TargetType)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($item.TargetUPN)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 600;'>$($item.Count)</td>
                                <td style='padding: 10px 8px;'>$resultBadge</td>
                            </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
"@
        } else {
            $html += "<div class='empty-state'><div class='empty-state-icon'>&#128269;</div><p>No user management activities</p></div>"
        }
        
        $html += "</div>"
        
        $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-audit-users')" style="background: #3498db; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    
    <!-- App Activities Modal -->
    <div id="modal-audit-apps" class="modal">
        <div class="modal-content">
            <div class="modal-header" style="background: linear-gradient(135deg, #16a085 0%, #138d75 100%);">
                <h2>&#128230; Application Activities</h2>
                <button class="modal-close" onclick="closeModal('modal-audit-apps')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box" style="background: linear-gradient(135deg, #16a085 0%, #138d75 100%);">
                        <div class="stat-value">$($AuditAnalysisResults.AppActivities)</div>
                        <div class="stat-label">Application Activities</div>
                    </div>
                </div>
                <div style='margin-top: 20px;'>
"@
        if ($AuditAnalysisResults.AppActivitiesList -and $AuditAnalysisResults.AppActivitiesList.Count -gt 0) {
            $html += @"
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#128230; App Activities List:</div>
                        <button onclick="exportIndicatorData('modal-audit-apps', 'App_Activities')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-audit-apps' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #16a085;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Activity</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator UPN</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator Name</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator IP</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target Type</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target UPN</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Result</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($item in $AuditAnalysisResults.AppActivitiesList) {
                $resultBadge = if ($item.Result -eq 'success') { "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>" } else { "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>" }
                $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($item.Activity)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($item.InitiatorUPN)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.InitiatorDisplayName)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d; font-family: monospace;'>$($item.InitiatorIP)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($item.TargetType)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($item.TargetUPN)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Count)</td>
                                <td style='padding: 10px 8px;'>$resultBadge</td>
                            </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
"@
        } else {
            $html += "<div class='empty-state'><div class='empty-state-icon'>&#128269;</div><p>No application activities</p></div>"
        }
        
        $html += "</div>"
        
        $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-audit-apps')" style="background: #16a085; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    
    <!-- Group Changes Modal -->
    <div id="modal-audit-groups" class="modal">
        <div class="modal-content">
            <div class="modal-header" style="background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%);">
                <h2>&#128101; Group Changes</h2>
                <button class="modal-close" onclick="closeModal('modal-audit-groups')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box" style="background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%);">
                        <div class="stat-value">$($AuditAnalysisResults.GroupChanges)</div>
                        <div class="stat-label">Group Changes</div>
                    </div>
                </div>
                <div style='margin-top: 20px;'>
"@
        if ($AuditAnalysisResults.GroupChangesList -and $AuditAnalysisResults.GroupChangesList.Count -gt 0) {
            $html += @"
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#128101; Group Changes List:</div>
                        <button onclick="exportIndicatorData('modal-audit-groups', 'Group_Changes')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-audit-groups' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #f39c12;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Activity</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator UPN</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator Name</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator IP</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target Type</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target UPN</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Result</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($item in $AuditAnalysisResults.GroupChangesList) {
                $resultBadge = if ($item.Result -eq 'success') { "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>" } else { "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>" }
                $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($item.Activity)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($item.InitiatorUPN)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.InitiatorDisplayName)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d; font-family: monospace;'>$($item.InitiatorIP)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($item.TargetType)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($item.TargetUPN)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Count)</td>
                                <td style='padding: 10px 8px;'>$resultBadge</td>
                            </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
"@
        } else {
            $html += "<div class='empty-state'><div class='empty-state-icon'>&#128269;</div><p>No group changes detected</p></div>"
        }
        
        $html += "</div>"
        
        $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-audit-groups')" style="background: #f39c12; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    
    <!-- MFA Changes Modal -->
    <div id="modal-audit-mfa" class="modal">
        <div class="modal-content">
            <div class="modal-header" style="background: linear-gradient(135deg, #8e44ad 0%, #71368a 100%);">
                <h2>&#128274; MFA Changes</h2>
                <button class="modal-close" onclick="closeModal('modal-audit-mfa')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box" style="background: linear-gradient(135deg, #8e44ad 0%, #71368a 100%);">
                        <div class="stat-value">$($AuditAnalysisResults.MFAChanges)</div>
                        <div class="stat-label">MFA Changes</div>
                    </div>
                </div>
                <p style="color: #7f8c8d; font-size: 14px; margin-bottom: 20px;">
                    Changes to multi-factor authentication settings and authentication methods
                </p>
                <div style='margin-top: 20px;'>
"@
        if ($AuditAnalysisResults.MFAChangesList -and $AuditAnalysisResults.MFAChangesList.Count -gt 0) {
            $html += @"
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#128274; MFA Changes List:</div>
                        <button onclick="exportIndicatorData('modal-audit-mfa', 'MFA_Changes')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-audit-mfa' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #8e44ad;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Activity</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Operation Type</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator UPN</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target Type</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target Name</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Result</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($item in $AuditAnalysisResults.MFAChangesList) {
                $resultBadge = if ($item.Result -eq 'success') { "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>" } else { "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>" }
                $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($item.Activity)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.OperationType)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($item.InitiatorUPN)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($item.TargetType)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.TargetDisplayName)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Count)</td>
                                <td style='padding: 10px 8px;'>$resultBadge</td>
                            </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
"@
        } else {
            $html += "<div class='empty-state'><div class='empty-state-icon'>&#128274;</div><p>No MFA changes detected</p></div>"
        }
        
        $html += "</div>"
        
        $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-audit-mfa')" style="background: #8e44ad; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    
    <!-- Off-Hours Activities Modal -->
    <div id="modal-audit-offhours" class="modal">
        <div class="modal-content">
            <div class="modal-header" style="background: linear-gradient(135deg, #d35400 0%, #ba4a00 100%);">
                <h2>&#127769; Off-Hours Activities</h2>
                <button class="modal-close" onclick="closeModal('modal-audit-offhours')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="modal-stats">
                    <div class="modal-stat-box" style="background: linear-gradient(135deg, #d35400 0%, #ba4a00 100%);">
                        <div class="stat-value">$($AuditAnalysisResults.OffHoursActivities)</div>
                        <div class="stat-label">Off-Hours Activities</div>
                    </div>
                </div>
                <p style="color: #7f8c8d; font-size: 14px; margin-bottom: 20px;">
                    Activities performed between 11 PM and 5 AM (UTC)
                </p>
                <div style='margin-top: 20px;'>
"@
        if ($AuditAnalysisResults.OffHoursActivitiesList -and $AuditAnalysisResults.OffHoursActivitiesList.Count -gt 0) {
            $html += @"
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>&#127769; Off-Hours Activities List:</div>
                        <button onclick="exportIndicatorData('modal-audit-offhours', 'OffHours_Activities')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <table id='table-modal-audit-offhours' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                        <thead>
                            <tr style='background: #f8f9fa; border-bottom: 2px solid #d35400;'>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Date (UTC)</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Activity</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Operation Type</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Initiator UPN</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target Type</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Target Name</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Count</th>
                                <th style='padding: 12px 8px; text-align: left; font-weight: 600; color: #2c3e50;'>Result</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($item in $AuditAnalysisResults.OffHoursActivitiesList) {
                $resultBadge = if ($item.Result -eq 'success') { "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>" } else { "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>" }
                $html += @"
                            <tr style='border-bottom: 1px solid #ecf0f1;'>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Timestamp)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-weight: 500;'>$($item.Activity)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.OperationType)</td>
                                <td style='padding: 10px 8px; color: #34495e; font-size: 12px;'>$($item.InitiatorUPN)</td>
                                <td style='padding: 10px 8px; color: #7f8c8d;'>$($item.TargetType)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.TargetDisplayName)</td>
                                <td style='padding: 10px 8px; color: #34495e;'>$($item.Count)</td>
                                <td style='padding: 10px 8px;'>$resultBadge</td>
                            </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
"@
        } else {
            $html += "<div class='empty-state'><div class='empty-state-icon'>&#127769;</div><p>No off-hours activities detected</p></div>"
        }
        
        $html += "</div>"
        
        $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('modal-audit-offhours')" style="background: #d35400; color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
    

"@
    
    # Generate modals for each audit indicator
    if ($AuditAnalysisResults -and $AuditAnalysisResults.Indicators) {
        $indicatorModals = @{
            'Off-Hours Password Change/Reset' = @{ Id = 'modal-indicator-password-changes'; Icon = '&#128273;'; Color = '#e67e22' }
            'Privileged Role Changes' = @{ Id = 'modal-indicator-role-changes'; Icon = '&#128081;'; Color = '#9b59b6' }
            'Off-Hours Audit Activity' = @{ Id = 'modal-indicator-offhours'; Icon = '&#127769;'; Color = '#d35400' }
            'Failed Audit Events' = @{ Id = 'modal-indicator-failed-audit'; Icon = '&#10060;'; Color = '#e74c3c' }
            'Authentication Info Changes' = @{ Id = 'modal-indicator-authmethod'; Icon = '&#128274;'; Color = '#3498db' }
            'Policy Changes' = @{ Id = 'modal-indicator-policy'; Icon = '&#128221;'; Color = '#16a085' }
            'Bulk Deletions' = @{ Id = 'modal-indicator-deletions'; Icon = '&#128465;'; Color = '#e74c3c' }
            'Consent to Application' = @{ Id = 'modal-indicator-consent'; Icon = '&#9989;'; Color = '#e67e22' }
            'Password Change' = @{ Id = 'modal-suspicious-password-change'; Icon = '&#128272;'; Color = '#3498db' }
            'Password Reset' = @{ Id = 'modal-suspicious-password-reset'; Icon = '&#128260;'; Color = '#f39c12' }
            'Update Application' = @{ Id = 'modal-hr-update-app'; Icon = '&#9999;'; Color = '#e67e22' }
            'Add Service Principal' = @{ Id = 'modal-hr-add-principal'; Icon = '&#128273;'; Color = '#e74c3c' }
            'Add App Role Assignment' = @{ Id = 'modal-hr-add-app-role'; Icon = '&#128274;'; Color = '#f39c12' }
            'Update Policy' = @{ Id = 'modal-hr-update-policy'; Icon = '&#128221;'; Color = '#e74c3c' }
            'Bulk Update User' = @{ Id = 'modal-hr-bulk-update-user'; Icon = '&#128101;'; Color = '#3498db' }
            'Add Owner to Application/Service Principal' = @{ Id = 'modal-hr-add-owner'; Icon = '&#128100;'; Color = '#6c5ce7' }
            'Update Service Principal' = @{ Id = 'modal-hr-update-service-principal'; Icon = '&#128295;'; Color = '#fdcb6e' }
            'Disable Account' = @{ Id = 'modal-hr-disable-account'; Icon = '&#128683;'; Color = '#e74c3c' }
        }
        
        # Disclaimer configurations for audit indicators
        $auditDisclaimers = @{
            'Off-Hours Password Change/Reset' = @{
                BgColor = '#fff4e6'; TextColor = '#6f4e37'
                Detection = 'Monitors all password change and password reset activities in audit logs and compares their timestamps against working hours.'
                RiskFormula = '<span style="background: white; padding: 4px 8px; border-radius: 4px; font-family: monospace; font-size: 12px;">If Count &gt;= 1 -&gt; Risk Score = 100%</span>'
                RiskExplanation = 'Any password change/reset outside working hours is flagged as critical (100% risk) due to the sensitivity of credential modifications.'
                Weight = '25%'; IsDetailed = $true
                SecurityNote = 'Off-hours password changes may indicate compromised credentials, unauthorized access, or malicious insider activity. Legitimate password resets rarely occur outside business hours.'
            }
            'Off-Hours Audit Activity' = @{
                BgColor = '#fff8f0'; TextColor = '#6b4a1a'
                Detection = 'Analyzes all audit log events and identifies activities performed outside working hours'
                RiskFormula = '<span style="background: white; padding: 4px 8px; border-radius: 4px; font-family: monospace; font-size: 12px;">Risk Score = Count x 10 (capped at 100%)</span>'
                RiskExplanation = 'Each off-hours event adds 10 points. Score reaches 100% at 10 or more events.'
                Weight = '25%'; IsDetailed = $true
                SecurityNote = 'Activities outside business hours can indicate unauthorized access, compromised accounts, or suspicious automation. Most legitimate activities occur during official working hours.'
            }
            'Failed Audit Events' = @{
                BgColor = '#ffebee'; TextColor = '#642424'
                Detection = 'Monitors all audit log events where the Result field is not ''success'', indicating failed operations or denied access attempts.'
                RiskFormula = '<span style="background: white; padding: 4px 8px; border-radius: 4px; font-family: monospace; font-size: 12px;">If Count &gt; 5 -&gt; Risk Score = 100%</span><br><span style="background: white; padding: 4px 8px; border-radius: 4px; font-family: monospace; font-size: 12px;">If Count &lt;= 5 -&gt; Risk Score = Count x 20</span>'
                RiskExplanation = 'High volume of failures (>5) triggers critical risk due to potential brute force or permission issues.'
                Weight = '25%'; IsDetailed = $true
                SecurityNote = 'Multiple failed audit events may indicate reconnaissance activity, privilege escalation attempts, misconfigured permissions, or an attacker testing various actions. Normal operations should have minimal failures.'
            }
            'Authentication Info Changes' = @{
                BgColor = '#e3f2fd'; TextColor = '#123448'
                Detection = 'Filters audit logs for events where Service = ''Authentication Methods'', capturing all MFA and authentication method modifications.'
                RiskFormula = '<span style="background: white; padding: 4px 8px; border-radius: 4px; font-family: monospace; font-size: 12px;">If Count &gt; 3 -&gt; Risk Score = 100%</span><br><span style="background: white; padding: 4px 8px; border-radius: 4px; font-family: monospace; font-size: 12px;">If Count &lt;= 3 -&gt; Risk Score = Count x 33</span>'
                RiskExplanation = 'More than 3 authentication method changes is flagged as critical due to potential account takeover or persistence attempts.'
                Weight = '25%'; IsDetailed = $true
                SecurityNote = 'Modifying authentication methods (adding/deleting MFA, phone numbers, authenticator apps) is a common persistence technique used by attackers to maintain access and bypass security controls.'
            }
            'Consent to Application' = @{
                BgColor = '#eef9f1'; TextColor = '#155724'
                Detection = 'Matches ''Consent to application'' in audit activities'
                RiskFormula = 'Score = Count x 30 (max 100%)'
                SecurityNote = 'Application consent grants can provide broad access to organizational data. Monitor for unfamiliar or suspicious app permissions.'
            }
            'Password Change' = @{
                BgColor = '#f0f7ff'; TextColor = '#123448'
                Detection = 'Matches ''Change password'' activities in audit logs'
                RiskFormula = 'Score = Count x 30 (max 100%)'
                SecurityNote = 'Multiple password changes may indicate compromised credentials, policy violations, or user credential issues requiring investigation.'
            }
            'Password Reset' = @{
                BgColor = '#fff7f0'; TextColor = '#6b4a1a'
                Detection = 'Regex pattern ''(?i)reset.*password'' in audit activities'
                RiskFormula = 'Score = Count x 30 (max 100%)'
                SecurityNote = 'Password resets can indicate social engineering attacks, helpdesk compromise, or legitimate credential recovery. Verify reset authenticity.'
            }
            'Privileged Role Changes' = @{
                BgColor = '#f6eefb'; TextColor = '#3b2a45'
                Detection = 'Monitors all role assignment and permission modification activities'
                RiskFormula = 'Score = Count x 20 (max 100%)'
                SecurityNote = 'Privileged role assignments are prime targets for privilege escalation. Unauthorized role changes can grant attackers admin-level access.'
            }
            'Policy Changes' = @{
                BgColor = '#eef7f4'; TextColor = '#0f4f45'
                Detection = 'Matches ''policy'' or ''conditional access'' keywords in activities'
                RiskFormula = 'Score = Count x 20 (max 100%)'
                SecurityNote = 'Policy modifications can weaken security controls, disable MFA requirements, or create backdoor access paths. Review all policy changes carefully.'
            }
            'Bulk Deletions' = @{
                BgColor = '#fff0f0'; TextColor = '#642424'
                Detection = 'Counts all deletion and removal activities in audit logs'
                RiskFormula = 'If Count > 5: Score = (Count - 5) x 15 (max 100%)'
                SecurityNote = 'Bulk deletions can indicate data destruction, sabotage, or cleanup after a breach. Threshold of 5+ triggers scoring to filter normal operations.'
            }
            'Update Application' = @{
                BgColor = '#fffaf0'; TextColor = '#5a3b1f'
                Detection = 'Matches ''Update application'' in audit activities'
                RiskFormula = 'Any detection = HIGH RISK (flagged for review)'
                SecurityNote = 'Application updates can modify permissions, redirect URLs, or add malicious functionality. All updates should be validated against change management.'
            }
            'Add Service Principal' = @{
                BgColor = '#fffaf0'; TextColor = '#5a2a20'
                Detection = 'Matches ''Add service principal'' activities'
                RiskFormula = 'Any detection = HIGH RISK'
                SecurityNote = 'Service principals can operate with elevated privileges and establish persistent access. Unauthorized additions are a common persistence mechanism.'
            }
            'Add App Role Assignment' = @{
                BgColor = '#fffaf0'; TextColor = '#5a3b1f'
                Detection = 'Matches ''Add app role assignment'' activities'
                RiskFormula = 'Any detection = HIGH RISK'
                SecurityNote = 'App role assignments grant applications permissions to access data. Unauthorized assignments can enable data exfiltration or privilege escalation.'
            }
            'Disable Account' = @{
                BgColor = '#fff0f0'; TextColor = '#642424'
                Detection = 'Matches ''Disable account'' audit activities'
                RiskFormula = 'Any detection = HIGH IMPACT'
                SecurityNote = 'Account disabling can be used for denial of service, disrupting operations, or covering tracks. Verify all account disablements are authorized.'
            }
            'Bulk Update User' = @{
                BgColor = '#fffaf0'; TextColor = '#5a3b1f'
                Detection = 'Identifies bulk user update operations'
                RiskFormula = 'Any detection = HIGH RISK'
                SecurityNote = 'Bulk user modifications can change contact info, permissions, or attributes across many accounts. Verify these are authorized administrative operations.'
            }
            'Add Owner to Application/Service Principal' = @{
                BgColor = '#f7f0ff'; TextColor = '#3b2a45'
                Detection = 'Matches ''Add owner to'' activities'
                RiskFormula = 'Any detection = SENSITIVE OPERATION'
                SecurityNote = 'Owners have full control over applications and service principals. Unauthorized owner additions enable attackers to modify credentials, permissions, and settings.'
            }
            'Update Service Principal' = @{
                BgColor = '#fffaf0'; TextColor = '#5a3b1f'
                Detection = 'Matches ''Update service principal'' activities'
                RiskFormula = 'Any detection = HIGH RISK'
                SecurityNote = 'Service principal updates can modify credentials, certificates, or permissions. Unauthorized changes enable persistent access and privilege escalation.'
            }
            'Update Policy' = @{
                BgColor = '#fff0f0'; TextColor = '#642424'
                Detection = 'Matches ''Update policy'' or policy modification patterns'
                RiskFormula = 'Any detection = HIGH RISK'
                SecurityNote = 'Policy updates can modify security controls and conditional access rules. Review all policy modifications carefully.'
            }
        }
        
        # Disclaimer configurations for sign-in indicators
        $signInDisclaimers = @{
            'Multiple IP Addresses' = @{
                BgColor = '#e8f6ff'; TextColor = '#073642'
                Detection = 'Scans 24-hour windows for users accessing from 2 or more unique IP addresses within the same day.'
                RiskFormula = '<span style="background: white; padding: 3px 6px; border-radius: 4px; font-family: monospace; font-size: 11px;">Score = Count x 30 (max 100%)</span> - Each 24-hour window with multiple IPs adds 30 points.'
                SecurityNote = 'Rapid IP changes can indicate account sharing, compromised credentials, VPN hopping, or attackers using multiple proxies to evade detection.'
            }
            'Password-spray' = @{
                BgColor = '#fff3e0'; TextColor = '#6f4e37'
                Detection = 'Identifies clusters of failed sign-ins with error code 50126 (invalid username/password). Looks for 10+ failures within a 60-minute sliding window.'
                RiskFormula = '<span style="background: white; padding: 3px 6px; border-radius: 4px; font-family: monospace; font-size: 11px;">Score = Count x 50 (max 100%)</span> - Each detected incident adds 50 points.'
                SecurityNote = 'Password-spray attacks use common passwords against many accounts to avoid lockouts. This is a common initial access technique used by attackers to compromise credentials without triggering brute-force detection.'
            }
            'Multiple Locations' = @{
                BgColor = '#f0f7ff'; TextColor = '#123448'
                Detection = 'Counts distinct sign-in cities from location data in sign-in logs.'
                RiskFormula = '<span style="background: white; padding: 3px 6px; border-radius: 4px; font-family: monospace; font-size: 11px;">If cities &gt; 1: Score ~ Count x 30 (max 100%)</span> - Each additional city beyond the first contributes approximately 30 points.'
                SecurityNote = 'Sign-ins from multiple geographic locations can indicate account compromise, especially if locations are geographically distant or impossible to travel between in the observed timeframe.'
            }
            'Failed/Interrupted Sign-ins' = @{
                BgColor = '#fff0f7'; TextColor = '#6f2740'
                Detection = 'Calculates the rate of sign-ins with status ''Failure'' or ''Interrupted'' across all sign-in attempts.'
                RiskFormula = '<span style="background: white; padding: 3px 6px; border-radius: 4px; font-family: monospace; font-size: 11px;">Score = Failure Rate x 2 (max 100%)</span> - Failure percentage multiplied by 2 to amplify risk signal.'
                SecurityNote = 'High failure rates can indicate credential stuffing attacks, password guessing attempts, or legitimate users with credential issues. Review error codes and patterns to distinguish attacks from user problems.'
            }
            'Risky Sign-ins' = @{
                BgColor = '#fff6ee'; TextColor = '#5a2a18'
                Detection = 'Uses Entra ID''s built-in risk detection fields (Risk State, Risk Level) to identify sign-ins flagged by Microsoft''s threat intelligence.'
                RiskFormula = '<span style="background: white; padding: 3px 6px; border-radius: 4px; font-family: monospace; font-size: 11px;">If any risky sign-ins detected -&gt; Score = 100%</span> - Any positive risk detection triggers maximum risk score.'
                SecurityNote = 'Risky sign-ins are flagged by Microsoft''s Identity Protection using machine learning and threat intelligence. These should be investigated immediately as they may indicate compromised credentials, malicious actors, or anomalous behavior.'
            }
            'Suspicious User Agents' = @{
                BgColor = '#f7f0ff'; TextColor = '#2c1540'
                Detection = 'Matches user-agent strings against patterns for non-browser tools (curl, wget, python, bot, scanner) and identifies missing user-agent headers.'
                RiskFormula = '<span style="background: white; padding: 3px 6px; border-radius: 4px; font-family: monospace; font-size: 11px;">Score = Count x 30 (max 100%)</span> - Each suspicious user-agent detection adds 30 points.'
                SecurityNote = 'Automated tools and scripts used for sign-ins may indicate API abuse, credential testing, or programmatic attacks. Legitimate users rarely sign in using command-line tools or scripts.'
            }
            'Off-hours Activity' = @{
                BgColor = '#fff9f0'; TextColor = '#6b4a1a'
                Detection = 'Counts successful sign-ins occurring outside configured working hours (default: 8 AM - 5 PM local time).'
                RiskFormula = '<span style="background: white; padding: 3px 6px; border-radius: 4px; font-family: monospace; font-size: 11px;">If Count &gt;= 2 -&gt; Score = 100% | If Count = 1 -&gt; Score = 50%</span> - Graduated risk based on frequency.'
                SecurityNote = 'Off-hours access may indicate compromised credentials used by attackers in different time zones, unauthorized access, or legitimate users working unusual hours. Context matters - verify if off-hours access is expected.'
            }
            'Multiple Devices' = @{
                BgColor = '#f0fff7'; TextColor = '#0b3f2b'
                Detection = 'Counts distinct operating systems detected in sign-in logs. Looks for variety beyond typical single or dual-device usage.'
                RiskFormula = '<span style="background: white; padding: 3px 6px; border-radius: 4px; font-family: monospace; font-size: 11px;">If OS Count &gt; 2: Score = (Count - 2) x 20 (max 100%)</span> - Each additional OS beyond 2 adds 20 points.'
                SecurityNote = 'Using many different devices/operating systems can indicate account sharing, compromised credentials accessed from multiple attacker devices, or token theft enabling access from various platforms.'
            }
            'Anonymous IP' = @{
                BgColor = '#f4f4f6'; TextColor = '#222'
                Detection = 'Detects anonymous infrastructure from risk event types, location fields indicating TOR/VPN/proxy usage, or network/ISP strings matching known anonymization services.'
                RiskFormula = '<span style="background: white; padding: 3px 6px; border-radius: 4px; font-family: monospace; font-size: 11px;">If any detection -&gt; Score = 100%</span> - Any anonymous IP usage triggers maximum risk.'
                SecurityNote = 'Anonymous IPs (TOR, VPNs, proxies) are commonly used by attackers to hide their true location and identity. While some legitimate users may use VPNs, anonymous infrastructure access should be scrutinized carefully.'
            }
            'Session IP Mismatch' = @{
                BgColor = '#fff4f4'; TextColor = '#5a2818'
                Detection = 'Compares authentication and token request IPs. Detects when session tokens are used from different IPs than where they were originally issued.'
                RiskFormula = '<span style="background: white; padding: 3px 6px; border-radius: 4px; font-family: monospace; font-size: 11px;">Score = Count x 30 (max 100%)</span> - Each IP mismatch adds 30 points.'
                SecurityNote = 'IP mismatches between authentication and token usage can indicate session hijacking, token theft, or lateral movement using stolen credentials. This is a strong indicator of post-compromise activity.'
            }
            'Brute-force' = @{
                BgColor = '#fff0f0'; TextColor = '#642424'
                Detection = 'Identifies clusters of failed sign-ins with error code 50126 (invalid username/password). Looks for 10+ failures within a 10-minute sliding window.'
                RiskFormula = '<span style="background: white; padding: 3px 6px; border-radius: 4px; font-family: monospace; font-size: 11px;">Score = Count x 50 (max 100%)</span> - Each detected incident adds 50 points.'
                SecurityNote = 'Brute-force attacks attempt to guess passwords through rapid repeated attempts. Multiple failures in a short time window indicate automated password cracking attempts against the account.'
            }
            'Account Lockout' = @{
                BgColor = '#fff7f0'; TextColor = '#6b4a1a'
                Detection = 'Counts sign-ins with error code 50053 indicating account lockout due to excessive failed attempts.'
                RiskFormula = '<span style="background: white; padding: 3px 6px; border-radius: 4px; font-family: monospace; font-size: 11px;">Score = Count x 40 (max 100%)</span> - Each lockout event adds 40 points.'
                SecurityNote = 'Account lockouts indicate either credential attacks or user credential issues. Multiple lockouts across accounts may indicate a coordinated attack campaign.'
            }
        }
        
        foreach ($indicatorName in $indicatorModals.Keys) {
            if ($AuditAnalysisResults.Indicators.ContainsKey($indicatorName)) {
                $indicator = $AuditAnalysisResults.Indicators[$indicatorName]
                $modalConfig = $indicatorModals[$indicatorName]
                $indicatorScore = [Math]::Round($indicator.Score, 0)
                
                $badgeClass = Get-BadgeClassUpper -Score $indicatorScore
                $badgeColor = Get-ProgressColor -Score $indicatorScore -ColorScheme 'audit'
                
                $html += @"
    <!-- $indicatorName Details Modal -->
    <div id="$($modalConfig.Id)" class="modal">
        <div class="modal-content" style="max-width: 1200px;">
            <div class="modal-header" style="background: linear-gradient(135deg, $($modalConfig.Color) 0%, $($modalConfig.Color)dd 100%);">
                <h2>$($modalConfig.Icon) $indicatorName</h2>
                <button class="modal-close" onclick="closeModal('$($modalConfig.Id)')">&times;</button>
            </div>
            <div class="modal-body">
                <div style='background: $($badgeColor)15; border-left: 4px solid $badgeColor; padding: 16px; margin-bottom: 20px; border-radius: 8px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <h3 style='margin: 0; color: #2c3e50; font-size: 18px;'>Indicator Assessment</h3>
                        <span style='background: $badgeColor; color: white; padding: 6px 16px; border-radius: 6px; font-size: 13px; font-weight: 600;'>$badgeClass - $indicatorScore%</span>
                    </div>
                    <div style='display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 12px;'>
                        <div style='background: white; padding: 12px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                            <div style='font-size: 11px; color: #7f8c8d; margin-bottom: 4px; text-transform: uppercase;'>Risk Score</div>
                            <div style='font-size: 24px; font-weight: 700; color: $badgeColor;'>$indicatorScore%</div>
                        </div>
                        <div style='background: white; padding: 12px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                            <div style='font-size: 11px; color: #7f8c8d; margin-bottom: 4px; text-transform: uppercase;'>Weight</div>
                            <div style='font-size: 24px; font-weight: 700; color: #2c3e50;'>$($indicator.Weight)%</div>
                        </div>
                        <div style='background: white; padding: 12px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                            <div style='font-size: 11px; color: #7f8c8d; margin-bottom: 4px; text-transform: uppercase;'>Detections</div>
                            <div style='font-size: 24px; font-weight: 700; color: #2c3e50;'>$($indicator.Count)</div>
                        </div>
                    </div>
                    <div style='width: 100%; background: #e0e0e0; height: 10px; border-radius: 5px; overflow: hidden;'>
                        <div style='width: $indicatorScore%; background: $badgeColor; height: 100%; transition: width 0.3s ease;'></div>
                    </div>
                </div>
"@

                # Generate disclaimers using configuration
                if ($auditDisclaimers.ContainsKey($indicatorName)) {
                    $config = $auditDisclaimers[$indicatorName]
                    $icon = $modalConfig.Icon
                    $color = $modalConfig.Color
                    
                    if ($config.IsDetailed) {
                        $html += Get-DetailedIndicatorDisclaimer -Icon $icon -Color $color `
                            -BgColor $config.BgColor -TextColor $config.TextColor `
                            -Detection $config.Detection -RiskFormula $config.RiskFormula `
                            -RiskExplanation $config.RiskExplanation -Weight $config.Weight `
                            -SecurityNote $config.SecurityNote
                    } else {
                        $html += Get-IndicatorDisclaimer -Icon $icon -Color $color `
                            -BgColor $config.BgColor -TextColor $config.TextColor `
                            -Detection $config.Detection -RiskFormula $config.RiskFormula `
                            -SecurityNote $config.SecurityNote
                    }
                }












                # Determine which list to use for table display
                $listData = $null
                $listName = ""
                $headerColor = $modalConfig.Color
                
                switch ($indicatorName) {
                    'Off-Hours Password Change/Reset' { 
                            $listData = $AuditAnalysisResults.PasswordChangesList
                            $listName = "Password Change Activities"
                        }
                    'Policy Changes' { 
                        $listData = $AuditAnalysisResults.PolicyChangesList
                        $listName = "Policy Change Activities"
                    }
                    'Privileged Role Changes' { 
                        $listData = $AuditAnalysisResults.RoleChangesList
                        $listName = "Role Change Activities"
                    }
                    'Off-Hours Audit Activity' { 
                        $listData = $AuditAnalysisResults.OffHoursActivitiesList
                        $listName = "Off-Hours Activities"
                    }
                    'Failed Audit Events' { 
                        $listData = $AuditAnalysisResults.FailedActivitiesList
                        $listName = "Failed Audit Activities"
                    }
                    'Authentication Info Changes' { 
                        $listData = $AuditAnalysisResults.AuthMethodChangesList
                        $listName = "Authentication Method Changes"
                    }
                    'Bulk Deletions' { 
                        $listData = $AuditAnalysisResults.DeletionActivitiesList
                        $listName = "Deletion Activities"
                    }
                    'Disable Account' {
                        $listData = $AuditAnalysisResults.DisableAccountList
                        $listName = "Disable Account Activities"
                    }
                    'Consent to Application' { 
                        $listData = $AuditAnalysisResults.ConsentToAppsList
                        $listName = "Consent to Application Activities"
                    }
                    'Update Service Principal' { 
                        $listData = $AuditAnalysisResults.UpdateServicePrincipalList
                        $listName = "Update Service Principal Activities"
                    }
                    'Add Owner to Application/Service Principal' { 
                        $listData = $AuditAnalysisResults.AddOwnerList
                        $listName = "Add Owner Activities"
                    }
                    'Add App Role Assignment' { 
                        $listData = $AuditAnalysisResults.AddAppRoleList
                        $listName = "Add App Role Assignment Activities"
                    }
                    'Update Application' { 
                        $listData = $AuditAnalysisResults.UpdateApplicationList
                        $listName = "Update Application Activities"
                    }
                    'Add Service Principal' { 
                        $listData = $AuditAnalysisResults.AddServicePrincipalList
                        $listName = "Add Service Principal Activities"
                    }
                    'Bulk Update User' { 
                        $listData = $AuditAnalysisResults.BulkUpdateUserList
                        $listName = "Bulk Update User Activities"
                    }
                    'Disable Account' {
                        $listData = $AuditAnalysisResults.DisableAccountList
                        $listName = "Disable Account Activities"
                    }
                    'Password Change' { 
                        $listData = $AuditAnalysisResults.PasswordChangeList
                        $listName = "Password Change Activities"
                    }
                    'Password Reset' { 
                        $listData = $AuditAnalysisResults.PasswordResetList
                        $listName = "Password Reset Activities"
                    }
                }
                
                # Display detailed table for indicators with structured data
                if ($listData -and $listData.Count -gt 0) {
                    $html += @"
                <div style='background: #f8f9fa; padding: 16px; border-radius: 8px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>
                            $($modalConfig.Icon) ${listName}:
                        </div>
                        <button onclick="exportIndicatorData('$($modalConfig.Id)', '$indicatorName')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <div style='background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                        <div style='max-height: 500px; overflow-y: auto;'>
                            <table id='table-$($modalConfig.Id)' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                                <thead style='background: $headerColor; color: white; position: sticky; top: 0;'>
                                    <tr>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($headerColor)dd; width: 40px;'>#</th>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($headerColor)dd;'>Date (UTC)</th>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($headerColor)dd;'>Activity</th>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($headerColor)dd;'>Operation Type</th>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($headerColor)dd;'>Initiator User UPN</th>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($headerColor)dd;'>Initiator IP</th>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($headerColor)dd;'>Target Display Name</th>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($headerColor)dd;'>Target Type</th>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($headerColor)dd;'>Target ID</th>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($headerColor)dd;'>Result</th>
                                    </tr>
                                </thead>
                                <tbody>
"@
                    $rowNumber = 1
                    foreach ($item in $listData) {
                        $resultBadge = if ($item.Result -eq 'success') { 
                            "<span style='background: #27ae60; color: white; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>" 
                        } else { 
                            "<span style='background: #e74c3c; color: white; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>" 
                        }
                        
                        $html += @"
                                    <tr style='border-bottom: 1px solid #ecf0f1;'>
                                        <td style='padding: 12px 8px; color: #7f8c8d; font-weight: 600;'>$rowNumber</td>
                                        <td style='padding: 12px 8px; color: #7f8c8d; font-size: 12px;'>$($item.Timestamp)</td>
                                        <td style='padding: 12px 8px; color: #2c3e50;'>$($item.Activity)</td>
                                        <td style='padding: 12px 8px; color: #34495e;'>$($item.OperationType)</td>
                                        <td style='padding: 12px 8px; color: #34495e;'>$($item.InitiatorUPN)</td>
                                        <td style='padding: 12px 8px; color: #34495e;'>$($item.InitiatorIP)</td>
                                        <td style='padding: 12px 8px; color: #34495e;'>$($item.TargetDisplayName)</td>
                                        <td style='padding: 12px 8px; color: #7f8c8d;'>$($item.TargetType)</td>
                                        <td style='padding: 12px 8px; color: #95a5a6; font-size: 11px; font-family: monospace;'>$($item.TargetID)</td>
                                        <td style='padding: 12px 8px;'>$resultBadge</td>
                                    </tr>
"@
                        $rowNumber++
                    }
                    
                    $html += @"
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
"@
                }
                elseif ($indicator.Count -gt 0 -and $indicator.Details -and $indicator.Details.Count -gt 0) {
                    $html += @"
                <div style='background: #f8f9fa; padding: 16px; border-radius: 8px;'>
                    <div style='font-weight: 600; color: #2c3e50; margin-bottom: 12px; font-size: 15px;'>
                        $($modalConfig.Icon) Detected Activities:
                    </div>
                    <div style='background: white; padding: 12px; border-radius: 6px; max-height: 400px; overflow-y: auto;'>
                        <ul style='margin: 0; padding-left: 20px; color: #34495e; font-size: 13px; line-height: 1.8;'>
"@
                    foreach ($detail in $indicator.Details) {
                        if (![string]::IsNullOrWhiteSpace($detail)) {
                            $html += "                            <li style='margin-bottom: 8px; padding-bottom: 8px; border-bottom: 1px solid #ecf0f1;'>$detail</li>`n"
                        }
                    }
                    
                    $html += @"
                        </ul>
                    </div>
                </div>
"@
                } else {
                    $html += @"
                <div style='text-align: center; padding: 40px; background: #f8f9fa; border-radius: 8px;'>
                    <div style='font-size: 48px; margin-bottom: 12px; color: #2ecc71;'>&#9989;</div>
                    <div style='font-size: 16px; color: #2ecc71; font-weight: 600;'>No Issues Detected</div>
                    <div style='font-size: 13px; color: #7f8c8d; margin-top: 8px;'>This indicator shows normal activity</div>
                </div>
"@
                }
                
                $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('$($modalConfig.Id)')" style="background: $($modalConfig.Color); color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
"@
            }
        }
    }
    
    # Generate modals for each Sign-In indicator
    if ($AnalysisResults -and $AnalysisResults.Indicators) {
        $signinIndicatorModals = @{
            'Multiple Locations' = @{ Id = 'modal-signin-multiple-locations'; Icon = '&#127760;'; Color = '#3498db' }
            'Failed/Interrupted Sign-ins' = @{ Id = 'modal-signin-failed'; Icon = '&#10060;'; Color = '#e74c3c' }
            'Brute-force' = @{ Id = 'modal-signin-bruteforce'; Icon = '&#128737;'; Color = '#d63031' }
            'Password-spray' = @{ Id = 'modal-signin-passwordspray'; Icon = '&#128167;'; Color = '#e74c3c' }
            'Account Lockout' = @{ Id = 'modal-signin-lockout'; Icon = '&#128274;'; Color = '#e67e22' }
            'Multiple IP Addresses' = @{ Id = 'modal-signin-multiple-ips'; Icon = '&#128187;'; Color = '#0984e3' }
            'Risky Sign-ins' = @{ Id = 'modal-signin-risky'; Icon = '&#9888;'; Color = '#d63031' }
            'Suspicious User Agents' = @{ Id = 'modal-signin-user-agents'; Icon = '&#128187;'; Color = '#6c5ce7' }
            'Off-hours Activity' = @{ Id = 'modal-signin-offhours'; Icon = '&#127769;'; Color = '#fdcb6e' }
            'Multiple Devices' = @{ Id = 'modal-signin-devices'; Icon = '&#128241;'; Color = '#00b894' }
            'Anonymous IP' = @{ Id = 'modal-signin-anonymous'; Icon = '&#128373;'; Color = '#2d3436' }
            'Session IP Mismatch' = @{ Id = 'modal-signin-session-mismatch'; Icon = '&#128274;'; Color = '#d63031' }
        }
        
        foreach ($indicatorName in $signinIndicatorModals.Keys) {
            if ($AnalysisResults.Indicators.ContainsKey($indicatorName)) {
                $indicator = $AnalysisResults.Indicators[$indicatorName]
                $modalConfig = $signinIndicatorModals[$indicatorName]
                $indicatorScore = [Math]::Round($indicator.Score, 0)
                
                $badgeClass = Get-BadgeClassUpper -Score $indicatorScore
                $badgeColor = Get-ProgressColor -Score $indicatorScore
                
                $html += @"
    <!-- $indicatorName Details Modal -->
    <div id="$($modalConfig.Id)" class="modal">
        <div class="modal-content" style="max-width: 1200px;">
            <div class="modal-header" style="background: linear-gradient(135deg, $($modalConfig.Color) 0%, $($modalConfig.Color)dd 100%);">
                <h2>$($modalConfig.Icon) $indicatorName</h2>
                <button class="modal-close" onclick="closeModal('$($modalConfig.Id)')">&times;</button>
            </div>
            <div class="modal-body">
                <div style='background: $($badgeColor)15; border-left: 4px solid $badgeColor; padding: 16px; margin-bottom: 20px; border-radius: 8px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <h3 style='margin: 0; color: #2c3e50; font-size: 18px;'>Indicator Assessment</h3>
                        <span style='background: $badgeColor; color: white; padding: 6px 16px; border-radius: 6px; font-size: 13px; font-weight: 600;'>$badgeClass - $indicatorScore%</span>
                    </div>
                    <div style='display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 12px;'>
                        <div style='background: white; padding: 12px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                            <div style='font-size: 11px; color: #7f8c8d; margin-bottom: 4px; text-transform: uppercase;'>Risk Score</div>
                            <div style='font-size: 24px; font-weight: 700; color: $badgeColor;'>$indicatorScore%</div>
                        </div>
                        <div style='background: white; padding: 12px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                            <div style='font-size: 11px; color: #7f8c8d; margin-bottom: 4px; text-transform: uppercase;'>Weight</div>
                            <div style='font-size: 24px; font-weight: 700; color: #2c3e50;'>$($indicator.Weight)%</div>
                        </div>
                        <div style='background: white; padding: 12px; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                            <div style='font-size: 11px; color: #7f8c8d; margin-bottom: 4px; text-transform: uppercase;'>Detections</div>
                            <div style='font-size: 24px; font-weight: 700; color: #2c3e50;'>$($indicator.Count)</div>
                        </div>
                    </div>
                    <div style='width: 100%; background: #e0e0e0; height: 10px; border-radius: 5px; overflow: hidden;'>
                        <div style='width: $indicatorScore%; background: $badgeColor; height: 100%; transition: width 0.3s ease;'></div>
                    </div>
                </div>
"@
                
                # Generate sign-in disclaimers using configuration
                if ($signInDisclaimers.ContainsKey($indicatorName)) {
                    $config = $signInDisclaimers[$indicatorName]
                    $icon = $modalConfig.Icon
                    $color = $modalConfig.Color
                    
                    $html += Get-IndicatorDisclaimer -Icon $icon -Color $color `
                        -BgColor $config.BgColor -TextColor $config.TextColor `
                        -Detection $config.Detection -RiskFormula $config.RiskFormula `
                        -SecurityNote $config.SecurityNote
                }

                if ($indicator.Count -gt 0 -and $indicator.Details -and $indicator.Details.Count -gt 0) {
                    # Special handling for Risky Sign-ins with multi-column table
                    if ($indicatorName -eq 'Risky Sign-ins') {
                        $html += @"
                <div style='background: #f8f9fa; padding: 16px; border-radius: 8px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>
                            $($modalConfig.Icon) Detected Activities:
                        </div>
                        <button onclick="exportIndicatorData('$($modalConfig.Id)', '$indicatorName')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <div style='background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                        <div style='max-height: 500px; overflow-y: auto;'>
                            <table id='table-$($modalConfig.Id)' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                                <thead style='background: $($modalConfig.Color); color: white; position: sticky; top: 0;'>
                                    <tr>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($modalConfig.Color)dd;'>#</th>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($modalConfig.Color)dd;'>Date (UTC)</th>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($modalConfig.Color)dd;'>IP Address</th>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($modalConfig.Color)dd;'>User</th>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($modalConfig.Color)dd;'>Application</th>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($modalConfig.Color)dd;'>Location</th>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($modalConfig.Color)dd;'>Sign-in Risk Detection</th>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($modalConfig.Color)dd;'>Detection Type</th>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($modalConfig.Color)dd;'>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
"@
                        $rowNumber = 1
                        # Parse the risky sign-ins data from the enriched $riskySignIns collection
                        $riskySignInsData = $AnalysisResults.Indicators['Risky Sign-ins'].RawData
                        if ($riskySignInsData) {
                            foreach ($signIn in $riskySignInsData) {
                                $timestamp = if ($signIn.'Date (UTC)') { $signIn.'Date (UTC)' } else { 'N/A' }
                                $ipAddress = if ($signIn.'IP address') { $signIn.'IP address' } else { 'N/A' }
                                $user = if ($signIn.'User') { $signIn.'User' } else { 'N/A' }
                                $application = if ($signIn.'Application') { $signIn.'Application' } else { 'N/A' }
                                $location = if ($signIn.'Location - City') { $signIn.'Location - City' } else { 'N/A' }
                                $riskLevel = if ($signIn.'Risk Level Aggregated') { $signIn.'Risk Level Aggregated' } else { 'N/A' }
                                $riskDetection = if ($signIn.'Sign-in risk detection') { $signIn.'Sign-in risk detection' } else { 'N/A' }
                                $detectionType = if ($signIn.'Detection type') { $signIn.'Detection type' } else { 'N/A' }
                                $statusValue = if ($signIn.'Status') { $signIn.'Status' } else { 'N/A' }
                                
                                # Create colorized status badge
                                if ($statusValue -eq 'Success') {
                                    $statusBadge = "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>"
                                } elseif ($statusValue -eq 'Failure' -or $statusValue -eq 'Failed') {
                                    $statusBadge = "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>"
                                } else {
                                    $statusBadge = "<span style='background: #95a5a6; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>$statusValue</span>"
                                }
                                
                                $html += @"
                                    <tr style='border-bottom: 1px solid #ecf0f1;'>
                                        <td style='padding: 12px 8px; color: #7f8c8d; font-weight: 600;'>$rowNumber</td>
                                        <td style='padding: 12px 8px; color: #34495e;'>$timestamp</td>
                                        <td style='padding: 12px 8px; color: #34495e;'>$ipAddress</td>
                                        <td style='padding: 12px 8px; color: #34495e;'>$user</td>
                                        <td style='padding: 12px 8px; color: #34495e;'>$application</td>
                                        <td style='padding: 12px 8px; color: #34495e;'>$location</td>
                                        <td style='padding: 12px 8px; color: #34495e;'>$riskDetection</td>
                                        <td style='padding: 12px 8px; color: #34495e;'>$detectionType</td>
                                        <td style='padding: 12px 8px;'>$statusBadge</td>
                                    </tr>
"@
                                $rowNumber++
                            }
                        }
                        
                        $html += @"
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
"@
                    } else {
                        # Multi-column table for indicators with RawData (except Multiple IP Addresses, Multiple Locations, Multiple Devices, and Session IP Mismatch)
                        if ($indicator.RawData -and $indicator.RawData.Count -gt 0 -and $indicatorName -ne 'Multiple IP Addresses' -and $indicatorName -ne 'Multiple Locations' -and $indicatorName -ne 'Multiple Devices' -and $indicatorName -ne 'Session IP Mismatch') {
                            # Determine columns based on indicator type
                            $columns = @()
                            $columns += @{ Name = '#'; Property = 'RowNum' }
                            $columns += @{ Name = 'Date (UTC)'; Property = 'Date (UTC)' }
                            $columns += @{ Name = 'IP Address'; Property = 'IP address' }
                            
                            # Add indicator-specific columns
                            switch ($indicatorName) {
                                'Multiple Locations' {
                                    $columns += @{ Name = 'User'; Property = 'User' }
                                    $columns += @{ Name = 'Application'; Property = 'Application' }
                                    $columns += @{ Name = 'Location'; Property = 'Location - City' }
                                    $columns += @{ Name = 'Country'; Property = 'Location - Country/Region' }
                                    $columns += @{ Name = 'Status'; Property = 'Status' }
                                }
                                'Failed/Interrupted Sign-ins' {
                                    $columns += @{ Name = 'User'; Property = 'User' }
                                    $columns += @{ Name = 'Application'; Property = 'Application' }
                                    $columns += @{ Name = 'Failure Reason'; Property = 'Failure reason' }
                                    $columns += @{ Name = 'Error Code'; Property = 'Sign-in error code' }
                                    $columns += @{ Name = 'Location'; Property = 'Location - City' }
                                    $columns += @{ Name = 'Status'; Property = 'Status' }
                                }
                                'Brute-force' {
                                    $columns += @{ Name = 'User'; Property = 'User' }
                                    $columns += @{ Name = 'Application'; Property = 'Application' }
                                    $columns += @{ Name = 'Failure Reason'; Property = 'Failure reason' }
                                    $columns += @{ Name = 'Error Code'; Property = 'Sign-in error code' }
                                    $columns += @{ Name = 'Location'; Property = 'Location - City' }
                                    $columns += @{ Name = 'Status'; Property = 'Status' }
                                }
                                'Password-spray' {
                                    $columns += @{ Name = 'User'; Property = 'User' }
                                    $columns += @{ Name = 'Application'; Property = 'Application' }
                                    $columns += @{ Name = 'Failure Reason'; Property = 'Failure reason' }
                                    $columns += @{ Name = 'Error Code'; Property = 'Sign-in error code' }
                                    $columns += @{ Name = 'Location'; Property = 'Location - City' }
                                    $columns += @{ Name = 'Status'; Property = 'Status' }
                                }
                                'Account Lockout' {
                                    $columns += @{ Name = 'User'; Property = 'User' }
                                    $columns += @{ Name = 'Application'; Property = 'Application' }
                                    $columns += @{ Name = 'Failure Reason'; Property = 'Failure reason' }
                                    $columns += @{ Name = 'Error Code'; Property = 'Sign-in error code' }
                                    $columns += @{ Name = 'Location'; Property = 'Location - City' }
                                    $columns += @{ Name = 'Status'; Property = 'Status' }
                                }
                                'Multiple IP Addresses' {
                                    $columns += @{ Name = 'User'; Property = 'User' }
                                    $columns += @{ Name = 'Application'; Property = 'Application' }
                                    $columns += @{ Name = 'Location'; Property = 'Location - City' }
                                    $columns += @{ Name = 'Status'; Property = 'Status' }
                                }
                                'Suspicious User Agents' {
                                    $columns += @{ Name = 'User'; Property = 'User' }
                                    $columns += @{ Name = 'Application'; Property = 'Application' }
                                    $columns += @{ Name = 'User Agent'; Property = 'User agent' }
                                    $columns += @{ Name = 'Location'; Property = 'Location - City' }
                                    $columns += @{ Name = 'Status'; Property = 'Status' }
                                }
                                'Off-hours Activity' {
                                    $columns += @{ Name = 'User'; Property = 'User' }
                                    $columns += @{ Name = 'Application'; Property = 'Application' }
                                    $columns += @{ Name = 'Location'; Property = 'Location - City' }
                                    $columns += @{ Name = 'Status'; Property = 'Status' }
                                }
                                'Multiple Devices' {
                                    $columns += @{ Name = 'User'; Property = 'User' }
                                    $columns += @{ Name = 'Application'; Property = 'Application' }
                                    $columns += @{ Name = 'Operating System'; Property = 'Operating System' }
                                    $columns += @{ Name = 'Location'; Property = 'Location - City' }
                                    $columns += @{ Name = 'Status'; Property = 'Status' }
                                }
                                'Anonymous IP' {
                                    $columns += @{ Name = 'User'; Property = 'User' }
                                    $columns += @{ Name = 'Application'; Property = 'Application' }
                                    $columns += @{ Name = 'Location'; Property = 'Location - City' }
                                    $columns += @{ Name = 'Status'; Property = 'Status' }
                                }
                                'Session IP Mismatch' {
                                    $columns += @{ Name = 'User'; Property = 'User' }
                                    $columns += @{ Name = 'Session ID'; Property = 'Session ID' }
                                    $columns += @{ Name = 'Location'; Property = 'Location - City' }
                                    $columns += @{ Name = 'Status'; Property = 'Status' }
                                }
                            }
                            
                            $html += @"
                <div style='background: #f8f9fa; padding: 16px; border-radius: 8px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>
                            $($modalConfig.Icon) Detected Activities:
                        </div>
                        <button onclick="exportIndicatorData('$($modalConfig.Id)', '$indicatorName')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <div style='background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                        <div style='max-height: 500px; overflow-y: auto;'>
                            <table id='table-$($modalConfig.Id)' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                                <thead style='background: $($modalConfig.Color); color: white; position: sticky; top: 0;'>
                                    <tr>
"@
                            # Generate header row
                            foreach ($col in $columns) {
                                $html += "                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($modalConfig.Color)dd;'>$($col.Name)</th>`n"
                            }
                            
                            $html += @"
                                    </tr>
                                </thead>
                                <tbody>
"@
                            # Generate data rows
                            $rowNumber = 1
                            foreach ($row in $indicator.RawData) {
                                $html += "                                    <tr style='border-bottom: 1px solid #ecf0f1;'>`n"
                                foreach ($col in $columns) {
                                    if ($col.Name -eq '#') {
                                        $html += "                                        <td style='padding: 12px 8px; color: #7f8c8d; font-weight: 600;'>$rowNumber</td>`n"
                                    } elseif ($col.Name -eq 'Status') {
                                        $statusValue = if ($row.($col.Property)) { $row.($col.Property) } else { 'N/A' }
                                        if ($statusValue -eq 'Success') {
                                            $statusBadge = "<span style='background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>SUCCESS</span>"
                                        } elseif ($statusValue -eq 'Failure' -or $statusValue -eq 'Failed') {
                                            $statusBadge = "<span style='background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>FAILED</span>"
                                        } else {
                                            $statusBadge = "<span style='background: #95a5a6; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;'>$statusValue</span>"
                                        }
                                        $html += "                                        <td style='padding: 12px 8px;'>$statusBadge</td>`n"
                                    } else {
                                        $value = if ($row.($col.Property)) { $row.($col.Property) } else { 'N/A' }
                                        $html += "                                        <td style='padding: 12px 8px; color: #34495e;'>$value</td>`n"
                                    }
                                }
                                $html += "                                    </tr>`n"
                                $rowNumber++
                            }
                            
                            $html += @"
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
"@
                        } else {
                            # Fallback: single-column table with Details
                            $html += @"
                <div style='background: #f8f9fa; padding: 16px; border-radius: 8px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;'>
                        <div style='font-weight: 600; color: #2c3e50; font-size: 15px;'>
                            $($modalConfig.Icon) Detected Activities:
                        </div>
                        <button onclick="exportIndicatorData('$($modalConfig.Id)', '$indicatorName')" style='background: #27ae60; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 6px;'>
                            <span>&#128190;</span> Export to CSV
                        </button>
                    </div>
                    <div style='background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                        <div style='max-height: 500px; overflow-y: auto;'>
                            <table id='table-$($modalConfig.Id)' style='width: 100%; border-collapse: collapse; font-size: 13px;'>
                                <thead style='background: $($modalConfig.Color); color: white; position: sticky; top: 0;'>
                                    <tr>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($modalConfig.Color)dd;'>#</th>
                                        <th style='padding: 12px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid $($modalConfig.Color)dd;'>Activity Details</th>
                                    </tr>
                                </thead>
                                <tbody>
"@
                            $rowNumber = 1
                            foreach ($detail in $indicator.Details) {
                                if (![string]::IsNullOrWhiteSpace($detail)) {
                                    $html += @"
                                    <tr style='border-bottom: 1px solid #ecf0f1;'>
                                        <td style='padding: 12px 8px; color: #7f8c8d; font-weight: 600; width: 40px;'>$rowNumber</td>
                                        <td style='padding: 12px 8px; color: #34495e;'>$detail</td>
                                    </tr>
"@
                                    $rowNumber++
                                }
                            }
                            
                            $html += @"
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
"@
                        }
                    }
                } else {
                    $html += @"
                <div style='text-align: center; padding: 40px; background: #f8f9fa; border-radius: 8px;'>
                    <div style='font-size: 48px; margin-bottom: 12px; color: #2ecc71;'>&#9989;</div>
                    <div style='font-size: 16px; color: #2ecc71; font-weight: 600;'>No Issues Detected</div>
                    <div style='font-size: 13px; color: #7f8c8d; margin-top: 8px;'>This indicator shows normal activity</div>
                </div>
"@
                }
                
                $html += @"
            </div>
            <div class="modal-footer">
                <button onclick="closeModal('$($modalConfig.Id)')" style="background: $($modalConfig.Color); color: white; border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    </div>
"@
            }
        }
    }
    
    # Add Granular Scoring System section
    $html += @"
    
    <!-- Granular Scoring System Section -->
    <div class="section-wrapper" id="scoring-system" style="margin-top: 32px;">
        <div class="section-header" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
            <h2 style="color: white;">&#128202; Understanding Your Results</h2>
        </div>
        <div class="stats-grid-container">
            <div style="background: #f8f9fa; border-radius: 12px; padding: 28px;">
                <h3 style="color: #2c3e50; margin-bottom: 24px; font-size: 20px; font-weight: 700; text-align: center;">&#127919; Granular Scoring System</h3>
                
                <div style="background: white; border-radius: 12px; padding: 24px; margin-bottom: 24px; border: 2px solid #e0e0e0;">
                    <h4 style="color: #2c3e50; margin-bottom: 16px; font-size: 18px; font-weight: 600; text-align: center;">Account Suspicious Behavior Score Calculation</h4>
                    <div style="text-align: center; margin-bottom: 20px;">
                        <div style="font-size: 15px; color: #7f8c8d; margin-bottom: 8px;">The overall Account Suspicious Behavior Score is calculated as:</div>
                        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 16px; border-radius: 10px; display: inline-block; font-size: 16px; font-weight: 600; box-shadow: 0 4px 6px rgba(102, 126, 234, 0.3);">
                            <strong style="font-size: 18px;">50%</strong> Sign-In Indicators Risk Score + <strong style="font-size: 18px;">50%</strong> Audit Indicators Risk Score
                        </div>
                        <div style="font-size: 13px; color: #95a5a6; margin-top: 12px; font-style: italic;">
                            Note: Suspicious Activities are tracked separately and not included in Account Suspicious Behavior Score
                        </div>
                    </div>
                </div>
                
                <!-- Two-column grid for Sign-In and Audit -->
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 24px; margin-bottom: 28px;">
                    
                    <!-- Sign-In Indicators Column -->
                    <div style="background: linear-gradient(135deg, #fff8e1 0%, #ffe082 10%); border-radius: 12px; padding: 24px; border: 3px solid #ffd54f; box-shadow: 0 4px 6px rgba(255, 213, 79, 0.3);">
                        <h4 style="color: #f57c00; margin-bottom: 18px; font-size: 17px; font-weight: 700; text-align: center;">
                            &#128205; Sign-In Indicators of Suspicious Behavior 
                        </h4>
                        <div style="background: white; border-radius: 8px; padding: 16px; margin-bottom: 16px;">
                            <div style="font-size: 14px; color: #666; margin-bottom: 12px; font-weight: 600;">12 Indicators @ ~8.33% each:</div>
                            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; font-size: 13px; color: #555;">
                                <div style="padding: 8px; background: #fff3e0; border-radius: 6px; border-left: 3px solid #f57c00;">&#8226; Multiple Locations</div>
                                <div style="padding: 8px; background: #fff3e0; border-radius: 6px; border-left: 3px solid #f57c00;">&#8226; Failed/Interrupted Sign-ins</div>
                                <div style="padding: 8px; background: #fff3e0; border-radius: 6px; border-left: 3px solid #f57c00;">&#8226; Brute-force</div>
                                <div style="padding: 8px; background: #fff3e0; border-radius: 6px; border-left: 3px solid #f57c00;">&#8226; Password-spray</div>
                                <div style="padding: 8px; background: #fff3e0; border-radius: 6px; border-left: 3px solid #f57c00;">&#8226; Account Lockout</div>
                                <div style="padding: 8px; background: #fff3e0; border-radius: 6px; border-left: 3px solid #f57c00;">&#8226; Multiple IP Addresses</div>
                                <div style="padding: 8px; background: #fff3e0; border-radius: 6px; border-left: 3px solid #f57c00;">&#8226; Risky Sign-ins</div>
                                <div style="padding: 8px; background: #fff3e0; border-radius: 6px; border-left: 3px solid #f57c00;">&#8226; Suspicious User Agents</div>
                                <div style="padding: 8px; background: #fff3e0; border-radius: 6px; border-left: 3px solid #f57c00;">&#8226; Off-hours Activity</div>
                                <div style="padding: 8px; background: #fff3e0; border-radius: 6px; border-left: 3px solid #f57c00;">&#8226; Multiple Devices</div>
                                <div style="padding: 8px; background: #fff3e0; border-radius: 6px; border-left: 3px solid #f57c00;">&#8226; Anonymous IP</div>
                                <div style="padding: 8px; background: #fff3e0; border-radius: 6px; border-left: 3px solid #f57c00;">&#8226; Session IP Mismatch</div>
                            </div>
                        </div>
                        <div style="background: #f57c00; color: white; padding: 12px; border-radius: 8px; text-align: center; font-weight: 600; font-size: 14px;">
                            Weighted Average of All Indicators
                        </div>
                    </div>
                    
                    <!-- Audit Risk Assessment Score Column -->
                    <div style="background: linear-gradient(135deg, #e3f2fd 0%, #90caf9 10%); border-radius: 12px; padding: 24px; border: 3px solid #64b5f6; box-shadow: 0 4px 6px rgba(100, 181, 246, 0.3);">
                        <h4 style="color: #1976d2; margin-bottom: 18px; font-size: 17px; font-weight: 700; text-align: center;">
                            &#128269; Audit Indicators of Suspicious Behavior 
                        </h4>
                        <div style="background: white; border-radius: 8px; padding: 16px; margin-bottom: 16px;">
                            <div style="font-size: 14px; color: #666; margin-bottom: 12px; font-weight: 600;">4 Main Indicators @ 25% each:</div>
                            <div style="display: grid; gap: 8px; font-size: 13px; color: #555;">
                                <div style="padding: 10px; background: #e1f5fe; border-radius: 6px; border-left: 3px solid #1976d2; font-weight: 600;">
                                    &#8226; Off-Hours Password Change/Reset <span style="float: right; color: #1976d2;">25%</span>
                                </div>
                                <div style="padding: 10px; background: #e1f5fe; border-radius: 6px; border-left: 3px solid #1976d2; font-weight: 600;">
                                    &#8226; Off-Hours Audit Activity <span style="float: right; color: #1976d2;">25%</span>
                                </div>
                                <div style="padding: 10px; background: #e1f5fe; border-radius: 6px; border-left: 3px solid #1976d2; font-weight: 600;">
                                    &#8226; Failed Audit Events <span style="float: right; color: #1976d2;">25%</span>
                                </div>
                                <div style="padding: 10px; background: #e1f5fe; border-radius: 6px; border-left: 3px solid #1976d2; font-weight: 600;">
                                    &#8226; Authentication Info Changes <span style="float: right; color: #1976d2;">25%</span>
                                </div>
                                <!-- Suspicious App Activities removed from main audit indicators -->
                            </div>
                        </div>
                            <div style="background: #1976d2; color: white; padding: 12px; border-radius: 8px; text-align: center; font-weight: 600; font-size: 14px;">
                            Weighted Average of 4 Indicators
                        </div>
                    </div>
                </div>
                
                <!-- Suspicious Activities Note -->
                <div style="background: linear-gradient(135deg, #f3e5f5 0%, #ce93d8 10%); border-radius: 12px; padding: 20px; margin-bottom: 28px; border: 3px solid #ba68c8;">
                    <h4 style="color: #7b1fa2; margin-bottom: 12px; font-size: 16px; font-weight: 700; text-align: center;">
                        &#9888; Suspicious Activities (Tracked Separately)
                    </h4>
                    <div style="background: white; border-radius: 8px; padding: 16px;">
                        <div style="font-size: 14px; color: #666; margin-bottom: 12px; text-align: center;">
                            13 suspicious activity patterns monitored independently (~7.69% weight each = 100%):
                        </div>
                        <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; font-size: 11px; color: #555;">
                            <div style="padding: 6px 10px; background: #f3e5f5; border-radius: 6px; text-align: center;">Policy Changes</div>
                            <div style="padding: 6px 10px; background: #f3e5f5; border-radius: 6px; text-align: center;">Bulk Deletions</div>
                            <div style="padding: 6px 10px; background: #f3e5f5; border-radius: 6px; text-align: center;">Privileged Role Changes</div>
                            <div style="padding: 6px 10px; background: #f3e5f5; border-radius: 6px; text-align: center;">Consent to Application</div>
                            <div style="padding: 6px 10px; background: #f3e5f5; border-radius: 6px; text-align: center;">Password Change</div>
                            <div style="padding: 6px 10px; background: #f3e5f5; border-radius: 6px; text-align: center;">Password Reset</div>
                            <div style="padding: 6px 10px; background: #f3e5f5; border-radius: 6px; text-align: center;">Update Application</div>
                            <div style="padding: 6px 10px; background: #f3e5f5; border-radius: 6px; text-align: center;">Add Service Principal</div>
                            <div style="padding: 6px 10px; background: #f3e5f5; border-radius: 6px; text-align: center;">Add App Role Assignment</div>
                            <div style="padding: 6px 10px; background: #f3e5f5; border-radius: 6px; text-align: center;">Disable Account</div>
                            <div style="padding: 6px 10px; background: #f3e5f5; border-radius: 6px; text-align: center;">Bulk Update User</div>
                            <div style="padding: 6px 10px; background: #f3e5f5; border-radius: 6px; text-align: center;">Add Owner to Application/Service Principal</div>
                            <div style="padding: 6px 10px; background: #f3e5f5; border-radius: 6px; text-align: center;">Update Service Principal</div>
                        </div>
                        <div style="margin-top: 12px; padding: 12px; background: #fce4ec; border-radius: 6px; text-align: center; color: #c2185b; font-weight: 600; font-size: 13px;">
                            These patterns are evaluated for Pass/Fail status only
                        </div>
                    </div>
                </div>
                
                <!-- Score Ranges -->
                <h4 style="color: #2c3e50; margin-bottom: 18px; font-size: 18px; font-weight: 700; text-align: center;">Risk Score Ranges</h4>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px;">
                    
                    <!-- Low -->
                    <div style="background: linear-gradient(135deg, #2ecc71 0%, #27ae60 100%); border-radius: 12px; padding: 18px; color: white; box-shadow: 0 4px 8px rgba(46, 204, 113, 0.4); transition: transform 0.2s;">
                        <div style="display: flex; align-items: center; justify-content: space-between;">
                            <div style="display: flex; align-items: center;">
                                <span style="font-size: 24px; margin-right: 16px;">&#10003;</span>
                                <div>
                                    <div style="font-weight: 700; font-size: 17px; margin-bottom: 4px;">LOW RISK (0-24)</div>
                                    <div style="font-size: 13px; opacity: 0.95;">Minimal security concerns detected</div>
                                </div>
                            </div>
                            <div style="background: rgba(255,255,255,0.2); padding: 8px 16px; border-radius: 8px; font-size: 14px; font-weight: 700;">0-24%</div>
                        </div>
                    </div>
                    
                    <!-- Medium -->
                    <div style="background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); border-radius: 12px; padding: 18px; color: white; box-shadow: 0 4px 8px rgba(52, 152, 219, 0.4); transition: transform 0.2s;">
                        <div style="display: flex; align-items: center; justify-content: space-between;">
                            <div style="display: flex; align-items: center;">
                                <span style="font-size: 24px; margin-right: 16px;">&#8505;</span>
                                <div>
                                    <div style="font-weight: 700; font-size: 17px; margin-bottom: 4px;">MEDIUM RISK (25-49)</div>
                                    <div style="font-size: 13px; opacity: 0.95;">Some suspicious patterns present, monitoring recommended</div>
                                </div>
                            </div>
                            <div style="background: rgba(255,255,255,0.2); padding: 8px 16px; border-radius: 8px; font-size: 14px; font-weight: 700;">25-49%</div>
                        </div>
                    </div>
                    
                    <!-- High -->
                    <div style="background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); border-radius: 12px; padding: 18px; color: white; box-shadow: 0 4px 8px rgba(243, 156, 18, 0.4); transition: transform 0.2s;">
                        <div style="display: flex; align-items: center; justify-content: space-between;">
                            <div style="display: flex; align-items: center;">
                                <span style="font-size: 24px; margin-right: 16px;">&#9888;</span>
                                <div>
                                    <div style="font-weight: 700; font-size: 17px; margin-bottom: 4px;">HIGH RISK (50-74)</div>
                                    <div style="font-size: 13px; opacity: 0.95;">Multiple security concerns identified, investigation needed</div>
                                </div>
                            </div>
                            <div style="background: rgba(255,255,255,0.2); padding: 8px 16px; border-radius: 8px; font-size: 14px; font-weight: 700;">50-74%</div>
                        </div>
                    </div>
                    
                    <!-- Critical -->
                    <div style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); border-radius: 12px; padding: 18px; color: white; box-shadow: 0 4px 8px rgba(231, 76, 60, 0.5); transition: transform 0.2s;">
                        <div style="display: flex; align-items: center; justify-content: space-between;">
                            <div style="display: flex; align-items: center;">
                                <span style="font-size: 24px; margin-right: 16px;">&#128680;</span>
                                <div>
                                    <div style="font-weight: 700; font-size: 17px; margin-bottom: 4px;">CRITICAL RISK (75-100)</div>
                                    <div style="font-size: 13px; opacity: 0.95;">Severe security threat - immediate action required</div>
                                </div>
                            </div>
                            <div style="background: rgba(255,255,255,0.2); padding: 8px 16px; border-radius: 8px; font-size: 14px; font-weight: 700;">75-100%</div>
                        </div>
                    </div>
                    
                </div>
                
            </div>
        </div>
    </div>
    
    <div id="chart-tooltip" class="chart-tooltip"></div>
    
    <script>
        // Store raw data for CSV export
        const rawDataMap = {
"@
    
    # Add raw audit data to JavaScript
    if ($AuditAnalysisResults) {
        if ($AuditAnalysisResults.RoleChangesRaw) {
            $roleChangesJson = $AuditAnalysisResults.RoleChangesRaw | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'Role_Changes': $roleChangesJson,
"@
        }
        if ($AuditAnalysisResults.PasswordChangesRaw) {
            $passwordChangesJson = $AuditAnalysisResults.PasswordChangesRaw | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'Password_Changes': $passwordChangesJson,
"@
        }
        if ($AuditAnalysisResults.UserManagementRaw) {
            $userMgmtJson = $AuditAnalysisResults.UserManagementRaw | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'User_Management': $userMgmtJson,
"@
        }
        if ($AuditAnalysisResults.AppActivitiesRaw) {
            $appActivitiesJson = $AuditAnalysisResults.AppActivitiesRaw | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'App_Activities': $appActivitiesJson,
"@
        }
        if ($AuditAnalysisResults.GroupChangesRaw) {
            $groupChangesJson = $AuditAnalysisResults.GroupChangesRaw | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'Group_Changes': $groupChangesJson,
"@
        }
        if ($AuditAnalysisResults.MFAChangesRaw) {
            $mfaChangesJson = $AuditAnalysisResults.MFAChangesRaw | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'MFA_Changes': $mfaChangesJson,
"@
        }
        if ($AuditAnalysisResults.OffHoursActivitiesRaw) {
            $offHoursJson = $AuditAnalysisResults.OffHoursActivitiesRaw | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'OffHours_Activities': $offHoursJson,
"@
        }
        if ($AuditAnalysisResults.TotalActivitiesList) {
            $totalActivitiesJson = $AuditAnalysisResults.TotalActivitiesList | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'Total_Audit_Activities': $totalActivitiesJson,
"@
        }
        if ($AuditAnalysisResults.SuccessfulActivitiesList) {
            $successfulActivitiesJson = $AuditAnalysisResults.SuccessfulActivitiesList | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'Successful_Audit_Activities': $successfulActivitiesJson,
"@
        }
        if ($AuditAnalysisResults.FailedActivitiesList) {
            $failedActivitiesJson = $AuditAnalysisResults.FailedActivitiesList | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'Failed_Audit_Activities': $failedActivitiesJson,
"@
        }
    }
    
    # Add raw sign-in data to JavaScript
    if ($AnalysisResults) {
        if ($AnalysisResults.LocationsRaw) {
            $locationsJson = $AnalysisResults.LocationsRaw | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'Countries': $locationsJson,
"@
        }
        if ($AnalysisResults.IPsRaw) {
            $ipsJson = $AnalysisResults.IPsRaw | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'IP_Addresses': $ipsJson,
"@
        }
        if ($AnalysisResults.SessionIdsRaw) {
            $sessionsJson = $AnalysisResults.SessionIdsRaw | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'Session_IDs': $sessionsJson,
"@
        }
        if ($AnalysisResults.ApplicationsRaw) {
            $appsJson = $AnalysisResults.ApplicationsRaw | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'Applications': $appsJson,
"@
        }
        if ($AnalysisResults.ClientAppsRaw) {
            $clientAppsJson = $AnalysisResults.ClientAppsRaw | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'Client_Apps': $clientAppsJson,
"@
        }
        if ($AnalysisResults.ResourcesRaw) {
            $resourcesJson = $AnalysisResults.ResourcesRaw | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'Resources': $resourcesJson,
"@
        }
        if ($AnalysisResults.OperatingSystemsRaw) {
            $osJson = $AnalysisResults.OperatingSystemsRaw | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'Operating_Systems': $osJson,
"@
        }
        if ($AnalysisResults.FailedSignInsRaw) {
            $failedSignInsJson = $AnalysisResults.FailedSignInsRaw | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'Failed_Sign_Ins': $failedSignInsJson,
"@
        }
        if ($AnalysisResults.InterruptedSignInsRaw) {
            $interruptedJson = $AnalysisResults.InterruptedSignInsRaw | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'Interrupted_Sign_Ins': $interruptedJson,
"@
        }
        if ($AnalysisResults.SuccessfulSignInsRaw) {
            $successfulJson = $AnalysisResults.SuccessfulSignInsRaw | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'Successful_Sign_Ins': $successfulJson,
"@
        }
        if ($AnalysisResults.OffHoursSignInsRaw) {
            $offHoursJson = $AnalysisResults.OffHoursSignInsRaw | ConvertTo-Json -Compress -Depth 10
            $html += @"
            'OffHours_SignIns': $offHoursJson,
"@
        }
    }
    
    $html += @"
        };
        
        // Chart interaction functions
        let currentTooltip = null;
        
        function highlightSegment(element, message) {
            showTooltip(message);
            element.style.strokeWidth = '16';
            element.style.filter = 'brightness(1.15) drop-shadow(0 0 8px currentColor)';
        }
        
        function unhighlightSegment(element) {
            hideTooltip();
            element.style.strokeWidth = '14';
            element.style.filter = 'none';
        }
        
        function showTooltip(message) {
            const tooltip = document.getElementById('chart-tooltip');
            if (tooltip) {
                tooltip.textContent = message;
                tooltip.classList.add('show');
            }
        }
        
        function hideTooltip() {
            const tooltip = document.getElementById('chart-tooltip');
            if (tooltip) {
                tooltip.classList.remove('show');
            }
        }
        
        function showChartTooltip(event, message) {
            const tooltip = document.getElementById('chart-tooltip');
            if (tooltip) {
                tooltip.textContent = message;
                tooltip.style.left = event.pageX + 'px';
                tooltip.style.top = (event.pageY - 40) + 'px';
                tooltip.classList.add('show');
            }
        }
        
        function hideChartTooltip() {
            hideTooltip();
        }
        
        function highlightLegend(element, chartId) {
            element.style.background = 'white';
            element.style.transform = 'translateX(4px)';
            const colorBox = element.querySelector('.legend-color');
            if (colorBox) {
                colorBox.style.transform = 'scale(1.3)';
            }
        }
        
        function unhighlightLegend(element) {
            element.style.background = '';
            element.style.transform = '';
            const colorBox = element.querySelector('.legend-color');
            if (colorBox) {
                colorBox.style.transform = '';
            }
        }
        
        // Smooth scrolling navigation
        function scrollToSection(sectionId, navItem) {
            event.preventDefault();
            const section = document.getElementById(sectionId);
            if (section) {
                section.scrollIntoView({ behavior: 'smooth', block: 'start' });
                
                // Update active nav item
                document.querySelectorAll('.nav-item').forEach(item => {
                    item.classList.remove('active');
                });
                navItem.classList.add('active');
            }
        }
        
        // Highlight active section on scroll
        window.addEventListener('scroll', function() {
            const sections = document.querySelectorAll('.section-wrapper');
            const navItems = document.querySelectorAll('.nav-item');
            
            let current = '';
            sections.forEach(section => {
                const sectionTop = section.offsetTop;
                const sectionHeight = section.clientHeight;
                if (pageYOffset >= sectionTop - 150) {
                    current = section.getAttribute('id');
                }
            });
            
            navItems.forEach(item => {
                item.classList.remove('active');
                if (item.getAttribute('href') === '#' + current) {
                    item.classList.add('active');
                }
            });
        });
        
        // Track mouse movement for tooltip positioning
        document.addEventListener('mousemove', function(e) {
            const tooltip = document.getElementById('chart-tooltip');
            if (tooltip && tooltip.classList.contains('show')) {
                tooltip.style.left = (e.pageX + 10) + 'px';
                tooltip.style.top = (e.pageY - 40) + 'px';
            }
        });
        
        // Animate charts on page load
        window.addEventListener('load', function() {
            const charts = document.querySelectorAll('.circular-progress');
            charts.forEach((chart, index) => {
                setTimeout(() => {
                    chart.style.opacity = '1';
                    chart.style.transform = 'scale(1)';
                }, index * 150);
            });
        });
        
        function openModal(modalId) {
            document.getElementById(modalId).style.display = 'block';
            document.body.style.overflow = 'hidden';
        }
        
        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
            document.body.style.overflow = 'auto';
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                event.target.style.display = 'none';
                document.body.style.overflow = 'auto';
            }
        }
        
        // Close modal with ESC key
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                const modals = document.querySelectorAll('.modal');
                modals.forEach(modal => {
                    modal.style.display = 'none';
                });
                document.body.style.overflow = 'auto';
            }
        });
        
        // Export indicator data to CSV
        function exportIndicatorData(modalId, indicatorName) {
            const table = document.getElementById('table-' + modalId);
            const modal = document.getElementById(modalId);
            let csv = [];
            
            // Check if raw data is available for this indicator
            if (rawDataMap && rawDataMap[indicatorName]) {
                const rawData = rawDataMap[indicatorName];
                
                if (Array.isArray(rawData) && rawData.length > 0) {
                    // Get all property names from the first object
                    const headers = Object.keys(rawData[0]);
                    csv.push(headers.join(','));
                    
                    // Export all individual events
                    rawData.forEach(item => {
                        const row = headers.map(header => {
                            let value = item[header] || '';
                            // Convert to string and handle special characters
                            value = String(value).trim();
                            if (value.includes(',') || value.includes('"') || value.includes('\n')) {
                                value = '"' + value.replace(/"/g, '""') + '"';
                            }
                            return value;
                        });
                        csv.push(row.join(','));
                    });
                    
                    // Create and download CSV
                    const csvContent = csv.join('\n');
                    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
                    const link = document.createElement('a');
                    const url = URL.createObjectURL(blob);
                    
                    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
                    const filename = indicatorName.replace(/\s+/g, '_') + '_' + timestamp + '.csv';
                    
                    link.setAttribute('href', url);
                    link.setAttribute('download', filename);
                    link.style.visibility = 'hidden';
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                    
                    // Show success message
                    const btn = event.target.closest('button');
                    const originalText = btn.innerHTML;
                    btn.innerHTML = '<span>&#10004;</span> Exported ' + rawData.length + ' events!';
                    btn.style.background = '#27ae60';
                    setTimeout(() => {
                        btn.innerHTML = originalText;
                        btn.style.background = '#27ae60';
                    }, 2000);
                    
                    return;
                }
            }
            
            // Fallback to table-based export if no raw data available
            if (table) {
                // Table-based export (for Resources and other table modals)
                const rows = table.querySelectorAll('tr');
                
                rows.forEach(row => {
                    const cols = row.querySelectorAll('td, th');
                    let rowData = [];
                    
                    cols.forEach(col => {
                        let text = col.textContent.trim();
                        text = text.replace(/\s+/g, ' ');
                        if (text.includes(',') || text.includes('"') || text.includes('\n')) {
                            text = '"' + text.replace(/"/g, '""') + '"';
                        }
                        rowData.push(text);
                    });
                    
                    if (rowData.length > 0 && !rowData[0].includes('... and')) {
                        csv.push(rowData.join(','));
                    }
                });
            } else if (modal) {
                // Modal-item based export (for IPs, Sessions, Apps, Client Apps, OS)
                const items = modal.querySelectorAll('.modal-item');
                
                if (items.length === 0) {
                    alert('No data available to export');
                    return;
                }
                
                // Add header
                csv.push(indicatorName.replace(/_/g, ' '));
                
                // Extract data from modal-item divs
                items.forEach(item => {
                    let text = item.textContent.trim();
                    // Remove emoji/icon characters and extra whitespace
                    text = text.replace(/[\u{1F300}-\u{1F9FF}]|[\u{2600}-\u{26FF}]|[\u{2700}-\u{27BF}]/gu, '').trim();
                    text = text.replace(/\s+/g, ' ');
                    
                    if (text && !text.includes('... and') && text.length > 0) {
                        if (text.includes(',') || text.includes('"') || text.includes('\n')) {
                            text = '"' + text.replace(/"/g, '""') + '"';
                        }
                        csv.push(text);
                    }
                });
            } else {
                alert('No data available to export');
                return;
            }
            
            // Create CSV content
            const csvContent = csv.join('\n');
            
            // Create blob and download
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            
            // Create filename with timestamp
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
            const filename = indicatorName.replace(/\s+/g, '_') + '_' + timestamp + '.csv';
            
            link.setAttribute('href', url);
            link.setAttribute('download', filename);
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            // Show success message
            const btn = event.target.closest('button');
            const originalText = btn.innerHTML;
            btn.innerHTML = '<span>&#10004;</span> Exported!';
            btn.style.background = '#27ae60';
            setTimeout(() => {
                btn.innerHTML = originalText;
                btn.style.background = '#27ae60';
            }, 2000);
        }

        // Toggle recommendation accordion expand/collapse
        function toggleRecommendation(element) {
            element.classList.toggle('expanded');
            const expandText = element.querySelector('.recommendation-expand-text');
            if (expandText) {
                expandText.textContent = element.classList.contains('expanded') ? 'Hide Details' : 'Show Details';
            }
        }

        // Toggle indicator details expand/collapse
        function toggleIndicatorDetails(id) {
            const detailsDiv = document.getElementById('details-' + id);
            const toggleBtn = document.getElementById('toggle-btn-' + id);
            
            if (detailsDiv && toggleBtn) {
                if (detailsDiv.style.display === 'none') {
                    detailsDiv.style.display = 'block';
                    toggleBtn.textContent = 'Hide Details';
                } else {
                    detailsDiv.style.display = 'none';
                    toggleBtn.textContent = 'View Details';
                }
            }
        }

        // Authorized test handling: allow hiding/restoring recommendations when report is an approved test
        document.addEventListener('DOMContentLoaded', function() {
            const checkbox = document.getElementById('authorizedTestCheckbox');
            const applyBtn = document.getElementById('applySkipBtn');
            const restoreBtn = document.getElementById('restoreRecommendationsBtn');
            const skipNotice = document.getElementById('skipNotice');

            if (!checkbox || !applyBtn || !restoreBtn) return;

            // Enable apply button only when checkbox checked
            checkbox.addEventListener('change', function() {
                applyBtn.disabled = !checkbox.checked;
            });

            applyBtn.addEventListener('click', function() {
                if (!checkbox.checked) return;

                // Hide all recommendation items
                document.querySelectorAll('.recommendation-item').forEach(el => el.style.display = 'none');
                // Show notice and restore button
                if (skipNotice) skipNotice.style.display = 'block';
                applyBtn.style.display = 'none';
                restoreBtn.style.display = 'inline-block';
                // Persist choice in sessionStorage
                try { sessionStorage.setItem('recommendationsSkipped', 'true'); } catch(e) {}
            });

            restoreBtn.addEventListener('click', function() {
                // Show all recommendation items
                document.querySelectorAll('.recommendation-item').forEach(el => el.style.display = 'block');
                if (skipNotice) skipNotice.style.display = 'none';
                restoreBtn.style.display = 'none';
                applyBtn.style.display = 'inline-block';
                applyBtn.disabled = !checkbox.checked;
                try { sessionStorage.removeItem('recommendationsSkipped'); } catch(e) {}
            });

            // Restore state from sessionStorage if previously skipped
            try {
                if (sessionStorage.getItem('recommendationsSkipped') === 'true') {
                    checkbox.checked = true;
                    applyBtn.disabled = false;
                    applyBtn.click();
                }
            } catch(e) {}
        });
    </script>
    
    <!-- Footer -->
    <footer style="background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%); color: white; padding: 24px; text-align: center; margin-top: 40px; border-top: 4px solid #3498db;">
        <div style="max-width: 1400px; margin: 0 auto;">
            <div style="font-size: 15px; font-weight: 600; margin-bottom: 8px;">
                Account Suspicious Behavior Checker 1.0
            </div>
            <div style="font-size: 13px; color: #bdc3c7;">
                Report generated at $($AnalysisResults.AnalysisDate)
            </div>
        </div>
    </footer>
    
</body>
</html>
"@
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "HTML report generated: $OutputPath" -ForegroundColor Green
}
#endregion

#region Function: Export-DirectoryAuditLogs
# Function to export directory audit logs
function Export-DirectoryAuditLogs {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserId,
        [Parameter(Mandatory=$true)]
        [string]$UserUPN,
        [Parameter(Mandatory=$true)]
        [string]$OutputFolder,
        [Parameter(Mandatory=$true)]
        [string]$Timestamp
    )
    
    Write-Host "`n===== Retrieving Directory Audit Logs =====" -ForegroundColor Cyan
    Write-Host "Retrieving audit logs initiated by user '$UserUPN'..." -ForegroundColor Cyan
    Write-Host "This may take a few minutes depending on the amount of data..." -ForegroundColor Yellow
    
    try {
        # Use v1.0 endpoint with user filter
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=initiatedBy/user/id eq '$UserId'"
        $allAuditLogs = @()
        
        do {
            $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
            
            if ($response.value) {
                $allAuditLogs += $response.value
                Write-Host "Retrieved $($allAuditLogs.Count) audit log records so far..." -ForegroundColor Yellow
            }
            
            # Get next page if available
            $uri = $response.'@odata.nextLink'
            
        } while ($uri)
        
        if ($allAuditLogs.Count -eq 0) {
            Write-Host "No directory audit logs found for this user." -ForegroundColor Yellow
            return $null
        }
        
        Write-Host "Retrieved $($allAuditLogs.Count) directory audit log entries." -ForegroundColor Green
        
        # Process and export to CSV
        Write-Host "Processing and exporting audit logs to CSV..." -ForegroundColor Cyan
        
        $csvFilePrefix = "AzureAD_DirectoryAuditLogs_$($UserUPN.Replace('@','_'))"
        $csvFileName = "${csvFilePrefix}_$Timestamp.csv"
        $csvFilePath = Join-Path -Path $OutputFolder -ChildPath $csvFileName
        
        # Expand nested properties for comprehensive export
        $exportData = $allAuditLogs | ForEach-Object {
            [PSCustomObject]@{
                'Timestamp' = $_.activityDateTime
                'Activity' = $_.activityDisplayName
                'Category' = $_.category
                'Service' = $_.loggedByService
                'Result' = $_.result
                'Result Reason' = $_.resultReason
                'Failure Reason' = if ($_.result -eq 'failure') { $_.resultReason } else { $null }
                'Correlation ID' = $_.correlationId
                'Operation Type' = $_.operationType
                'Initiator User ID' = $_.initiatedBy.user.id
                'Initiator User UPN' = $_.initiatedBy.user.userPrincipalName
                'Initiator Display Name' = $_.initiatedBy.user.displayName
                'Initiator IP' = $_.initiatedBy.user.ipAddress
                'Initiator User Type' = $_.initiatedBy.user.userType
                'Initiator App ID' = $_.initiatedBy.app.appId
                'Initiator App Display Name' = $_.initiatedBy.app.displayName
                'Initiator Service Principal ID' = $_.initiatedBy.app.servicePrincipalId
                'Initiator Service Principal Name' = $_.initiatedBy.app.servicePrincipalName
                'Target Resources' = if ($_.targetResources) { 
                    ($_.targetResources | ForEach-Object { 
                        "Type: $($_.type), ID: $($_.id), DisplayName: $($_.displayName), UPN: $($_.userPrincipalName)" 
                    }) -join '; ' 
                } else { $null }
                'Target Type' = if ($_.targetResources -and $_.targetResources.Count -gt 0) { $_.targetResources[0].type } else { $null }
                'Target ID' = if ($_.targetResources -and $_.targetResources.Count -gt 0) { $_.targetResources[0].id } else { $null }
                'Target Display Name' = if ($_.targetResources -and $_.targetResources.Count -gt 0) { $_.targetResources[0].displayName } else { $null }
                'Target UPN' = if ($_.targetResources -and $_.targetResources.Count -gt 0) { $_.targetResources[0].userPrincipalName } else { $null }
                'Modified Properties' = if ($_.targetResources -and $_.targetResources[0].modifiedProperties) {
                    ($_.targetResources[0].modifiedProperties | ForEach-Object {
                        "Property: $($_.displayName), OldValue: $($_.oldValue), NewValue: $($_.newValue)"
                    }) -join '; '
                } else { $null }
                'Additional Details' = if ($_.additionalDetails) { 
                    ($_.additionalDetails | ForEach-Object { "$($_.key): $($_.value)" }) -join '; ' 
                } else { $null }
                'ID' = $_.id
            }
        }
        
        # Export to CSV
        $exportData | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8
        
        Write-Host "Audit logs export completed successfully!" -ForegroundColor Green
        Write-Host "File saved to: $csvFilePath" -ForegroundColor Green
        Write-Host "Total audit records exported: $($allAuditLogs.Count)" -ForegroundColor Green
        
        return $csvFilePath
        
    }
    catch {
        Write-Host "Failed to retrieve or export directory audit logs. Error: $_" -ForegroundColor Red
        return $null
    }
}
#endregion

#region Function: Show-MainMenu
# Function to show main menu
function Show-MainMenu {
    Write-Host "`n===== Entra ID Sign-In Logs Analysis Tool =====" -ForegroundColor Cyan
    Write-Host "Select an option:" -ForegroundColor White
    Write-Host "  1. Analyze existing CSV files from a folder" -ForegroundColor Yellow
    Write-Host "  2. Connect to Entra ID, export logs, and analyze" -ForegroundColor Yellow
    Write-Host "  Q. Quit" -ForegroundColor Yellow
    Write-Host ""
    
    do {
        $selection = Read-Host "Enter your choice (1, 2, or Q)"
        
        if ($selection -eq 'Q' -or $selection -eq 'q') {
            Write-Host "Exiting script..." -ForegroundColor Cyan
            exit 0
        }
        
        if ($selection -ne '1' -and $selection -ne '2') {
            Write-Host "Invalid selection. Please enter 1, 2, or Q." -ForegroundColor Red
        }
    } while ($selection -ne '1' -and $selection -ne '2')
    
    return $selection
}
#endregion

#region Function: Analyze-ExistingCSVFiles
# Function to analyze existing CSV files
function Analyze-ExistingCSVFiles {
    param(
        [string]$FolderPath = $null,
        [string]$OutputFolder = $null,
        [string]$Start = $null,
        [string]$End = $null,
        [switch]$Open
    )

    Write-Host "`n===== Analyze Existing CSV Files =====" -ForegroundColor Cyan

    if ($FolderPath) {
        $folderPath = $FolderPath
        if (-not (Test-Path -Path $folderPath -PathType Container)) {
            Write-Host "The specified folder does not exist. Exiting..." -ForegroundColor Red
            return
        }
        Write-Host "Using folder: $folderPath" -ForegroundColor Green
    }
    else {
        # Ask for folder path
        Write-Host "`nEnter the folder path where the sign-in and audit CSV files are located:" -ForegroundColor Yellow
        $folderPath = Read-Host "Folder Path"

        # Validate the path
        if ([string]::IsNullOrWhiteSpace($folderPath)) {
            Write-Host "No folder path entered. Exiting..." -ForegroundColor Red
            return
        }

        if (-not (Test-Path -Path $folderPath -PathType Container)) {
            Write-Host "The specified folder does not exist. Exiting..." -ForegroundColor Red
            return
        }

        Write-Host "Using folder: $folderPath" -ForegroundColor Green
    }
    
    # Look for CSV files in the folder
    $csvFiles = Get-ChildItem -Path $folderPath -Filter "*.csv" | Sort-Object LastWriteTime -Descending
    
    if ($csvFiles.Count -eq 0) {
        Write-Host "No CSV files found in the specified folder." -ForegroundColor Red
        return
    }
    
    Write-Host "`nFound $($csvFiles.Count) CSV file(s)" -ForegroundColor Cyan
    
    # Try to identify sign-in and audit log files automatically
    $signInFile = $csvFiles | Where-Object { $_.Name -like "*SignInLogs*" } | Select-Object -First 1
    $auditFile = $csvFiles | Where-Object { $_.Name -like "*DirectoryAuditLogs*" } | Select-Object -First 1
    
    # Verify sign-in file was found
    if (-not $signInFile) {
        Write-Host "No sign-in logs file found. Looking for files with 'SignInLogs' in the name." -ForegroundColor Red
        Write-Host "`nAvailable CSV files:" -ForegroundColor Yellow
        for ($i = 0; $i -lt $csvFiles.Count; $i++) {
            Write-Host "  $($i + 1). $($csvFiles[$i].Name) - $($csvFiles[$i].LastWriteTime)" -ForegroundColor White
        }
        
        $fileIndex = Read-Host "`nEnter the number of the sign-in logs CSV file"
        if ($fileIndex -match '^\d+$' -and [int]$fileIndex -ge 1 -and [int]$fileIndex -le $csvFiles.Count) {
            $signInFile = $csvFiles[[int]$fileIndex - 1]
        } else {
            Write-Host "Invalid selection. Exiting..." -ForegroundColor Red
            return
        }
    }
    
    Write-Host "`nUsing sign-in logs file: $($signInFile.Name)" -ForegroundColor Green
    
    # Check for audit file
    $auditFilePath = $null
    if ($auditFile) {
        Write-Host "Found audit logs file: $($auditFile.Name)" -ForegroundColor Green
        $auditFilePath = $auditFile.FullName
    } else {
        Write-Host "No audit logs file found (looking for 'DirectoryAuditLogs' in filename)" -ForegroundColor Yellow
        Write-Host "Continuing with sign-in logs analysis only..." -ForegroundColor Yellow
    }
    
    # Get user information from the CSV
    Write-Host "`nReading sign-in log data..." -ForegroundColor Cyan
    $signInData = Import-Csv -Path $signInFile.FullName
    
    if ($signInData.Count -eq 0) {
        Write-Host "The sign-in CSV file is empty." -ForegroundColor Red
        return
    }

    # Apply optional Start/End filtering if provided
    if ($Start -or $End) {
        $startDt = $null; $endDt = $null
        if ($Start) { $startDt = Convert-ToUtcDateTime -Value $Start }
        if ($End) { $endDt = Convert-ToUtcDateTime -Value $End }

        # Attempt to identify a datetime column
        $possibleCols = @('createdDateTime','"Date (UTC)"','"Date"','Timestamp','Date','DateTime','activityDateTime')
        $cols = $signInData[0].PSObject.Properties.Name
        $dateField = $cols | Where-Object { $possibleCols -contains $_ } | Select-Object -First 1

        if ($dateField) {
            $signInData = $signInData | Where-Object {
                $raw = $_.$dateField
                $dt = $null
                try { $dt = [DateTime]::Parse($raw) } catch { $dt = $null }
                if (-not $dt) { return $true }
                $utc = $dt.ToUniversalTime()
                $okStart = ($startDt -eq $null -or $utc -ge $startDt)
                $okEnd = ($endDt -eq $null -or $utc -le $endDt)
                return ($okStart -and $okEnd)
            }
            Write-Host "Filtered sign-in records by date field '$dateField' to $($signInData.Count) entries." -ForegroundColor Cyan
        }
        else {
            Write-Host "Start/End provided but no recognized datetime column found in CSV; skipping date filter." -ForegroundColor Yellow
        }
    }
    
    # Try to extract user information
    $firstRecord = $signInData[0]
    $userDisplayName = if ($firstRecord.'User display name') { $firstRecord.'User display name' } else { "Unknown User" }
    $userUPN = if ($firstRecord.'User principal name') { $firstRecord.'User principal name' } else { "unknown@domain.com" }
    
    Write-Host "Analyzing data for user: $userDisplayName ($userUPN)" -ForegroundColor Green
    
    # Get working hours configuration (use provided -Start/-End as hours when valid)
    $ghParams = @{}
    try {
        if ($Start -and $End) {
            $maybeStart = [int]$Start
            $maybeEnd = [int]$End
            if ($maybeStart -ge 0 -and $maybeStart -le 23 -and $maybeEnd -ge 0 -and $maybeEnd -le 23 -and $maybeStart -ne $maybeEnd) {
                $ghParams['StartHourParam'] = $maybeStart
                $ghParams['EndHourParam'] = $maybeEnd
            }
        }
    } catch { }

    if ($ghParams.Count -gt 0) { $workingHours = Get-WorkingHours @ghParams } else { $workingHours = Get-WorkingHours }
    
    # Analyze sign-in logs
    Write-Host "`nAnalyzing sign-in log data..." -ForegroundColor Cyan
    $analysisResults = Analyze-SignInLogs -CsvFilePath $signInFile.FullName -UserDisplayName $userDisplayName -UserUPN $userUPN -WorkingHours $workingHours
    
    # Analyze audit logs if available
    $auditAnalysisResults = $null
    if ($auditFilePath) {
        Write-Host "`nAnalyzing audit log data..." -ForegroundColor Cyan
        $auditAnalysisResults = Analyze-AuditLogs -CsvFilePath $auditFilePath -UserDisplayName $userDisplayName -UserUPN $userUPN -WorkingHours $workingHours
        
        if ($auditAnalysisResults) {
            Write-Host "Audit log analysis completed!" -ForegroundColor Green
            Write-Host "Total audit activities: $($auditAnalysisResults.TotalActivities)" -ForegroundColor Green
        }
    }
    
    if ($analysisResults) {
        # Generate HTML report
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        if ($OutputFolder) {
            $reportFolder = $OutputFolder
            if (-not (Test-Path -Path $reportFolder -PathType Container)) {
                try { New-Item -Path $reportFolder -ItemType Directory -Force | Out-Null } catch {}
            }
        }
        else {
            $reportFolder = $folderPath
        }

        $htmlReportPath = Join-Path -Path $reportFolder -ChildPath "Account_Suspicious_Behavior_Report_$timestamp.html"

        if ($auditAnalysisResults) {
            Generate-HTMLReport -AnalysisResults $analysisResults -OutputPath $htmlReportPath -AuditAnalysisResults $auditAnalysisResults
        } else {
            Generate-HTMLReport -AnalysisResults $analysisResults -OutputPath $htmlReportPath
        }
        
        # Display summary
        Write-Host "`n===== Security Analysis Summary =====" -ForegroundColor Cyan
        Write-Host "Overall Risk Score: $($analysisResults.OverallScore)%" -ForegroundColor $(
            if ($analysisResults.OverallScore -ge 75) { "Red" }
            elseif ($analysisResults.OverallScore -ge 50) { "Yellow" }
            elseif ($analysisResults.OverallScore -ge 25) { "Yellow" }
            else { "Green" }
        )
        
        $riskLevel = if ($analysisResults.OverallScore -ge 75) { "CRITICAL" } 
                    elseif ($analysisResults.OverallScore -ge 50) { "HIGH" } 
                    elseif ($analysisResults.OverallScore -ge 25) { "MEDIUM" } 
                    else { "LOW" }
        
        Write-Host "Risk Level: $riskLevel" -ForegroundColor $(
            if ($analysisResults.OverallScore -ge 75) { "Red" }
            elseif ($analysisResults.OverallScore -ge 50) { "Yellow" }
            else { "Green" }
        )
        
        Write-Host "`nTop Indicators:" -ForegroundColor White
        $topIndicators = $analysisResults.Indicators.GetEnumerator() | 
            Where-Object { $_.Value.Score -gt 0 } | 
            Sort-Object { $_.Value.Score } -Descending | 
            Select-Object -First 5
        
        foreach ($indicator in $topIndicators) {
            $indicatorScore = [Math]::Round($indicator.Value.Score, 0)
            Write-Host "  - $($indicator.Key): $indicatorScore% (Count: $($indicator.Value.Count))" -ForegroundColor Yellow
        }
        
        # Display audit log summary if available
        if ($auditAnalysisResults) {
            Write-Host "`nAudit Log Summary:" -ForegroundColor White
            Write-Host "  - Total Activities: $($auditAnalysisResults.TotalActivities)" -ForegroundColor Cyan
            Write-Host "  - Successful Activities: $($auditAnalysisResults.SuccessfulActivities)" -ForegroundColor Green
        }
        
        Write-Host "`nHTML Report: $htmlReportPath" -ForegroundColor Green
        
        # Offer to open the report (only in interactive mode when -Open switch is not provided)
        if (-not $Open) {
            $openReport = Read-Host "`nWould you like to open the HTML report now? (Y/N)"
            if ($openReport -eq 'Y' -or $openReport -eq 'y') {
                $pathToOpen = if ($htmlReportPath -is [System.Array]) { $htmlReportPath[0] } else { $htmlReportPath }
                try { Start-Process -FilePath $pathToOpen } catch { Write-Host "Failed to open report: $_" -ForegroundColor Yellow }
            }
        }
        elseif ($Open) {
            # -Open switch was provided, automatically open the report
            $pathToOpen = if ($htmlReportPath -is [System.Array]) { $htmlReportPath[0] } else { $htmlReportPath }
            try { Start-Process -FilePath $pathToOpen } catch { Write-Host "Failed to open report: $_" -ForegroundColor Yellow }
        }
    }
    
        Write-Host "`n===== Analysis Completed =====" -ForegroundColor Cyan
        if ($htmlReportPath) {
            return $htmlReportPath
        }
        else {
            return $null
        }
    }

# Function to connect to Entra ID and export logs
function Connect-AndExportLogs {
    param(
        [string]$ConnectUPN = $null,
        [string]$AffectedUPNParam = $null,
        [string]$OutputFolderParam = $null,
        [string]$Start = $null,
        [string]$End = $null,
        [switch]$OpenReport
    )

    Write-Host "`n===== Connect to Entra ID and Export Logs =====" -ForegroundColor Cyan
    
    try {
        # Step 1: Install required modules
        Install-RequiredModules
        
        # Step 2: Import modules
        Write-Host "`nImporting Microsoft Graph modules..." -ForegroundColor Cyan
        Import-Module Microsoft.Graph.Authentication
        Import-Module Microsoft.Graph.Reports
        
        # Step 3: Check current connection status
        $currentContext = Get-MgContext -ErrorAction SilentlyContinue
        if ($currentContext) {
            Write-Host "`nAlready connected to Microsoft Graph as: $($currentContext.Account)" -ForegroundColor Yellow
            Write-Host "Tenant: $($currentContext.TenantId)" -ForegroundColor Yellow
            $reauth = Read-Host "Do you want to re-authenticate with different credentials? (Y/N)"
            if ($reauth -eq 'Y' -or $reauth -eq 'y') {
                Write-Host "`nDisconnecting current session..." -ForegroundColor Cyan
                Disconnect-MgGraph | Out-Null
            } else {
                Write-Host "Using existing connection." -ForegroundColor Green
            }
        }
        
        # Step 4: Connect to Microsoft Graph if not already connected
        if (-not (Get-MgContext)) {
            Write-Host "`nPlease enter your Entra ID credentials in the authentication window..." -ForegroundColor Yellow
            
            try {
                # Connect to Microsoft Graph with required scopes
                Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All" -ErrorAction Stop
                Write-Host "Successfully connected to Microsoft Graph." -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to connect to Microsoft Graph. Error: $_" -ForegroundColor Red
                return
            }
        }
        
        # Step 5: Determine output folder
        if ($OutputFolderParam) {
            $outputFolder = $OutputFolderParam
            if (-not (Test-Path -Path $outputFolder -PathType Container)) {
                try { New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null } catch {}
            }
            Write-Host "Using folder: $outputFolder" -ForegroundColor Green
        }
        else {
            $outputFolder = Get-OutputFolderPath
            Write-Host "Using folder: $outputFolder" -ForegroundColor Green
        }

        # Step 6: Determine the target user UPN to analyze
        if ($AffectedUPNParam) {
            $userUPN = $AffectedUPNParam
        }
        else {
            $userUPN = Read-Host "`nEnter the User Principal Name (UPN) of the user"
        }

        if ([string]::IsNullOrWhiteSpace($userUPN)) {
            Write-Host "No UPN provided. Exiting script." -ForegroundColor Red
            Disconnect-MgGraph | Out-Null
            return
        }
        
        # Get user object ID from UPN
        Write-Host "Looking up user '$userUPN'..." -ForegroundColor Yellow
        try {
            $userUri = "https://graph.microsoft.com/v1.0/users/$userUPN"
            $userObject = Invoke-MgGraphRequest -Uri $userUri -Method GET -ErrorAction Stop
            $userId = $userObject.id
            
            Write-Host "Found user: $($userObject.displayName) (ID: $userId)" -ForegroundColor Green
            
            $userFilter = "userId eq '$userId'"
            $csvFilePrefix = "Signinlogs_$($userUPN.Replace('@','_'))"
        }
        catch {
            Write-Host "Failed to find user '$userUPN'. Error: $_" -ForegroundColor Red
            Disconnect-MgGraph | Out-Null
            return
        }
        
        # Step 6: Generate filename with timestamp
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvFileName = "${csvFilePrefix}_$timestamp.csv"
        $csvFilePath = Join-Path -Path $outputFolder -ChildPath $csvFileName
        
        # Step 7: Retrieve sign-in logs using Graph API Beta endpoint
        Write-Host "`nRetrieving Entra ID sign-in logs for user '$userUPN'..." -ForegroundColor Cyan
        Write-Host "This may take a few minutes depending on the amount of data..." -ForegroundColor Yellow
        
        try {
            # Determine if Start/End represent working-hour integers (0-23)
            $useHourRange = $false
            try {
                if ($Start -and $End) {
                    $maybeStart = [int]$Start
                    $maybeEnd = [int]$End
                    if ($maybeStart -ge 0 -and $maybeStart -le 23 -and $maybeEnd -ge 0 -and $maybeEnd -le 23 -and $maybeStart -ne $maybeEnd) {
                        $useHourRange = $true
                    }
                }
            } catch { $useHourRange = $false }

            # Build OData date filter only when not using hour-range
            $odataFilter = $userFilter
            if (-not $useHourRange) {
                $startDt = $null; $endDt = $null
                if ($Start) { $startDt = Convert-ToUtcDateTime -Value $Start }
                if ($End)   { $endDt = Convert-ToUtcDateTime -Value $End }

                if ($startDt) { $odataFilter += " and createdDateTime ge $($startDt.ToString('yyyy-MM-ddTHH:mm:ssZ'))" }
                if ($endDt)   { $odataFilter += " and createdDateTime le $($endDt.ToString('yyyy-MM-ddTHH:mm:ssZ'))" }
            }

            # Use beta endpoint with user and optional date filter
            $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$odataFilter"
            $allSignInLogs = @()
            
            do {
                $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
                
                if ($response.value) {
                    $allSignInLogs += $response.value
                    Write-Host "Retrieved $($allSignInLogs.Count) records so far..." -ForegroundColor Yellow
                }
                
                # Get next page if available
                $uri = $response.'@odata.nextLink'
                
            } while ($uri)
            
            $signInLogs = $allSignInLogs
            
            if ($signInLogs.Count -eq 0) {
                Write-Host "No sign-in logs found." -ForegroundColor Yellow
                # Do not return here; allow audit-only reports or empty sign-in analysis
            }
            
            Write-Host "Retrieved $($signInLogs.Count) sign-in log entries." -ForegroundColor Green
            
        }
        catch {
            Write-Host "Failed to retrieve sign-in logs. Error: $_" -ForegroundColor Red
            Disconnect-MgGraph | Out-Null
            return
        }
    
    # Step 7: Process and export to CSV with full details
    Write-Host "`nProcessing and exporting data to CSV..." -ForegroundColor Cyan
    
    try {
        # Expand nested properties for comprehensive export from beta API response
        $exportData = $signInLogs | ForEach-Object {
            [PSCustomObject]@{
                'Date (UTC)' = $_.createdDateTime
                'Request ID' = $_.id
                'User agent' = $_.userAgent
                'Correlation ID' = $_.correlationId
                'User ID' = $_.userId
                'User' = $_.userDisplayName
                'Username' = $_.userPrincipalName
                'User type' = $_.userType
                'Cross tenant access type' = $_.crossTenantAccessType
                'Incoming token type' = $_.incomingTokenType
                'Authentication Protocol' = $_.authenticationProtocol
                'Unique token identifier' = $_.uniqueTokenIdentifier
                'Original transfer method' = $_.originalTransferMethod
                'Client credential type' = $_.clientCredentialType
                'Token Protection - Sign In Session' = $_.sessionLifetimePolicy.expirationRequirement
                'Token Protection - Sign In Session StatusCode' = $_.signInSessionStatusCode
                'Application' = $_.appDisplayName
                'Application ID' = $_.appId
                'App owner tenant ID' = $_.appOwnerTenantId
                'Resource' = $_.resourceDisplayName
                'Resource ID' = $_.resourceId
                'Resource tenant ID' = $_.resourceTenantId
                'Resource owner tenant ID' = $_.resourceOwnerTenantId
                'Home tenant ID' = $_.homeTenantId
                'Home tenant name' = $_.homeTenantName
                'IP address' = $_.ipAddress
                'Location' = if ($_.location) {
                    $locParts = @()
                    if ($_.location.city) { $locParts += $_.location.city }
                    if ($_.location.state) { $locParts += $_.location.state }
                    if ($_.location.countryOrRegion) { $locParts += $_.location.countryOrRegion }
                    $locParts -join ', '
                } else { $null }
                'Location - City' = $_.location.city
                'Location - State' = $_.location.state
                'Location - Country/Region' = $_.location.countryOrRegion
                'Location - Latitude' = $_.location.geoCoordinates.latitude
                'Location - Longitude' = $_.location.geoCoordinates.longitude
                'Status' = if ($_.status.errorCode -eq 0) { 
                    "Success" 
                } elseif ($_.status.errorCode -eq 50058 -or $_.status.failureReason -match 'interrupt') { 
                    "Interrupted" 
                } elseif ($_.status.errorCode) { 
                    "Failure" 
                } else { 
                    $null 
                }
                'Sign-in error code' = $_.status.errorCode
                'Failure reason' = $_.status.failureReason
                'Status - Additional Details' = $_.status.additionalDetails
                'Client app' = $_.clientAppUsed
                'Is Interactive' = $_.isInteractive
                'Device ID' = $_.deviceDetail.deviceId
                'Device Display Name' = $_.deviceDetail.displayName
                'Browser' = $_.deviceDetail.browser
                'Operating System' = $_.deviceDetail.operatingSystem
                'Compliant' = $_.deviceDetail.isCompliant
                'Managed' = $_.deviceDetail.isManaged
                'Join Type' = $_.deviceDetail.trustType
                'Multifactor authentication result' = if ($_.mfaDetail.authMethod) { "Success" } elseif ($_.authenticationRequirement -eq 'multiFactorAuthentication') { "Required" } else { "Not Required" }
                'Multifactor authentication auth method' = $_.mfaDetail.authMethod
                'Multifactor authentication auth detail' = $_.mfaDetail.authDetail
                'Authentication requirement' = $_.authenticationRequirement
                'Sign-in identifier' = $_.signInIdentifier
                'Session ID' = $_.sessionId
                'Sign-in identifier type' = $_.signInIdentifierType
                'Sign-in event types' = if ($_.signInEventTypes) { ($_.signInEventTypes -join '; ') } else { $null }
                'IP address (seen by resource)' = $_.ipAddressFromResourceProvider
                'Is Tenant Restricted' = $_.isTenantRestricted
                'Is Through Global Secure Access' = $_.isThroughGlobalSecureAccess
                'Global Secure Access IP address' = $_.globalSecureAccessIpAddress
                'Autonomous system number' = $_.autonomousSystemNumber
                'Flagged for review' = $_.flaggedForReview
                'Token issuer type' = $_.tokenIssuerType
                'Token issuer name' = $_.tokenIssuerName
                'Sign In Token Protection Status' = $_.signInTokenProtectionStatus
                'Token Protection - Sign In Session Status' = $_.tokenProtectionStatusDetails.signInSessionStatus
                'Token Protection - Sign In Session Code' = $_.tokenProtectionStatusDetails.signInSessionStatusCode
                'Latency' = $_.processingTimeInMilliseconds
                'Conditional Access Status' = $_.conditionalAccessStatus
                'Conditional Access Policies' = $(if ($_.appliedConditionalAccessPolicies) { ($_.appliedConditionalAccessPolicies | ForEach-Object { "$($_.displayName): $($_.result)" }) -join '; ' } else { $null })
                'Conditional Access Audiences' = $(if ($_.conditionalAccessAudiences) { ($_.conditionalAccessAudiences -join '; ') } else { $null })
                'Risk Detail' = $_.riskDetail
                'Risk Level Aggregated' = $_.riskLevelAggregated
                'Risk Level During SignIn' = $_.riskLevelDuringSignIn
                'Risk State' = $_.riskState
                'Risk Event Types' = $(if ($_.riskEventTypes) { ($_.riskEventTypes -join '; ') } else { $null })
                'Risk Event Types v2' = $(if ($_.riskEventTypes_v2) { ($_.riskEventTypes_v2 -join '; ') } else { $null })
                'Sign-in risk detection' = (Get-RiskEventEnrichment -RiskEventTypesV2 $(if ($_.riskEventTypes_v2) { ($_.riskEventTypes_v2 -join '; ') } else { $null })).Descriptions
                'Detection type' = (Get-RiskEventEnrichment -RiskEventTypesV2 $(if ($_.riskEventTypes_v2) { ($_.riskEventTypes_v2 -join '; ') } else { $null })).DetectionTypes
                'Original Request ID' = $_.originalRequestId
                'Managed Identity type' = $_.managedServiceIdentity.msiType
                'Associated Resource Id' = $_.managedServiceIdentity.associatedResourceId
                'Federated Credential Id' = $_.federatedCredentialId
                'Federated Token Id' = $_.managedServiceIdentity.federatedTokenId
                'Federated Token Issuer' = $_.managedServiceIdentity.federatedTokenIssuer
                'Resource Service Principal Id' = $_.resourceServicePrincipalId
                'Authentication Context Class References' = $(if ($_.authenticationContextClassReferences) { ($_.authenticationContextClassReferences | ForEach-Object { "$($_.id) - $($_.detail)" }) -join '; ' } else { $null })
                'Authentication Details' = $(if ($_.authenticationDetails) { ($_.authenticationDetails | ForEach-Object { "Method: $($_.authenticationMethod), Result: $($_.succeeded), Detail: $($_.authenticationStepResultDetail)" }) -join '; ' } else { $null })
                'Authentication Requirement Policies' = $(if ($_.authenticationRequirementPolicies) { ($_.authenticationRequirementPolicies | ForEach-Object { "$($_.requirementProvider): $($_.detail)" }) -join '; ' } else { $null })
                'Authentication Method Details' = $(if ($_.authenticationMethodsUsed) { ($_.authenticationMethodsUsed -join '; ') } else { $null })
                'Applied Event Listeners' = $(if ($_.appliedEventListeners) { ($_.appliedEventListeners | ForEach-Object { $_.displayName }) -join '; ' } else { $null })
                'Private Link Details - Policy Id' = $_.privateLinkDetails.policyId
                'Private Link Details - Policy Name' = $_.privateLinkDetails.policyName
                'Private Link Details - Resource Id' = $_.privateLinkDetails.resourceId
                'Private Link Details - Policy Tenant Id' = $_.privateLinkDetails.policyTenantId
                'Service Principal Credential Key Id' = $_.servicePrincipalCredentialKeyId
                'Service Principal Credential Thumbprint' = $_.servicePrincipalCredentialThumbprint
                'Service Principal Id' = $_.servicePrincipalId
                'Service Principal Name' = $_.servicePrincipalName
                'Authentication App Device Details' = $_.authenticationAppDeviceDetails
                'Authentication App Policy Evaluation Details' = $(if ($_.authenticationAppPolicyEvaluationDetails) { ($_.authenticationAppPolicyEvaluationDetails -join '; ') } else { $null })
                'Session Lifetime Policies' = $(if ($_.sessionLifetimePolicies) { ($_.sessionLifetimePolicies -join '; ') } else { $null })
                'Agent Type' = $_.agent.agentType
                'Agent Parent App Id' = $_.agent.parentAppId
                'Agent Subject Type' = $_.agent.agentSubjectType
                'Agent Subject Parent Id' = $_.agent.agentSubjectParentId
                'Authentication Processing Details' = $(if ($_.authenticationProcessingDetails) { ($_.authenticationProcessingDetails | ForEach-Object { "$($_.key): $($_.value)" }) -join '; ' } else { $null })
                'Network Location Details' = $(if ($_.networkLocationDetails) { ($_.networkLocationDetails | ForEach-Object { "Type: $($_.networkType), Names: $(($_.networkNames -join ','))" }) -join '; ' } else { $null })
            }
        }
        
        # Export to CSV
        $exportData | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8
        
        Write-Host "`nExport completed successfully!" -ForegroundColor Green
        Write-Host "File saved to: $csvFilePath" -ForegroundColor Green
        Write-Host "Total records exported: $($signInLogs.Count)" -ForegroundColor Green
        
        # Step 8: Get working hours configuration (use provided -Start/-End as hours when valid)
        $ghParams = @{}
        try {
            if ($Start -and $End) {
                $maybeStart = [int]$Start
                $maybeEnd = [int]$End
                if ($maybeStart -ge 0 -and $maybeStart -le 23 -and $maybeEnd -ge 0 -and $maybeEnd -le 23 -and $maybeStart -ne $maybeEnd) {
                    $ghParams['StartHourParam'] = $maybeStart
                    $ghParams['EndHourParam'] = $maybeEnd
                }
            }
        } catch { }

        if ($ghParams.Count -gt 0) { $workingHours = Get-WorkingHours @ghParams } else { $workingHours = Get-WorkingHours }
        
        # Step 9: Analyze the data for indicators of suspicious behavior
        Write-Host "`n===== Analyzing Sign-In Logs for Security Risks =====" -ForegroundColor Cyan
        
        $analysisResults = Analyze-SignInLogs -CsvFilePath $csvFilePath -UserDisplayName $userObject.displayName -UserUPN $userUPN -WorkingHours $workingHours
        
        # Step 10: Export Directory Audit Logs
        Write-Host "`n===== Exporting Directory Audit Logs =====" -ForegroundColor Cyan
        $auditLogPath = Export-DirectoryAuditLogs -UserId $userId -UserUPN $userUPN -OutputFolder $outputFolder -Timestamp $timestamp
        
        # Analyze audit logs if export was successful
        $auditAnalysisResults = $null
        if ($auditLogPath) {
            Write-Host "`nAnalyzing audit log data..." -ForegroundColor Cyan
            $auditAnalysisResults = Analyze-AuditLogs -CsvFilePath $auditLogPath -UserDisplayName $userObject.displayName -UserUPN $userUPN -WorkingHours $workingHours
            
            if ($auditAnalysisResults) {
                Write-Host "Audit log analysis completed!" -ForegroundColor Green
                Write-Host "Total audit activities: $($auditAnalysisResults.TotalActivities)" -ForegroundColor Green
            }
        }
        
        if ($analysisResults -or $auditAnalysisResults) {
            # If no sign-in analysis but audit analysis exists, create a minimal placeholder AnalysisResults
            if (-not $analysisResults -and $auditAnalysisResults) {
                $analysisResults = @{
                    OverallScore = 0
                    Indicators = @{}
                    TotalSignIns = 0
                    SuccessfulSignIns = 0
                    SuccessPercentage = 0
                    FailurePercentage = 0
                    InterruptedSignIns = 0
                    InterruptedPercentage = 0
                    UniqueCountries = 0
                    UniqueIPs = 0
                    FailedSignIns = 0
                    UniqueSessionIds = 0
                    UniqueApplications = 0
                    UniqueClientApps = 0
                    UniqueResources = 0
                    UniqueOperatingSystems = 0
                    UserDisplayName = $userObject.displayName
                    UserUPN = $userUPN
                    AnalysisDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    CountriesList = @()
                    LocationsList = @()
                    IPsList = @()
                    SessionIdsList = @()
                    ApplicationsList = @()
                    ClientAppsList = @()
                    ResourcesList = @()
                    OperatingSystemsList = @()
                    FailedSignInsList = @()
                    InterruptedSignInsList = @()
                    SuccessfulSignInsList = @()
                }
            }

            # Generate HTML report with both sign-in and audit data (audit may be null)
            $htmlReportPath = Join-Path -Path $outputFolder -ChildPath "Account_Suspicious_Behavior_Report_$timestamp.html"
            Generate-HTMLReport -AnalysisResults $analysisResults -OutputPath $htmlReportPath -AuditAnalysisResults $auditAnalysisResults
            
            # Display summary
            Write-Host "`n===== Security Analysis Summary =====" -ForegroundColor Cyan
            Write-Host "Overall Risk Score: $($analysisResults.OverallScore)%" -ForegroundColor $(
                if ($analysisResults.OverallScore -ge 75) { "Red" }
                elseif ($analysisResults.OverallScore -ge 50) { "Yellow" }
                elseif ($analysisResults.OverallScore -ge 25) { "Yellow" }
                else { "Green" }
            )
            
            $riskLevel = if ($analysisResults.OverallScore -ge 75) { "CRITICAL" } 
                        elseif ($analysisResults.OverallScore -ge 50) { "HIGH" } 
                        elseif ($analysisResults.OverallScore -ge 25) { "MEDIUM" } 
                        else { "LOW" }
            
            Write-Host "Risk Level: $riskLevel" -ForegroundColor $(
                if ($analysisResults.OverallScore -ge 75) { "Red" }
                elseif ($analysisResults.OverallScore -ge 50) { "Yellow" }
                else { "Green" }
            )
            
            Write-Host "`nTop Indicators:" -ForegroundColor White
            $topIndicators = $analysisResults.Indicators.GetEnumerator() | 
                Where-Object { $_.Value.Score -gt 0 } | 
                Sort-Object { $_.Value.Score } -Descending | 
                Select-Object -First 5
            
            foreach ($indicator in $topIndicators) {
                $indicatorScore = [Math]::Round($indicator.Value.Score, 0)
                Write-Host "  - $($indicator.Key): $indicatorScore% (Count: $($indicator.Value.Count))" -ForegroundColor Yellow
            }
            
            # Display audit log summary if available
            if ($auditAnalysisResults) {
                Write-Host "`nAudit Log Summary:" -ForegroundColor White
                Write-Host "  - Total Activities: $($auditAnalysisResults.TotalActivities)" -ForegroundColor Cyan
                Write-Host "  - Successful Activities: $($auditAnalysisResults.SuccessfulActivities)" -ForegroundColor Green
            }
            
            Write-Host "`nHTML Report: $htmlReportPath" -ForegroundColor Green
            
            # Offer to open the report
            if ($OpenReport) {
                $pathToOpen = if ($htmlReportPath -is [System.Array]) { $htmlReportPath[0] } else { $htmlReportPath }
                if (Test-Path -Path $pathToOpen) { Start-Process -FilePath $pathToOpen }
                else { Write-Host "Report not found: $pathToOpen" -ForegroundColor Yellow }
            }
            else {
                try {
                    $openAnswer = Read-Host "`nWould you like to open the HTML report now? (Y/N)"
                    if ($openAnswer -and $openAnswer.Trim().ToUpper() -in @('Y','YES')) {
                        $pathToOpen = if ($htmlReportPath -is [System.Array]) { $htmlReportPath[0] } else { $htmlReportPath }
                        if (Test-Path -Path $pathToOpen) { Start-Process -FilePath $pathToOpen }
                        else { Write-Host "Report not found: $pathToOpen" -ForegroundColor Yellow }
                    }
                }
                catch {
                    Write-Host "Unable to open report automatically: $_" -ForegroundColor Yellow
                }
            }
            # Return the generated report path for the caller
            if ($htmlReportPath) { return $htmlReportPath }
        }
        
    }
    catch {
        Write-Host "Failed to export data to CSV. Error: $_" -ForegroundColor Red
        Disconnect-MgGraph | Out-Null
        exit 1
    }
    
        # Step 10: Disconnect from Microsoft Graph
        Write-Host "`nDisconnecting from Microsoft Graph..." -ForegroundColor Cyan
        Disconnect-MgGraph | Out-Null
        Write-Host "Disconnected successfully." -ForegroundColor Green
        
        Write-Host "`n===== Process Completed =====" -ForegroundColor Cyan
    }
    catch {
        Write-Host "`nAn unexpected error occurred: $_" -ForegroundColor Red
        if (Get-MgContext) {
            Disconnect-MgGraph | Out-Null
        }
    }
}
#endregion

# Main Script Execution

    Write-Host "`n===== Account Suspicious Behavior Checker =====" -ForegroundColor Cyan
$scriptStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
try {
    # If importCSVPath parameter provided, run non-interactively
    if ($importCSVPath) {
        if (-not (Test-Path -Path $importCSVPath)) {
            Write-Host "Specified import path does not exist: $importCSVPath" -ForegroundColor Red
            exit 1
        }

        # If importCSVPath is a file, use its parent folder
        if ((Test-Path -Path $importCSVPath -PathType Leaf)) {
            $folder = Split-Path -Path $importCSVPath -Parent
        }
        else {
            $folder = $importCSVPath
        }

        $reportPath = Analyze-ExistingCSVFiles -FolderPath $folder -OutputFolder $Output -Start $Start -End $End -Open:$Open
    }
    elseif ($EntraIDConnect) {
        # Non-interactive Entra ID connect and analysis
        $reportPath = Connect-AndExportLogs -ConnectUPN $EntraIDConnect -AffectedUPNParam $AffectedUPN -OutputFolderParam $Output -Start $Start -End $End -OpenReport:$Open
        if ($Open -and $reportPath) {
            $pathToOpen = if ($reportPath -is [System.Array]) { $reportPath[0] } else { $reportPath }
            try { Start-Process -FilePath $pathToOpen } catch { Write-Host "Failed to open report: $_" -ForegroundColor Yellow }
        }
    }
    else {
        # Interactive menu
        $selection = Show-MainMenu
        if ($selection -eq '1') {
            Analyze-ExistingCSVFiles
        }
        elseif ($selection -eq '2') {
            Connect-AndExportLogs
        }
    }
    
    # Display script execution time
    $scriptStopwatch.Stop()
    $elapsed = $scriptStopwatch.Elapsed
    Write-Host "`n===== Script Execution Time =====" -ForegroundColor Cyan
    if ($elapsed.TotalHours -ge 1) {
        Write-Host "Total Time: $([Math]::Floor($elapsed.TotalHours))h $($elapsed.Minutes)m $($elapsed.Seconds)s" -ForegroundColor Green
    } elseif ($elapsed.TotalMinutes -ge 1) {
        Write-Host "Total Time: $($elapsed.Minutes)m $($elapsed.Seconds)s" -ForegroundColor Green
    } else {
        Write-Host "Total Time: $($elapsed.Seconds)s $($elapsed.Milliseconds)ms" -ForegroundColor Green
    }
}
catch {
    Write-Host "`nAn unexpected error occurred: $_" -ForegroundColor Red
    if ($scriptStopwatch) {
        $scriptStopwatch.Stop()
        $elapsed = $scriptStopwatch.Elapsed
        Write-Host "Script ran for: $($elapsed.Minutes)m $($elapsed.Seconds)s before error" -ForegroundColor Yellow
    }
    exit 1
}


# SIG # Begin signature block
# MIIFwQYJKoZIhvcNAQcCoIIFsjCCBa4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUr816CFpSmDDDeBhkDCYpyR1w
# o+igggNAMIIDPDCCAiSgAwIBAgIQEwQ/TrNamJlGjSmrJ+kbVDANBgkqhkiG9w0B
# AQsFADA2MTQwMgYDVQQDDCtBYmR1bGxhaFptYWlsaUNvZGVTaWduaW5nQWNjb3Vu
# dENvbXByb21pc2VkMB4XDTI2MDEwNDE1MDgzOVoXDTI3MDEwNDE1MjgzOVowNjE0
# MDIGA1UEAwwrQWJkdWxsYWhabWFpbGlDb2RlU2lnbmluZ0FjY291bnRDb21wcm9t
# aXNlZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMwmhbeWIptSNGCM
# CBe9GKsoIfx5/mSKpaBdH+u0TSHeXe+q4UdOJUJGp6ZAae6AldJdETind5odoswI
# w0GIdNv0rDXZ9AIAohqltOHIz3/bXzW9/7F7iI8vIIjUZttb8ZKJajaqb4I4BTbM
# fbsJggvbjfH1Ur2iN1d3RmlwFb0gJvntoCyG5X8mu7tN+Q8QkJsKpuB6cx8FqqSc
# /2Vo1GsFJlKEKyGRDn9kfp5pRUhW+wwKbPvONEfwxgbobwszkBr/2DySqf2iKWFy
# xQPDrC88cQNhbTom5KOUOFib20RwhXIzeGj6BihINkBV3zMO1EFclDgIN70kWaTn
# rJj1JGECAwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUF
# BwMDMB0GA1UdDgQWBBQAvjKbT/vu7F3y1B3lYsSha3OfzDANBgkqhkiG9w0BAQsF
# AAOCAQEArkVPTFJa45VUTtBzzD0iZJcuFYeHSKNpKYC2wQoZ+0wsG0xxpU/zhD/r
# O+HsKpFbLghl7I2pIiDqV9hX5+IdKk39012JkzLsAxo9R+PtPgFjZ9bVf3J8+0FB
# 6v9L9vKj2aFLYyQC5H5NbhBC0HsvYcbYAID/PzWPSC7s6/ljtlUGe1/NodWgMTXM
# Qilqb/x6tpqs0KhX0fEsO11MkgNyuCLh53Nsf+z4+49AMB3047W4JDD7m/Q92rTR
# 8kJQHETs7LrG5Zdk9/kLErhza/3y+tf9DU5OLfR1Hn1nMavFGWVoVDQVrXKh/s4K
# olbQH6jpgeOuHQd78nK24fDoG6cKVTGCAeswggHnAgEBMEowNjE0MDIGA1UEAwwr
# QWJkdWxsYWhabWFpbGlDb2RlU2lnbmluZ0FjY291bnRDb21wcm9taXNlZAIQEwQ/
# TrNamJlGjSmrJ+kbVDAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUbOsUmFmurLcM4tK9pAtoKEWP
# XT0wDQYJKoZIhvcNAQEBBQAEggEAMI1NNjCD8Gz8oaZ8MSQ+0YBamUryPZTSMubl
# fsW0e/aLLZCPVN3Y2W+Ouz+MRCBvC+IX8bWUdi+7SFSOIHsnU/4UQcQ+MDjSVWee
# Zcm7EADBvf8ESEYylm+OQkWijIeQygaU9kipoyqjGqn6AmOMYHAv8AoMHiLRsrtP
# xI36dsxRk8VeSbsl5425MAT+HQtTFwBZFrWNL0v6izE6HL5sEX/TWoNB8Tjn6S8u
# vmKDTNrI7AmIqoSlLUCnubXjsh7EsphJEAKSFPBbG1YRRGSnxooC9uzvumGlf8OB
# o3BT/V1eQ6Jt+NN+CXDmy+Fd0opWLqrJLFAArrlpiSlOgsPAHQ==
# SIG # End signature block
