# acunetix_automation.ps1
# Acunetix Web Vulnerability Scanner Automation Script
# Version: 1.0
# Description: Automates Acunetix scanning and reporting tasks

# ============================================
# INITIALIZATION AND CONFIGURATION
# ============================================

# Script metadata
$ScriptVersion = "1.0"
$ScriptName = "Acunetix Automation Script"

# Configuration variables
$AcunetixServer = "https://localhost:13443"
$ApiKey = $null
$ReportPath = "C:\SecurityTools\Reports\"
$LogPath = "C:\SecurityTools\Logs\"
$LogFile = "acunetix_automation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Scan configuration
$Global:ScanTypes = @{
    "1" = @{Name="Full Scan"; Description="Complete web application scan"}
    "2" = @{Name="High Risk Vulnerabilities"; Description="Scan for critical vulnerabilities only"}
    "3" = @{Name="Cross-site Scripting"; Description="XSS specific scan"}
    "4" = @{Name="SQL Injection"; Description="SQLi specific scan"}
}

# Connection status
$Global:IsConnected = $false
$Global:SessionHeaders = $null

# ============================================
# LOGGING FUNCTIONS
# ============================================

function Initialize-Logging {
    <#
    .SYNOPSIS
    Initializes logging system
    #>
    
    # Create directories if they don't exist
    if (!(Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
        Write-Host "Created log directory: $LogPath" -ForegroundColor Green
    }
    
    if (!(Test-Path $ReportPath)) {
        New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
        Write-Host "Created report directory: $ReportPath" -ForegroundColor Green
    }
    
    # Start logging
    Start-Transcript -Path (Join-Path $LogPath $LogFile) -Append
    Write-Log "Script started - $ScriptName v$ScriptVersion"
}

function Write-Log {
    <#
    .SYNOPSIS
    Writes message to log file and console
    .PARAMETER Message
    Message to log
    .PARAMETER Level
    Log level (INFO, WARNING, ERROR, SUCCESS)
    #>
    
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    
    # Write to console with colors
    switch ($Level) {
        "INFO" { Write-Host $logEntry -ForegroundColor Gray }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        default { Write-Host $logEntry }
    }
    
    # Also write to transcript (captured by Start-Transcript)
    Write-Output $logEntry
}

# ============================================
# PREREQUISITE CHECK FUNCTIONS
# ============================================

function Test-Prerequisites {
    <#
    .SYNOPSIS
    Checks if all prerequisites are met
    #>
    
    Write-Log "Checking prerequisites..." "INFO"
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion.Major
    if ($psVersion -lt 5) {
        Write-Log "PowerShell 5.1 or later is required (current: $psVersion)" "ERROR"
        return $false
    }
    Write-Log "PowerShell version $psVersion - OK" "SUCCESS"
    
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Log "Administrative privileges required. Please run as Administrator." "ERROR"
        return $false
    }
    Write-Log "Running as Administrator - OK" "SUCCESS"
    
    # Check required modules
    $requiredModules = @("PSLogging")
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Log "Module $module is not installed. Attempting to install..." "WARNING"
            try {
                Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
                Import-Module $module
                Write-Log "Module $module installed successfully" "SUCCESS"
            } catch {
                Write-Log "Failed to install module $module. Please install manually." "ERROR"
                return $false
            }
        } else {
            Import-Module $module -ErrorAction SilentlyContinue
            Write-Log "Module $module - OK" "SUCCESS"
        }
    }
    
    return $true
}

# ============================================
# ACUNETIX API FUNCTIONS
# ============================================

function Connect-AcunetixServer {
    <#
    .SYNOPSIS
    Connects to Acunetix server using API key
    #>
    
    Clear-Host
    Write-Host "=== CONNECT TO ACUNETIX SERVER ===" -ForegroundColor Cyan
    Write-Host ""
    
    # Get server URL
    $serverInput = Read-Host "Enter Acunetix server URL (default: $AcunetixServer)"
    if ($serverInput) {
        $script:AcunetixServer = $serverInput
    }
    
    # Get API key
    $script:ApiKey = Read-Host "Enter API key" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:ApiKey)
    $plainApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    
    # Test connection
    Write-Log "Testing connection to $AcunetixServer..." "INFO"
    
    try {
        # Set up headers for API calls
        $script:SessionHeaders = @{
            "X-Auth" = $plainApiKey
            "Content-Type" = "application/json"
            "Accept" = "application/json"
        }
        
        # Test API endpoint (adjust based on your Acunetix version)
        $testUrl = "$AcunetixServer/api/v1/me"
        $response = Invoke-RestMethod -Uri $testUrl -Method Get -Headers $script:SessionHeaders -ErrorAction Stop
        
        $script:IsConnected = $true
        Write-Log "Successfully connected to Acunetix server!" "SUCCESS"
        Write-Log "User: $($response.username)" "INFO"
        Write-Log "Email: $($response.email)" "INFO"
        
        Pause
        return $true
        
    } catch {
        Write-Log "Failed to connect to Acunetix server: $_" "ERROR"
        $script:IsConnected = $false
        Pause
        return $false
    } finally {
        # Clear the plain API key from memory
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
}

function Start-NewScan {
    <#
    .SYNOPSIS
    Starts a new security scan
    #>
    
    if (-not $script:IsConnected) {
        Write-Log "Not connected to Acunetix server. Please connect first." "ERROR"
        Pause
        return
    }
    
    Clear-Host
    Write-Host "=== START NEW SCAN ===" -ForegroundColor Cyan
    Write-Host ""
    
    # Get target URL
    $targetUrl = Read-Host "Enter target URL (e.g., https://example.com)"
    if (-not $targetUrl) {
        Write-Log "Target URL is required" "ERROR"
        Pause
        return
    }
    
    # Show scan types
    Write-Host "`nAvailable Scan Types:" -ForegroundColor Yellow
    foreach ($key in $script:ScanTypes.Keys | Sort-Object) {
        Write-Host "  $key. $($script:ScanTypes[$key].Name)" -ForegroundColor White
        Write-Host "     $($script:ScanTypes[$key].Description)" -ForegroundColor Gray
    }
    Write-Host ""
    
    # Select scan type
    $scanTypeChoice = Read-Host "Select scan type (1-4)"
    if (-not $script:ScanTypes.ContainsKey($scanTypeChoice)) {
        Write-Log "Invalid scan type selection" "ERROR"
        Pause
        return
    }
    
    $scanType = $script:ScanTypes[$scanTypeChoice].Name
    
    # Configure scan parameters
    Write-Host "`nConfigure Scan Parameters:" -ForegroundColor Yellow
    
    $profile = Read-Host "Scan profile (default: Full Scan)"
    if (-not $profile) { $profile = "Full Scan" }
    
    $maxScanTime = Read-Host "Maximum scan time in minutes (default: 60)"
    if (-not $maxScanTime) { $maxScanTime = 60 }
    
    # Create scan configuration
    $scanConfig = @{
        target_id = $targetUrl
        profile_id = $profile
        schedule = @{
            disable = $false
            start_date = $null
            time_sensitive = $false
        }
        max_scan_time = $maxScanTime
    } | ConvertTo-Json
    
    try {
        Write-Log "Starting scan for $targetUrl..." "INFO"
        
        # API call to start scan (adjust endpoint based on your Acunetix version)
        $scanUrl = "$AcunetixServer/api/v1/scans"
        $response = Invoke-RestMethod -Uri $scanUrl -Method Post -Headers $script:SessionHeaders -Body $scanConfig -ErrorAction Stop
        
        Write-Log "Scan started successfully!" "SUCCESS"
        Write-Log "Scan ID: $($response.scan_id)" "INFO"
        Write-Log "Target: $targetUrl" "INFO"
        Write-Log "Scan Type: $scanType" "INFO"
        
        # Save scan ID for later use
        $Global:LastScanId = $response.scan_id
        $Global:LastTarget = $targetUrl
        
    } catch {
        Write-Log "Failed to start scan: $_" "ERROR"
    }
    
    Pause
}

function Check-ScanStatus {
    <#
    .SYNOPSIS
    Checks the status of a scan
    #>
    
    if (-not $script:IsConnected) {
        Write-Log "Not connected to Acunetix server. Please connect first." "ERROR"
        Pause
        return
    }
    
    Clear-Host
    Write-Host "=== CHECK SCAN STATUS ===" -ForegroundColor Cyan
    Write-Host ""
    
    # Get scan ID or use last one
    if ($Global:LastScanId) {
        $defaultScanId = $Global:LastScanId
        $scanId = Read-Host "Enter scan ID (default: $defaultScanId)"
        if (-not $scanId) { $scanId = $defaultScanId }
    } else {
        $scanId = Read-Host "Enter scan ID"
    }
    
    if (-not $scanId) {
        Write-Log "Scan ID is required" "ERROR"
        Pause
        return
    }
    
    try {
        Write-Log "Checking status for scan ID: $scanId" "INFO"
        
        # API call to get scan status (adjust endpoint based on your Acunetix version)
        $statusUrl = "$AcunetixServer/api/v1/scans/$scanId"
        $response = Invoke-RestMethod -Uri $statusUrl -Method Get -Headers $script:SessionHeaders -ErrorAction Stop
        
        # Display scan information
        Write-Host "`nScan Information:" -ForegroundColor Yellow
        Write-Host "  Scan ID: $($response.scan_id)" -ForegroundColor White
        Write-Host "  Target: $($response.target.address)" -ForegroundColor White
        Write-Host "  Status: $($response.status)" -ForegroundColor Green
        Write-Host "  Progress: $($response.progress)%" -ForegroundColor Cyan
        
        if ($response.current_session) {
            Write-Host "  Started: $(Get-Date $response.current_session.start_date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
        }
        
        if ($response.complete_date) {
            Write-Host "  Completed: $(Get-Date $response.complete_date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
        }
        
        # Show vulnerabilities if available
        if ($response.vulnerabilities) {
            Write-Host "`nVulnerabilities Found:" -ForegroundColor Yellow
            $vulnCount = ($response.vulnerabilities | Measure-Object).Count
            Write-Host "  Total: $vulnCount" -ForegroundColor White
            
            # Group by severity
            $severityGroups = $response.vulnerabilities | Group-Object severity
            foreach ($group in $severityGroups) {
                Write-Host "  $($group.Name): $($group.Count)" -ForegroundColor White
            }
        }
        
    } catch {
        Write-Log "Failed to get scan status: $_" "ERROR"
    }
    
    Pause
}

function Generate-Report {
    <#
    .SYNOPSIS
    Generates a scan report
    #>
    
    if (-not $script:IsConnected) {
        Write-Log "Not connected to Acunetix server. Please connect first." "ERROR"
        Pause
        return
    }
    
    Clear-Host
    Write-Host "=== GENERATE REPORT ===" -ForegroundColor Cyan
    Write-Host ""
    
    # Get scan ID or use last one
    if ($Global:LastScanId) {
        $defaultScanId = $Global:LastScanId
        $scanId = Read-Host "Enter scan ID (default: $defaultScanId)"
        if (-not $scanId) { $scanId = $defaultScanId }
    } else {
        $scanId = Read-Host "Enter scan ID"
    }
    
    if (-not $scanId) {
        Write-Log "Scan ID is required" "ERROR"
        Pause
        return
    }
    
    # Select report format
    Write-Host "`nReport Formats:" -ForegroundColor Yellow
    Write-Host "  1. PDF" -ForegroundColor White
    Write-Host "  2. HTML" -ForegroundColor White
    Write-Host "  3. XML" -ForegroundColor White
    Write-Host ""
    
    $formatChoice = Read-Host "Select report format (1-3)"
    switch ($formatChoice) {
        "1" { $format = "pdf"; $extension = ".pdf" }
        "2" { $format = "html"; $extension = ".html" }
        "3" { $format = "xml"; $extension = ".xml" }
        default { $format = "pdf"; $extension = ".pdf" }
    }
    
    # Get report template (if needed)
    $template = Read-Host "Report template (default: Default)"
    if (-not $template) { $template = "Default" }
    
    # Generate filename
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $fileName = "acunetix_scan_${scanId}_${timestamp}${extension}"
    $fullPath = Join-Path $ReportPath $fileName
    
    try {
        Write-Log "Generating $format report for scan ID: $scanId..." "INFO"
        
        # API call to generate report (adjust endpoint based on your Acunetix version)
        $reportUrl = "$AcunetixServer/api/v1/reports"
        $reportConfig = @{
            template_id = $template
            source = @{
                list_type = "scans"
                id_list = @($scanId)
            }
            format = $format
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri $reportUrl -Method Post -Headers $script:SessionHeaders -Body $reportConfig -ErrorAction Stop
        
        # Download the report
        if ($response.report_id) {
            Write-Log "Report generated with ID: $($response.report_id)" "INFO"
            
            # Download the report file (adjust endpoint based on your Acunetix version)
            $downloadUrl = "$AcunetixServer/api/v1/reports/$($response.report_id)/download"
            $reportData = Invoke-RestMethod -Uri $downloadUrl -Method Get -Headers $script:SessionHeaders -ErrorAction Stop
            
            # Save to file
            $reportData | Out-File -FilePath $fullPath -Encoding UTF8
            Write-Log "Report saved to: $fullPath" "SUCCESS"
            
            # Show file information
            $fileInfo = Get-Item $fullPath
            Write-Host "`nFile Information:" -ForegroundColor Yellow
            Write-Host "  Path: $fullPath" -ForegroundColor White
            Write-Host "  Size: $([math]::Round($fileInfo.Length/1KB,2)) KB" -ForegroundColor White
            Write-Host "  Created: $(Get-Date $fileInfo.CreationTime -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
        }
        
    } catch {
        Write-Log "Failed to generate report: $_" "ERROR"
    }
    
    Pause
}

function List-ScanTypes {
    <#
    .SYNOPSIS
    Lists available scan types
    #>
    
    Clear-Host
    Write-Host "=== AVAILABLE SCAN TYPES ===" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Scan Type Configuration:" -ForegroundColor Yellow
    Write-Host "------------------------" -ForegroundColor Yellow
    
    foreach ($key in $script:ScanTypes.Keys | Sort-Object) {
        Write-Host "`n[$key] $($script:ScanTypes[$key].Name)" -ForegroundColor Green
        Write-Host "   Description: $($script:ScanTypes[$key].Description)" -ForegroundColor White
        Write-Host "   Recommended Use: " -ForegroundColor Gray -NoNewline
        
        switch ($key) {
            "1" { Write-Host "Comprehensive security assessments" -ForegroundColor White }
            "2" { Write-Host "Quick security checks" -ForegroundColor White }
            "3" { Write-Host "Web application XSS testing" -ForegroundColor White }
            "4" { Write-Host "Database security testing" -ForegroundColor White }
        }
    }
    
    Write-Host "`nAdditional Information:" -ForegroundColor Yellow
    Write-Host "------------------------" -ForegroundColor Yellow
    Write-Host "• Full Scan: Includes all vulnerability checks" -ForegroundColor Gray
    Write-Host "• High Risk: Focuses on critical vulnerabilities only" -ForegroundColor Gray
    Write-Host "• XSS Scan: Specialized for Cross-site Scripting" -ForegroundColor Gray
    Write-Host "• SQLi Scan: Specialized for SQL Injection" -ForegroundColor Gray
    
    Pause
}

# ============================================
# MAIN MENU
# ============================================

function Show-Menu {
    <#
    .SYNOPSIS
    Displays the main menu
    #>
    
    Clear-Host
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "     ACUNETIX AUTOMATION SCRIPT" -ForegroundColor Yellow
    Write-Host "           Version $ScriptVersion" -ForegroundColor Gray
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Show connection status
    if ($script:IsConnected) {
        Write-Host "  Status: " -NoNewline -ForegroundColor White
        Write-Host "CONNECTED" -ForegroundColor Green
        Write-Host "  Server: $AcunetixServer" -ForegroundColor Gray
    } else {
        Write-Host "  Status: " -NoNewline -ForegroundColor White
        Write-Host "DISCONNECTED" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "  Please select an option:" -ForegroundColor White
    Write-Host ""
    Write-Host "  1. Connect to Acunetix Server" -ForegroundColor Cyan
    Write-Host "  2. Start New Scan" -ForegroundColor Cyan
    Write-Host "  3. Check Scan Status" -ForegroundColor Cyan
    Write-Host "  4. Generate Report" -ForegroundColor Cyan
    Write-Host "  5. List Scan Types" -ForegroundColor Cyan
    Write-Host "  6. View Configuration" -ForegroundColor Cyan
    Write-Host "  7. Exit" -ForegroundColor Red
    Write-Host ""
    
    $choice = Read-Host "Enter choice (1-7)"
    return $choice
}

function Show-Configuration {
    <#
    .SYNOPSIS
    Displays current configuration
    #>
    
    Clear-Host
    Write-Host "=== CONFIGURATION ===" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Script Configuration:" -ForegroundColor Yellow
    Write-Host "---------------------" -ForegroundColor Yellow
    Write-Host "  Script Name: $ScriptName" -ForegroundColor White
    Write-Host "  Version: $ScriptVersion" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Connection Settings:" -ForegroundColor Yellow
    Write-Host "-------------------" -ForegroundColor Yellow
    Write-Host "  Acunetix Server: $AcunetixServer" -ForegroundColor White
    Write-Host "  Connected: " -NoNewline -ForegroundColor White
    if ($script:IsConnected) {
        Write-Host "Yes" -ForegroundColor Green
    } else {
        Write-Host "No" -ForegroundColor Red
    }
    Write-Host ""
    
    Write-Host "File Paths:" -ForegroundColor Yellow
    Write-Host "-----------" -ForegroundColor Yellow
    Write-Host "  Report Path: $ReportPath" -ForegroundColor White
    Write-Host "  Log Path: $LogPath" -ForegroundColor White
    Write-Host "  Current Log: $LogFile" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Recent Activity:" -ForegroundColor Yellow
    Write-Host "---------------" -ForegroundColor Yellow
    if ($Global:LastScanId) {
        Write-Host "  Last Scan ID: $Global:LastScanId" -ForegroundColor White
        Write-Host "  Last Target: $Global:LastTarget" -ForegroundColor White
    } else {
        Write-Host "  No recent scans" -ForegroundColor Gray
    }
    
    Pause
}

# ============================================
# MAIN EXECUTION
# ============================================

function Main {
    <#
    .SYNOPSIS
    Main execution function
    #>
    
    # Clear screen and show banner
    Clear-Host
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "     ACUNETIX AUTOMATION SCRIPT" -ForegroundColor Yellow
    Write-Host "           Version $ScriptVersion" -ForegroundColor Gray
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "Initializing..." -ForegroundColor White
    Write-Host ""
    
    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "Prerequisites check failed. Exiting." "ERROR"
        Pause
        exit 1
    }
    
    # Initialize logging
    Initialize-Logging
    
    Write-Log "Script initialized successfully" "SUCCESS"
    Write-Log "Report directory: $ReportPath" "INFO"
    Write-Log "Log directory: $LogPath" "INFO"
    
    Start-Sleep -Seconds 2
    
    # Main loop
    $running = $true
    while ($running) {
        $choice = Show-Menu
        
        switch ($choice) {
            "1" { Connect-AcunetixServer }
            "2" { Start-NewScan }
            "3" { Check-ScanStatus }
            "4" { Generate-Report }
            "5" { List-ScanTypes }
            "6" { Show-Configuration }
            "7" { 
                Write-Log "Exiting script" "INFO"
                $running = $false 
            }
            default {
                Write-Log "Invalid option selected: $choice" "WARNING"
                Pause
            }
        }
    }
    
    # Cleanup
    Write-Log "Script execution completed" "INFO"
    Stop-Transcript
    Write-Host "`nScript completed. Press any key to exit..." -ForegroundColor Green
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ============================================
# SCRIPT ENTRY POINT
# ============================================

# Check if script is being run directly
if ($MyInvocation.InvocationName -ne '.') {
    try {
        Main
    } catch {
        Write-Host "`nAn error occurred: $_" -ForegroundColor Red
        Write-Host "Check the log file for details: $LogPath" -ForegroundColor Yellow
        Pause
    }
} 
