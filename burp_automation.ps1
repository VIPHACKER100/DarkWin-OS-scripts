<#
.SYNOPSIS
    Burp Suite Professional Automation Script for DarkWin OS
.DESCRIPTION
    Advanced automation script for Burp Suite Professional with comprehensive
    scanning, reporting, and integration capabilities optimized for DarkWin OS
.NOTES
    Version: 2.0
    Author: DarkWin Security Team
    Last Updated: 2026-01-28
    Requirements:
        - Windows 10/11 or DarkWin OS
        - PowerShell 7.0 or later
        - Burp Suite Professional
        - Administrative privileges
#>

#Requires -Version 7.0
#Requires -RunAsAdministrator

# ============================================================================
# CONFIGURATION
# ============================================================================

$Script:Config = @{
    BurpSuitePath = "C:\Program Files\Burp Suite Professional\burpsuite_pro.jar"
    JavaPath = "C:\Program Files\Java\jdk-17\bin\java.exe"
    ConfigFile = "C:\SecurityTools\Configs\burp_config.json"
    ProjectsDir = "C:\SecurityTools\Projects\burp"
    ReportsDir = "C:\SecurityTools\Reports\burp"
    LogsDir = "C:\SecurityTools\Logs\burp"
    TemplatesDir = "C:\SecurityTools\Templates\burp"
    ScriptsDir = "C:\SecurityTools\Scripts\burp"
    BackupsDir = "C:\SecurityTools\Backups\burp"
    MaxConcurrentScans = 5
    ScanTimeout = 7200
    RetryAttempts = 3
    RetryDelay = 5
}

# ============================================================================
# INITIALIZATION
# ============================================================================

# Import required modules
try {
    Import-Module PSLogging -ErrorAction Stop
} catch {
    Write-Warning "PSLogging module not found. Installing..."
    Install-Module PSLogging -Force -Scope CurrentUser
    Import-Module PSLogging
}

# Create required directories
foreach ($dir in $Script:Config.Values | Where-Object { $_ -match '^C:\\' -and $_ -match 'Dir$' }) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Initialize logging
$Script:LogFile = Join-Path $Script:Config.LogsDir "burp_automation_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
Start-Log -LogPath $Script:LogFile -LogLevel Debug

Write-Log -Message "=== Burp Suite Automation Script Started ===" -Level Info
Write-Log -Message "Version: 2.0 | DarkWin OS Optimized" -Level Info

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validates all prerequisites are met
    #>
    Write-Log -Message "Checking prerequisites..." -Level Info
    
    $issues = @()
    
    # Check Java
    if (-not (Test-Path $Script:Config.JavaPath)) {
        $issues += "Java not found at: $($Script:Config.JavaPath)"
    }
    
    # Check Burp Suite
    if (-not (Test-Path $Script:Config.BurpSuitePath)) {
        $issues += "Burp Suite not found at: $($Script:Config.BurpSuitePath)"
    }
    
    # Check config file
    if (-not (Test-Path $Script:Config.ConfigFile)) {
        $issues += "Configuration file not found at: $($Script:Config.ConfigFile)"
    }
    
    if ($issues.Count -gt 0) {
        Write-Log -Message "Prerequisites check failed:" -Level Error
        foreach ($issue in $issues) {
            Write-Log -Message "  - $issue" -Level Error
            Write-Host "  [ERROR] $issue" -ForegroundColor Red
        }
        return $false
    }
    
    Write-Log -Message "Prerequisites check passed" -Level Info
    return $true
}

function New-BurpProjectFile {
    <#
    .SYNOPSIS
        Creates a new Burp Suite project file path
    #>
    param (
        [string]$Type
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $filename = "burp_${Type}_${timestamp}.burp"
    return Join-Path $Script:Config.ProjectsDir $filename
}

function New-BurpReportFile {
    <#
    .SYNOPSIS
        Creates a new report file path
    #>
    param (
        [string]$Type,
        [string]$Format = "html"
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $filename = "burp_${Type}_${timestamp}.${Format}"
    return Join-Path $Script:Config.ReportsDir $filename
}

function Send-Notification {
    <#
    .SYNOPSIS
        Sends notification about scan completion or errors
    #>
    param (
        [string]$Title,
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Type = "Info"
    )
    
    Write-Log -Message "Notification: $Title - $Message" -Level $Type
    
    # Display toast notification on DarkWin OS
    $toastXml = @"
<toast>
    <visual>
        <binding template="ToastGeneric">
            <text>$Title</text>
            <text>$Message</text>
        </binding>
    </visual>
</toast>
"@
    
    try {
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
        
        $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xml.LoadXml($toastXml)
        
        $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Burp Suite Automation").Show($toast)
    } catch {
        Write-Log -Message "Could not send toast notification: $_" -Level Warning
    }
}

# ============================================================================
# BURP SUITE MANAGEMENT FUNCTIONS
# ============================================================================

function Start-BurpSuite {
    <#
    .SYNOPSIS
        Starts Burp Suite with custom configuration
    #>
    param (
        [string]$ConfigFile = $Script:Config.ConfigFile,
        [switch]$Headless,
        [string]$ProjectFile
    )
    
    Write-Log -Message "Starting Burp Suite..." -Level Info
    Write-Host "`n[*] Starting Burp Suite Professional..." -ForegroundColor Cyan
    
    $arguments = @(
        "-jar", $Script:Config.BurpSuitePath,
        "--config-file=$ConfigFile"
    )
    
    if ($Headless) {
        $arguments += "--headless"
        Write-Log -Message "Running in headless mode" -Level Info
    }
    
    if ($ProjectFile) {
        $arguments += "--project-file=$ProjectFile"
        Write-Log -Message "Using project file: $ProjectFile" -Level Info
    }
    
    try {
        $process = Start-Process -FilePath $Script:Config.JavaPath `
                                -ArgumentList $arguments `
                                -PassThru `
                                -NoNewWindow:$Headless
        
        Write-Log -Message "Burp Suite started successfully (PID: $($process.Id))" -Level Info
        Write-Host "[+] Burp Suite started successfully (PID: $($process.Id))" -ForegroundColor Green
        
        return $process
    } catch {
        Write-Log -Message "Failed to start Burp Suite: $_" -Level Error
        Write-Host "[-] Failed to start Burp Suite: $_" -ForegroundColor Red
        return $null
    }
}

function Stop-BurpSuite {
    <#
    .SYNOPSIS
        Stops running Burp Suite instances
    #>
    param (
        [switch]$Force
    )
    
    Write-Log -Message "Stopping Burp Suite instances..." -Level Info
    
    $processes = Get-Process | Where-Object { $_.MainWindowTitle -like "*Burp Suite*" }
    
    if ($processes) {
        foreach ($process in $processes) {
            try {
                if ($Force) {
                    $process | Stop-Process -Force
                } else {
                    $process | Stop-Process
                }
                Write-Log -Message "Stopped Burp Suite process (PID: $($process.Id))" -Level Info
            } catch {
                Write-Log -Message "Failed to stop process $($process.Id): $_" -Level Error
            }
        }
    } else {
        Write-Log -Message "No running Burp Suite instances found" -Level Info
    }
}

# ============================================================================
# SCANNING FUNCTIONS
# ============================================================================

function Start-PassiveScan {
    <#
    .SYNOPSIS
        Performs passive security scanning
    #>
    param (
        [Parameter(Mandatory)]
        [string]$Target,
        
        [string]$Scope,
        
        [int]$Duration = 300
    )
    
    Write-Log -Message "Starting passive scan of: $Target" -Level Info
    Write-Host "`n[*] Starting passive scan..." -ForegroundColor Cyan
    Write-Host "    Target: $Target" -ForegroundColor White
    Write-Host "    Duration: $Duration seconds" -ForegroundColor White
    
    $projectFile = New-BurpProjectFile -Type "passive"
    $reportFile = New-BurpReportFile -Type "passive"
    
    $scanConfig = @{
        target_url = $Target
        scan_type = "passive"
        scope = if ($Scope) { $Scope } else { $Target }
        duration = $Duration
    } | ConvertTo-Json
    
    $scanConfigFile = Join-Path $Script:Config.ProjectsDir "scan_config_temp.json"
    $scanConfig | Out-File -FilePath $scanConfigFile -Encoding UTF8
    
    try {
        $arguments = @(
            "-jar", $Script:Config.BurpSuitePath,
            "--headless",
            "--project-file=$projectFile",
            "--config-file=$($Script:Config.ConfigFile)",
            "--scan-config-file=$scanConfigFile"
        )
        
        $process = Start-Process -FilePath $Script:Config.JavaPath `
                                -ArgumentList $arguments `
                                -PassThru `
                                -NoNewWindow `
                                -RedirectStandardOutput (Join-Path $Script:Config.LogsDir "passive_scan_output.log") `
                                -RedirectStandardError (Join-Path $Script:Config.LogsDir "passive_scan_error.log")
        
        # Wait for scan to complete
        $timeout = [datetime]::Now.AddSeconds($Duration + 60)
        while (-not $process.HasExited -and [datetime]::Now -lt $timeout) {
            Start-Sleep -Seconds 5
            Write-Host "." -NoNewline -ForegroundColor Yellow
        }
        
        if (-not $process.HasExited) {
            $process | Stop-Process -Force
            Write-Log -Message "Scan timed out and was terminated" -Level Warning
        }
        
        Write-Host "`n[+] Passive scan completed" -ForegroundColor Green
        Write-Log -Message "Passive scan completed. Project: $projectFile" -Level Info
        
        # Generate report
        $report = New-BurpReport -ProjectFile $projectFile -OutputFile $reportFile
        
        Send-Notification -Title "Passive Scan Complete" -Message "Target: $Target" -Type Success
        
        return @{
            ProjectFile = $projectFile
            ReportFile = $report
            Success = $true
        }
    } catch {
        Write-Log -Message "Passive scan failed: $_" -Level Error
        Write-Host "[-] Passive scan failed: $_" -ForegroundColor Red
        
        Send-Notification -Title "Passive Scan Failed" -Message $_.Exception.Message -Type Error
        
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    } finally {
        if (Test-Path $scanConfigFile) {
            Remove-Item $scanConfigFile -Force
        }
    }
}

function Start-ActiveScan {
    <#
    .SYNOPSIS
        Performs active security scanning with vulnerability testing
    #>
    param (
        [Parameter(Mandatory)]
        [string]$Target,
        
        [string]$Scope,
        
        [ValidateSet("Light", "Normal", "Thorough")]
        [string]$Intensity = "Normal",
        
        [int]$MaxDuration = 3600
    )
    
    Write-Log -Message "Starting active scan of: $Target (Intensity: $Intensity)" -Level Info
    Write-Host "`n[*] Starting active scan..." -ForegroundColor Cyan
    Write-Host "    Target: $Target" -ForegroundColor White
    Write-Host "    Intensity: $Intensity" -ForegroundColor White
    Write-Host "    Max Duration: $MaxDuration seconds" -ForegroundColor White
    Write-Host "`n[!] WARNING: Active scanning may impact the target system" -ForegroundColor Yellow
    
    $confirm = Read-Host "Continue? (y/N)"
    if ($confirm -ne 'y') {
        Write-Host "[*] Scan cancelled by user" -ForegroundColor Yellow
        return @{ Success = $false; Cancelled = $true }
    }
    
    $projectFile = New-BurpProjectFile -Type "active"
    $reportFile = New-BurpReportFile -Type "active"
    
    $scanConfig = @{
        target_url = $Target
        scan_type = "active"
        intensity = $Intensity.ToLower()
        scope = if ($Scope) { $Scope } else { $Target }
        max_duration = $MaxDuration
    } | ConvertTo-Json
    
    $scanConfigFile = Join-Path $Script:Config.ProjectsDir "scan_config_temp.json"
    $scanConfig | Out-File -FilePath $scanConfigFile -Encoding UTF8
    
    try {
        $arguments = @(
            "-jar", $Script:Config.BurpSuitePath,
            "--headless",
            "--project-file=$projectFile",
            "--config-file=$($Script:Config.ConfigFile)",
            "--scan-config-file=$scanConfigFile",
            "--unpause-spider-and-scanner"
        )
        
        $process = Start-Process -FilePath $Script:Config.JavaPath `
                                -ArgumentList $arguments `
                                -PassThru `
                                -NoNewWindow `
                                -RedirectStandardOutput (Join-Path $Script:Config.LogsDir "active_scan_output.log") `
                                -RedirectStandardError (Join-Path $Script:Config.LogsDir "active_scan_error.log")
        
        # Monitor scan progress
        $startTime = Get-Date
        $lastUpdate = $startTime
        
        while (-not $process.HasExited) {
            $elapsed = (Get-Date) - $startTime
            
            if ($elapsed.TotalSeconds -ge $MaxDuration) {
                $process | Stop-Process -Force
                Write-Log -Message "Scan reached max duration and was terminated" -Level Warning
                break
            }
            
            # Update progress every 30 seconds
            if (((Get-Date) - $lastUpdate).TotalSeconds -ge 30) {
                $progress = [math]::Round(($elapsed.TotalSeconds / $MaxDuration) * 100, 1)
                Write-Host "`r[*] Scan progress: $progress% ($(Format-TimeSpan $elapsed) elapsed)" -NoNewline -ForegroundColor Cyan
                $lastUpdate = Get-Date
            }
            
            Start-Sleep -Seconds 5
        }
        
        Write-Host "`n[+] Active scan completed" -ForegroundColor Green
        Write-Log -Message "Active scan completed. Project: $projectFile" -Level Info
        
        # Generate comprehensive report
        $report = New-BurpReport -ProjectFile $projectFile -OutputFile $reportFile -Detailed
        
        # Analyze results
        $analysis = Get-ScanResults -ProjectFile $projectFile
        
        Write-Host "`n[*] Scan Results Summary:" -ForegroundColor Cyan
        Write-Host "    High Severity: $($analysis.High)" -ForegroundColor Red
        Write-Host "    Medium Severity: $($analysis.Medium)" -ForegroundColor Yellow
        Write-Host "    Low Severity: $($analysis.Low)" -ForegroundColor White
        Write-Host "    Informational: $($analysis.Info)" -ForegroundColor Gray
        
        Send-Notification -Title "Active Scan Complete" -Message "Found $($analysis.High) high severity issues" -Type $(if ($analysis.High -gt 0) { "Warning" } else { "Success" })
        
        return @{
            ProjectFile = $projectFile
            ReportFile = $report
            Analysis = $analysis
            Success = $true
        }
    } catch {
        Write-Log -Message "Active scan failed: $_" -Level Error
        Write-Host "[-] Active scan failed: $_" -ForegroundColor Red
        
        Send-Notification -Title "Active Scan Failed" -Message $_.Exception.Message -Type Error
        
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    } finally {
        if (Test-Path $scanConfigFile) {
            Remove-Item $scanConfigFile -Force
        }
    }
}

function Start-Crawl {
    <#
    .SYNOPSIS
        Performs web application crawling and site mapping
    #>
    param (
        [Parameter(Mandatory)]
        [string]$Target,
        
        [int]$MaxDepth = 10,
        
        [int]$MaxLinks = 1000,
        
        [int]$MaxDuration = 1800
    )
    
    Write-Log -Message "Starting crawl of: $Target" -Level Info
    Write-Host "`n[*] Starting web crawl..." -ForegroundColor Cyan
    Write-Host "    Target: $Target" -ForegroundColor White
    Write-Host "    Max Depth: $MaxDepth" -ForegroundColor White
    Write-Host "    Max Links: $MaxLinks" -ForegroundColor White
    
    $projectFile = New-BurpProjectFile -Type "crawl"
    $reportFile = New-BurpReportFile -Type "crawl"
    
    $crawlConfig = @{
        target_url = $Target
        max_depth = $MaxDepth
        max_links = $MaxLinks
        max_duration = $MaxDuration
        crawl_forms = $true
        crawl_hidden = $true
        follow_redirects = $true
    } | ConvertTo-Json
    
    $crawlConfigFile = Join-Path $Script:Config.ProjectsDir "crawl_config_temp.json"
    $crawlConfig | Out-File -FilePath $crawlConfigFile -Encoding UTF8
    
    try {
        $arguments = @(
            "-jar", $Script:Config.BurpSuitePath,
            "--headless",
            "--project-file=$projectFile",
            "--config-file=$($Script:Config.ConfigFile)",
            "--crawl-config-file=$crawlConfigFile"
        )
        
        $process = Start-Process -FilePath $Script:Config.JavaPath `
                                -ArgumentList $arguments `
                                -PassThru `
                                -NoNewWindow `
                                -RedirectStandardOutput (Join-Path $Script:Config.LogsDir "crawl_output.log") `
                                -RedirectStandardError (Join-Path $Script:Config.LogsDir "crawl_error.log")
        
        # Monitor crawl progress
        $timeout = [datetime]::Now.AddSeconds($MaxDuration + 60)
        while (-not $process.HasExited -and [datetime]::Now -lt $timeout) {
            Start-Sleep -Seconds 10
            Write-Host "." -NoNewline -ForegroundColor Yellow
        }
        
        if (-not $process.HasExited) {
            $process | Stop-Process -Force
            Write-Log -Message "Crawl timed out and was terminated" -Level Warning
        }
        
        Write-Host "`n[+] Crawl completed" -ForegroundColor Green
        Write-Log -Message "Crawl completed. Project: $projectFile" -Level Info
        
        # Generate site map report
        $report = New-BurpReport -ProjectFile $projectFile -OutputFile $reportFile -IncludeSiteMap
        
        Send-Notification -Title "Crawl Complete" -Message "Target: $Target" -Type Success
        
        return @{
            ProjectFile = $projectFile
            ReportFile = $report
            Success = $true
        }
    } catch {
        Write-Log -Message "Crawl failed: $_" -Level Error
        Write-Host "[-] Crawl failed: $_" -ForegroundColor Red
        
        Send-Notification -Title "Crawl Failed" -Message $_.Exception.Message -Type Error
        
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    } finally {
        if (Test-Path $crawlConfigFile) {
            Remove-Item $crawlConfigFile -Force
        }
    }
}

# ============================================================================
# REPORTING FUNCTIONS
# ============================================================================

function New-BurpReport {
    <#
    .SYNOPSIS
        Generates reports from Burp Suite project files
    #>
    param (
        [Parameter(Mandatory)]
        [string]$ProjectFile,
        
        [string]$OutputFile,
        
        [ValidateSet("HTML", "XML", "JSON")]
        [string]$Format = "HTML",
        
        [switch]$Detailed,
        
        [switch]$IncludeSiteMap,
        
        [switch]$IncludeEvidence
    )
    
    if (-not (Test-Path $ProjectFile)) {
        Write-Log -Message "Project file not found: $ProjectFile" -Level Error
        throw "Project file not found: $ProjectFile"
    }
    
    if (-not $OutputFile) {
        $OutputFile = New-BurpReportFile -Type "report" -Format $Format.ToLower()
    }
    
    Write-Log -Message "Generating $Format report from: $ProjectFile" -Level Info
    Write-Host "`n[*] Generating report..." -ForegroundColor Cyan
    
    try {
        $reportOptions = @{
            format = $Format.ToLower()
            include_http_messages = $IncludeEvidence.IsPresent
            include_site_map = $IncludeSiteMap.IsPresent
            detailed = $Detailed.IsPresent
        } | ConvertTo-Json
        
        $reportOptionsFile = Join-Path $Script:Config.ProjectsDir "report_options_temp.json"
        $reportOptions | Out-File -FilePath $reportOptionsFile -Encoding UTF8
        
        $arguments = @(
            "-jar", $Script:Config.BurpSuitePath,
            "--headless",
            "--project-file=$ProjectFile",
            "--generate-report=$OutputFile",
            "--report-options-file=$reportOptionsFile"
        )
        
        $process = Start-Process -FilePath $Script:Config.JavaPath `
                                -ArgumentList $arguments `
                                -PassThru `
                                -Wait `
                                -NoNewWindow `
                                -RedirectStandardOutput (Join-Path $Script:Config.LogsDir "report_generation_output.log") `
                                -RedirectStandardError (Join-Path $Script:Config.LogsDir "report_generation_error.log")
        
        if (Test-Path $OutputFile) {
            Write-Host "[+] Report generated: $OutputFile" -ForegroundColor Green
            Write-Log -Message "Report generated successfully: $OutputFile" -Level Info
            
            # Open report in default browser
            Start-Process $OutputFile
            
            return $OutputFile
        } else {
            throw "Report file was not created"
        }
    } catch {
        Write-Log -Message "Report generation failed: $_" -Level Error
        Write-Host "[-] Report generation failed: $_" -ForegroundColor Red
        throw
    } finally {
        if (Test-Path $reportOptionsFile) {
            Remove-Item $reportOptionsFile -Force
        }
    }
}

function Get-ScanResults {
    <#
    .SYNOPSIS
        Analyzes scan results from project file
    #>
    param (
        [Parameter(Mandatory)]
        [string]$ProjectFile
    )
    
    # This is a placeholder for actual implementation
    # In practice, you would parse the project file or use Burp's API
    
    return @{
        High = 0
        Medium = 0
        Low = 0
        Info = 0
        Total = 0
    }
}

# ============================================================================
# PROXY CONFIGURATION
# ============================================================================

function Set-BurpProxy {
    <#
    .SYNOPSIS
        Configures Burp Suite proxy settings
    #>
    param (
        [string]$Interface = "127.0.0.1",
        
        [int]$Port = 8080,
        
        [switch]$EnableSSL,
        
        [string]$CertificatePath
    )
    
    Write-Log -Message "Configuring Burp Suite proxy on ${Interface}:${Port}" -Level Info
    Write-Host "`n[*] Configuring proxy..." -ForegroundColor Cyan
    
    try {
        $config = Get-Content $Script:Config.ConfigFile | ConvertFrom-Json
        
        # Update proxy settings
        if (-not $config.proxy) {
            $config | Add-Member -MemberType NoteProperty -Name "proxy" -Value @{}
        }
        
        $config.proxy.listen_address = $Interface
        $config.proxy.listen_port = $Port
        
        if ($EnableSSL) {
            $config.proxy.ssl_enabled = $true
            if ($CertificatePath) {
                $config.proxy.ssl_certificate = $CertificatePath
            }
        }
        
        # Save configuration
        $config | ConvertTo-Json -Depth 10 | Set-Content $Script:Config.ConfigFile -Encoding UTF8
        
        Write-Host "[+] Proxy configured: ${Interface}:${Port}" -ForegroundColor Green
        Write-Log -Message "Proxy configured successfully" -Level Info
        
        # Update system proxy settings
        Write-Host "[*] Update system proxy settings? (y/N)" -ForegroundColor Yellow
        $update = Read-Host
        
        if ($update -eq 'y') {
            netsh winhttp set proxy "${Interface}:${Port}"
            Write-Host "[+] System proxy updated" -ForegroundColor Green
        }
        
        return $true
    } catch {
        Write-Log -Message "Proxy configuration failed: $_" -Level Error
        Write-Host "[-] Proxy configuration failed: $_" -ForegroundColor Red
        return $false
    }
}

function Reset-SystemProxy {
    <#
    .SYNOPSIS
        Resets system proxy settings
    #>
    Write-Host "[*] Resetting system proxy..." -ForegroundColor Cyan
    netsh winhttp reset proxy
    Write-Host "[+] System proxy reset" -ForegroundColor Green
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Format-TimeSpan {
    param ([TimeSpan]$TimeSpan)
    
    if ($TimeSpan.TotalHours -ge 1) {
        return "{0:hh\:mm\:ss}" -f $TimeSpan
    } else {
        return "{0:mm\:ss}" -f $TimeSpan
    }
}

function Show-Banner {
    $banner = @"

╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ ██╗   ██╗██████╗ ██████╗                         ║
║   ██╔══██╗██║   ██║██╔══██╗██╔══██╗                        ║
║   ██████╔╝██║   ██║██████╔╝██████╔╝                        ║
║   ██╔══██╗██║   ██║██╔══██╗██╔═══╝                         ║
║   ██████╔╝╚██████╔╝██║  ██║██║                             ║
║   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝                             ║
║                                                              ║
║   Burp Suite Professional Automation v2.0                    ║
║   Optimized for DarkWin OS                                   ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Cyan
}

# ============================================================================
# MAIN MENU
# ============================================================================

function Show-Menu {
    Write-Host "`n╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           Burp Suite Automation Menu                    ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Start Burp Suite (GUI)" -ForegroundColor White
    Write-Host "  [2] Start Passive Scan" -ForegroundColor White
    Write-Host "  [3] Start Active Scan" -ForegroundColor White
    Write-Host "  [4] Start Web Crawl" -ForegroundColor White
    Write-Host "  [5] Generate Report from Project" -ForegroundColor White
    Write-Host "  [6] Configure Proxy Settings" -ForegroundColor White
    Write-Host "  [7] Reset System Proxy" -ForegroundColor White
    Write-Host "  [8] View Recent Scans" -ForegroundColor White
    Write-Host "  [9] Stop All Burp Instances" -ForegroundColor White
    Write-Host "  [0] Exit" -ForegroundColor White
    Write-Host ""
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    try {
        Show-Banner
        
        # Check prerequisites
        if (-not (Test-Prerequisites)) {
            Write-Host "`n[!] Prerequisites check failed. Please resolve issues and try again." -ForegroundColor Red
            exit 1
        }
        
        Write-Host "[+] All prerequisites met. Ready to start." -ForegroundColor Green
        
        do {
            Show-Menu
            $choice = Read-Host "Select an option"
            
            switch ($choice) {
                "1" {
                    Start-BurpSuite
                }
                "2" {
                    $target = Read-Host "Enter target URL"
                    $duration = Read-Host "Enter scan duration in seconds (default: 300)"
                    if (-not $duration) { $duration = 300 }
                    Start-PassiveScan -Target $target -Duration ([int]$duration)
                }
                "3" {
                    $target = Read-Host "Enter target URL"
                    $intensity = Read-Host "Enter scan intensity (Light/Normal/Thorough, default: Normal)"
                    if (-not $intensity) { $intensity = "Normal" }
                    Start-ActiveScan -Target $target -Intensity $intensity
                }
                "4" {
                    $target = Read-Host "Enter target URL"
                    $maxDepth = Read-Host "Enter max crawl depth (default: 10)"
                    if (-not $maxDepth) { $maxDepth = 10 }
                    Start-Crawl -Target $target -MaxDepth ([int]$maxDepth)
                }
                "5" {
                    $projectFile = Read-Host "Enter project file path"
                    $format = Read-Host "Enter report format (HTML/XML/JSON, default: HTML)"
                    if (-not $format) { $format = "HTML" }
                    New-BurpReport -ProjectFile $projectFile -Format $format -Detailed
                }
                "6" {
                    $interface = Read-Host "Enter interface (default: 127.0.0.1)"
                    $port = Read-Host "Enter port (default: 8080)"
                    if (-not $interface) { $interface = "127.0.0.1" }
                    if (-not $port) { $port = 8080 }
                    Set-BurpProxy -Interface $interface -Port ([int]$port)
                }
                "7" {
                    Reset-SystemProxy
                }
                "8" {
                    Write-Host "`n[*] Recent scan projects:" -ForegroundColor Cyan
                    Get-ChildItem $Script:Config.ProjectsDir -Filter "*.burp" | 
                        Sort-Object LastWriteTime -Descending | 
                        Select-Object -First 10 | 
                        ForEach-Object {
                            Write-Host "  - $($_.Name) ($(Get-Date $_.LastWriteTime -Format 'yyyy-MM-dd HH:mm'))" -ForegroundColor White
                        }
                }
                "9" {
                    Stop-BurpSuite -Force
                }
                "0" {
                    Write-Log -Message "Exiting Burp Suite automation" -Level Info
                    Write-Host "`n[*] Exiting... Goodbye!" -ForegroundColor Yellow
                    Stop-Log
                    exit 0
                }
                default {
                    Write-Host "[-] Invalid option. Please try again." -ForegroundColor Red
                }
            }
            
            if ($choice -ne "0") {
                Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        } while ($true)
        
    } catch {
        Write-Log -Message "Fatal error: $_" -Level Error
        Write-Host "`n[-] Fatal error: $_" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor Red
        Stop-Log
        exit 1
    }
}

# Start the script
Main
