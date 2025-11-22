# Import required modules
Import-Module PSLogging
Import-Module security_logging

# Initialize logging
$logPath = "C:\SecurityTools\Logs\security_integration_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
Initialize-Logging -LogPath $logPath

# Configuration
$configPath = "C:\SecurityTools\Configs\security_integration_config.json"
$reportPath = "C:\SecurityTools\Reports\"

# Create necessary directories
if (-not (Test-Path $reportPath)) {
    New-Item -ItemType Directory -Path $reportPath -Force
    Write-Log -Message "Created reports directory at $reportPath" -Level Info
}

# Function to perform comprehensive security assessment
function Start-ComprehensiveAssessment {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Target,
        
        [Parameter(Mandatory=$false)]
        [string]$AssessmentType = "Full"
    )
    
    try {
        Write-Log -Message "Starting comprehensive security assessment for target: $Target" -Level Info
        
        # 1. Network Security Assessment
        Write-Log -Message "Starting network security assessment" -Level Info
        $nmapResults = Start-NmapScan -Target $Target -ScanType "Full"
        
        # 2. Web Application Security Assessment
        Write-Log -Message "Starting web application security assessment" -Level Info
        $acunetixResults = Start-AcunetixScan -TargetUrl $Target -ScanType "FullScan"
        
        # 3. Vulnerability Assessment
        Write-Log -Message "Starting vulnerability assessment" -Level Info
        $openvasResults = Start-FullScan -Target $Target
        
        # 4. System Security Assessment
        Write-Log -Message "Starting system security assessment" -Level Info
        $systemResults = Check-SystemSecurity
        
        # Generate comprehensive report
        $reportFile = New-ComprehensiveReport -Target $Target -NmapResults $nmapResults -AcunetixResults $acunetixResults -OpenvasResults $openvasResults -SystemResults $systemResults
        
        Write-Log -Message "Completed comprehensive security assessment" -Level Info
        return $reportFile
    }
    catch {
        Write-Log -Message "Failed to complete comprehensive assessment: $_" -Level Error
        return $null
    }
}

# Function to generate comprehensive report
function New-ComprehensiveReport {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Target,
        
        [Parameter(Mandatory=$true)]
        [object]$NmapResults,
        
        [Parameter(Mandatory=$true)]
        [object]$AcunetixResults,
        
        [Parameter(Mandatory=$true)]
        [object]$OpenvasResults,
        
        [Parameter(Mandatory=$true)]
        [object]$SystemResults
    )
    
    try {
        $reportFile = "$reportPath\comprehensive_assessment_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"
        
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Comprehensive Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #2c3e50; }
        .section { margin: 20px 0; padding: 10px; border: 1px solid #ddd; }
        .critical { color: #e74c3c; }
        .high { color: #e67e22; }
        .medium { color: #f1c40f; }
        .low { color: #2ecc71; }
    </style>
</head>
<body>
    <h1>Comprehensive Security Assessment Report</h1>
    <p>Target: $Target</p>
    <p>Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    
    <div class="section">
        <h2>Network Security Assessment</h2>
        <pre>$($NmapResults | ConvertTo-Html)</pre>
    </div>
    
    <div class="section">
        <h2>Web Application Security Assessment</h2>
        <pre>$($AcunetixResults | ConvertTo-Html)</pre>
    </div>
    
    <div class="section">
        <h2>Vulnerability Assessment</h2>
        <pre>$($OpenvasResults | ConvertTo-Html)</pre>
    </div>
    
    <div class="section">
        <h2>System Security Assessment</h2>
        <pre>$($SystemResults | ConvertTo-Html)</pre>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
            <li>Implement recommended security patches</li>
            <li>Configure firewall rules based on assessment</li>
            <li>Address identified vulnerabilities</li>
            <li>Enhance system security settings</li>
        </ul>
    </div>
</body>
</html>
"@
        
        $html | Out-File -FilePath $reportFile -Encoding UTF8
        Write-Log -Message "Generated comprehensive report at $reportFile" -Level Info
        return $reportFile
    }
    catch {
        Write-Log -Message "Failed to generate comprehensive report: $_" -Level Error
        return $null
    }
}

# Function to monitor security tools
function Start-SecurityMonitoring {
    param (
        [Parameter(Mandatory=$false)]
        [int]$Interval = 300
    )
    
    try {
        Write-Log -Message "Starting security tools monitoring" -Level Info
        
        while ($true) {
            # Check Nmap status
            $nmapStatus = Get-NmapStatus
            Write-Log -Message "Nmap status: $nmapStatus" -Level Info
            
            # Check Acunetix status
            $acunetixStatus = Get-AcunetixStatus
            Write-Log -Message "Acunetix status: $acunetixStatus" -Level Info
            
            # Check OpenVAS status
            $openvasStatus = Get-OpenVASStatus
            Write-Log -Message "OpenVAS status: $openvasStatus" -Level Info
            
            # Check system security status
            $systemStatus = Get-SystemSecurityStatus
            Write-Log -Message "System security status: $systemStatus" -Level Info
            
            Start-Sleep -Seconds $Interval
        }
    }
    catch {
        Write-Log -Message "Failed to monitor security tools: $_" -Level Error
    }
}

# Function to synchronize security tools
function Sync-SecurityTools {
    param (
        [Parameter(Mandatory=$false)]
        [string]$SyncType = "Full"
    )
    
    try {
        Write-Log -Message "Starting security tools synchronization" -Level Info
        
        # Synchronize configurations
        if ($SyncType -eq "Full") {
            # Sync Nmap configurations
            Sync-NmapConfig
            
            # Sync Acunetix configurations
            Sync-AcunetixConfig
            
            # Sync OpenVAS configurations
            Sync-OpenVASConfig
            
            # Sync system security settings
            Sync-SystemSecurity
        }
        
        Write-Log -Message "Completed security tools synchronization" -Level Info
    }
    catch {
        Write-Log -Message "Failed to synchronize security tools: $_" -Level Error
    }
}

# Main menu function
function Show-Menu {
    Write-Host "`nSecurity Integration Menu"
    Write-Host "1. Start Comprehensive Assessment"
    Write-Host "2. Monitor Security Tools"
    Write-Host "3. Synchronize Security Tools"
    Write-Host "4. Generate Report"
    Write-Host "5. Exit"
    
    $choice = Read-Host "`nEnter your choice (1-5)"
    
    switch ($choice) {
        "1" {
            $target = Read-Host "Enter target"
            $assessmentType = Read-Host "Enter assessment type (default: Full)"
            Start-ComprehensiveAssessment -Target $target -AssessmentType $assessmentType
        }
        "2" {
            $interval = Read-Host "Enter monitoring interval in seconds (default: 300)"
            Start-SecurityMonitoring -Interval $interval
        }
        "3" {
            $syncType = Read-Host "Enter sync type (default: Full)"
            Sync-SecurityTools -SyncType $syncType
        }
        "4" {
            $target = Read-Host "Enter target"
            $nmapResults = Get-NmapResults -Target $target
            $acunetixResults = Get-AcunetixResults -Target $target
            $openvasResults = Get-OpenVASResults -Target $target
            $systemResults = Get-SystemResults -Target $target
            New-ComprehensiveReport -Target $target -NmapResults $nmapResults -AcunetixResults $acunetixResults -OpenvasResults $openvasResults -SystemResults $systemResults
        }
        "5" {
            Write-Log -Message "Exiting security integration script" -Level Info
            exit
        }
        default {
            Write-Host "Invalid choice. Please try again."
        }
    }
    
    Show-Menu
}

# Start the menu
Show-Menu 