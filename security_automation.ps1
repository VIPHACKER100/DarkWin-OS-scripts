# Security Automation Script

# Import required modules
Import-Module ActiveDirectory
Import-Module NetSecurity
Import-Module Defender
Import-Module SecurityPolicy
Import-Module PSLogging

# Initialize logging
$logPath = "C:\SecurityTools\Logs\security_automation_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
Start-Log -LogPath $logPath -LogLevel Info

# Function to check system security status
function Check-SystemSecurity {
    Write-Log -Message "Starting system security check" -Level Info
    Write-Host "Checking system security status..." -ForegroundColor Green
    
    # Check Windows Defender status
    $defenderStatus = Get-MpComputerStatus
    Write-Log -Message "Checking Windows Defender status" -Level Info
    Write-Host "Windows Defender Status:" -ForegroundColor Yellow
    Write-Host "  Antivirus Enabled: $($defenderStatus.AntivirusEnabled)"
    Write-Host "  Real-time Protection: $($defenderStatus.RealTimeProtectionEnabled)"
    Write-Host "  Antispyware Enabled: $($defenderStatus.AntispywareEnabled)"
    Write-Host "  Tamper Protection: $($defenderStatus.TamperProtectionEnabled)"
    Write-Host "  Cloud Protection: $($defenderStatus.CloudProtectionEnabled)"
    
    # Check firewall status
    $firewallStatus = Get-NetFirewallProfile
    Write-Log -Message "Checking firewall status" -Level Info
    Write-Host "`nFirewall Status:" -ForegroundColor Yellow
    $firewallStatus | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Enabled)"
        Write-Host "  Default Inbound Action: $($_.DefaultInboundAction)"
        Write-Host "  Default Outbound Action: $($_.DefaultOutboundAction)"
    }
    
    # Check Windows Update status
    $updateStatus = Get-WindowsUpdateStatus
    Write-Log -Message "Checking Windows Update status" -Level Info
    Write-Host "`nWindows Update Status:" -ForegroundColor Yellow
    Write-Host "  Last Check: $($updateStatus.LastCheckTime)"
    Write-Host "  Updates Available: $($updateStatus.UpdatesAvailable)"
    
    # Check BitLocker status
    $bitlockerStatus = Get-BitLockerVolume
    Write-Log -Message "Checking BitLocker status" -Level Info
    Write-Host "`nBitLocker Status:" -ForegroundColor Yellow
    $bitlockerStatus | ForEach-Object {
        Write-Host "  Drive: $($_.MountPoint)"
        Write-Host "  Protection Status: $($_.VolumeStatus)"
        Write-Host "  Encryption Percentage: $($_.EncryptionPercentage)%"
    }
    
    # Check UAC settings
    $uacSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
    Write-Log -Message "Checking UAC settings" -Level Info
    Write-Host "`nUAC Status:" -ForegroundColor Yellow
    Write-Host "  UAC Enabled: $($uacSettings.EnableLUA -eq 1)"
    
    # Check Windows Services
    Write-Log -Message "Checking critical services" -Level Info
    Write-Host "`nCritical Services Status:" -ForegroundColor Yellow
    $criticalServices = @("WinDefend", "BFE", "mpssvc", "wscsvc")
    foreach ($service in $criticalServices) {
        $status = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($status) {
            Write-Host "  $service : $($status.Status)"
        }
    }
    
    # Check installed security software
    Write-Log -Message "Checking installed security software" -Level Info
    Write-Host "`nInstalled Security Software:" -ForegroundColor Yellow
    $securitySoftware = @(
        "Windows Defender",
        "Windows Firewall",
        "Windows Security",
        "Windows Update"
    )
    foreach ($software in $securitySoftware) {
        $installed = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*$software*" }
        Write-Host "  $software : $(if ($installed) { 'Installed' } else { 'Not Installed' })"
    }
    
    # Check system security settings
    Write-Log -Message "Checking system security settings" -Level Info
    Write-Host "`nSystem Security Settings:" -ForegroundColor Yellow
    
    # Check registry security settings
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Security",
        "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    )
    
    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            $settings = Get-ItemProperty -Path $path
            Write-Host "  Registry Path: $path"
            $settings.PSObject.Properties | ForEach-Object {
                if ($_.Name -notlike "PS*") {
                    Write-Host "    $($_.Name): $($_.Value)"
                }
            }
        }
    }
    
    # Check network security
    Write-Log -Message "Checking network security" -Level Info
    Write-Host "`nNetwork Security:" -ForegroundColor Yellow
    
    # Check open ports
    $openPorts = Get-NetTCPConnection -State Listen
    Write-Host "  Open Ports:"
    $openPorts | Group-Object LocalPort | ForEach-Object {
        Write-Host "    Port $($_.Name): $($_.Count) connections"
    }
    
    # Check network adapters
    $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    Write-Host "  Active Network Adapters:"
    $networkAdapters | ForEach-Object {
        Write-Host "    $($_.Name): $($_.InterfaceDescription)"
    }
    
    # Check DNS settings
    $dnsSettings = Get-DnsClientServerAddress
    Write-Host "  DNS Settings:"
    $dnsSettings | ForEach-Object {
        Write-Host "    $($_.InterfaceAlias): $($_.ServerAddresses)"
    }
    
    # Check system integrity
    Write-Log -Message "Checking system integrity" -Level Info
    Write-Host "`nSystem Integrity:" -ForegroundColor Yellow
    
    # Run SFC scan
    Write-Host "  Running System File Checker..."
    $sfcResult = sfc /verifyonly
    Write-Host "    $sfcResult"
    
    # Check Windows features
    $windowsFeatures = Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq "Enabled" }
    Write-Host "  Enabled Windows Features:"
    $windowsFeatures | ForEach-Object {
        Write-Host "    $($_.DisplayName)"
    }
    
    Write-Log -Message "System security check completed" -Level Info
}

# Function to perform security scan
function Start-SecurityScan {
    param (
        [string]$Target,
        [string]$ScanType = "full"
    )
    
    Write-Log -Message "Starting security scan of $Target" -Level Info
    Write-Host "Starting security scan of $Target..." -ForegroundColor Green
    
    # Create scan directory
    $scanDir = "C:\SecurityTools\Scans\$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
    New-Item -ItemType Directory -Path $scanDir -Force | Out-Null
    Write-Log -Message "Created scan directory: $scanDir" -Level Info
    
    # Run Nmap scan
    Write-Log -Message "Starting Nmap scan" -Level Info
    Write-Host "Running Nmap scan..." -ForegroundColor Yellow
    $nmapOutput = "$scanDir\nmap_scan.xml"
    if ($ScanType -eq "quick") {
        nmap -sV -sC -T4 -oX $nmapOutput $Target
    } else {
        nmap -sV -sC -p- -T4 -oX $nmapOutput $Target
    }
    Write-Log -Message "Nmap scan completed" -Level Info
    
    # Run vulnerability scan
    Write-Log -Message "Starting Burp Suite scan" -Level Info
    Write-Host "Running vulnerability scan..." -ForegroundColor Yellow
    $vulnOutput = "$scanDir\vuln_scan.html"
    Start-Process "C:\Program Files\Burp Suite\burpsuite.exe" -ArgumentList "--config-file=C:\SecurityTools\Configs\burp.conf --project-file=$scanDir\burp_project.burp --unpause-spider-and-scanner"
    
    # Run Metasploit auxiliary scan
    Write-Log -Message "Starting Metasploit scan" -Level Info
    Write-Host "Running Metasploit auxiliary scan..." -ForegroundColor Yellow
    $msfOutput = "$scanDir\msf_scan.txt"
    Start-Process "msfconsole" -ArgumentList "-r C:\SecurityTools\Scripts\msf\scan.rc -o $msfOutput"
    
    # Run additional security scans
    Write-Log -Message "Starting additional security scans" -Level Info
    
    # Run Windows Defender scan
    Write-Host "Running Windows Defender scan..." -ForegroundColor Yellow
    Start-MpScan -ScanType QuickScan
    
    # Run Windows Update scan
    Write-Host "Running Windows Update scan..." -ForegroundColor Yellow
    Get-WindowsUpdate
    
    # Generate report
    Write-Log -Message "Generating scan report" -Level Info
    Write-Host "Generating scan report..." -ForegroundColor Yellow
    $reportPath = "$scanDir\security_report.html"
    New-SecurityReport -OutputPath $reportPath
    
    Write-Log -Message "Security scan completed" -Level Info
    Write-Host "Scan complete. Results saved to $scanDir" -ForegroundColor Green
}

# Function to monitor system security
function Start-SecurityMonitoring {
    Write-Log -Message "Starting security monitoring" -Level Info
    Write-Host "Starting security monitoring..." -ForegroundColor Green
    
    # Monitor Windows Event Logs
    $eventLogs = @("Security", "System", "Application")
    foreach ($log in $eventLogs) {
        Get-WinEvent -LogName $log -MaxEvents 10 | Where-Object { $_.Level -eq 2 -or $_.Level -eq 1 } | ForEach-Object {
            Write-Log -Message "Critical event in $log: $($_.Message)" -Level Warning
            Write-Host "Critical Event in $log:" -ForegroundColor Red
            Write-Host "  Time: $($_.TimeCreated)"
            Write-Host "  ID: $($_.Id)"
            Write-Host "  Message: $($_.Message)"
            Write-Host ""
        }
    }
    
    # Monitor network connections
    Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } | ForEach-Object {
        Write-Log -Message "Active connection: $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort)" -Level Info
        Write-Host "Active Connection:" -ForegroundColor Yellow
        Write-Host "  Local: $($_.LocalAddress):$($_.LocalPort)"
        Write-Host "  Remote: $($_.RemoteAddress):$($_.RemotePort)"
        Write-Host "  State: $($_.State)"
        Write-Host "  Process: $((Get-Process -Id $_.OwningProcess).ProcessName)"
        Write-Host ""
    }
    
    # Monitor file system changes
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = "C:\Windows\System32"
    $watcher.Filter = "*.*"
    $watcher.EnableRaisingEvents = $true
    
    Register-ObjectEvent $watcher "Created" -Action {
        Write-Log -Message "File created: $($Event.SourceEventArgs.FullPath)" -Level Warning
        Write-Host "File Created: $($Event.SourceEventArgs.FullPath)" -ForegroundColor Red
    }
    
    Register-ObjectEvent $watcher "Changed" -Action {
        Write-Log -Message "File changed: $($Event.SourceEventArgs.FullPath)" -Level Warning
        Write-Host "File Changed: $($Event.SourceEventArgs.FullPath)" -ForegroundColor Red
    }
    
    # Monitor process creation
    $processWatcher = New-Object System.Diagnostics.ProcessStartInfo
    $processWatcher.FileName = "powershell.exe"
    $processWatcher.Arguments = "-Command Get-Process | Where-Object { `$_.StartTime -gt (Get-Date).AddMinutes(-1) }"
    $processWatcher.UseShellExecute = $false
    $processWatcher.RedirectStandardOutput = $true
    
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processWatcher
    $process.Start() | Out-Null
    
    $output = $process.StandardOutput.ReadToEnd()
    $process.WaitForExit()
    
    if ($output) {
        Write-Log -Message "New processes detected: $output" -Level Warning
        Write-Host "New Processes:" -ForegroundColor Yellow
        Write-Host $output
    }
    
    Write-Log -Message "Security monitoring started" -Level Info
}

# Function to perform security hardening
function Start-SecurityHardening {
    Write-Log -Message "Starting security hardening" -Level Info
    Write-Host "Starting security hardening..." -ForegroundColor Green
    
    # Disable unnecessary services
    $servicesToDisable = @(
        "RemoteRegistry",
        "PrintSpooler",
        "Fax",
        "XblAuthManager",
        "XblGameSave",
        "XboxNetApiSvc",
        "WSearch",
        "W32Time",
        "TabletInputService",
        "SysMain",
        "RemoteAccess",
        "RemoteRegistry",
        "RpcLocator",
        "RpcSs",
        "RpcSs",
        "RpcSs",
        "RpcSs",
        "RpcSs",
        "RpcSs",
        "RpcSs"
    )
    
    foreach ($service in $servicesToDisable) {
        Set-Service -Name $service -StartupType Disabled
        Write-Log -Message "Disabled service: $service" -Level Info
        Write-Host "Disabled service: $service" -ForegroundColor Yellow
    }
    
    # Configure Windows Defender
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -DisableIOAVProtection $false
    Set-MpPreference -DisableBehaviorMonitoring $false
    Set-MpPreference -DisableBlockAtFirstSeen $false
    Set-MpPreference -DisablePrivacyMode $false
    Set-MpPreference -DisableIntrusionPreventionSystem $false
    Set-MpPreference -DisableScriptScanning $false
    Set-MpPreference -DisableRemovableDriveScanning $false
    Set-MpPreference -DisableEmailScanning $false
    Write-Log -Message "Configured Windows Defender settings" -Level Info
    
    # Configure firewall rules
    New-NetFirewallRule -DisplayName "Block Outbound Telnet" -Direction Outbound -Protocol TCP -RemotePort 23 -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound FTP" -Direction Outbound -Protocol TCP -RemotePort 21 -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound SMB" -Direction Outbound -Protocol TCP -RemotePort 445 -Action Block
    New-NetFirewallRule -DisplayName "Block Outbound RDP" -Direction Outbound -Protocol TCP -RemotePort 3389 -Action Block
    Write-Log -Message "Configured firewall rules" -Level Info
    
    # Configure UAC
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
    Write-Log -Message "Configured UAC settings" -Level Info
    
    # Configure password policy
    net accounts /minpwlen:12
    net accounts /maxpwage:90
    net accounts /minpwage:1
    net accounts /lockoutthreshold:5
    net accounts /lockoutduration:30
    net accounts /lockoutwindow:30
    Write-Log -Message "Configured password policy" -Level Info
    
    # Enable BitLocker if not enabled
    $bitlockerStatus = Get-BitLockerVolume
    if ($bitlockerStatus.VolumeStatus -ne "FullyEncrypted") {
        Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly
        Write-Log -Message "Enabled BitLocker encryption" -Level Info
    }
    
    # Configure additional security settings
    Write-Log -Message "Configuring additional security settings" -Level Info
    
    # Disable AutoRun
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 0xFF
    
    # Disable Remote Desktop
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
    
    # Disable Remote Assistance
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0
    
    # Disable Windows Script Host
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0
    
    # Disable Windows Script Host
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0
    
    # Disable Windows Script Host
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0
    
    Write-Log -Message "Security hardening completed" -Level Info
    Write-Host "Security hardening complete" -ForegroundColor Green
}

# Function to perform security audit
function Start-SecurityAudit {
    Write-Log -Message "Starting security audit" -Level Info
    Write-Host "Starting security audit..." -ForegroundColor Green
    
    # Check user accounts
    Get-LocalUser | ForEach-Object {
        Write-Log -Message "Checking user account: $($_.Name)" -Level Info
        Write-Host "User Account:" -ForegroundColor Yellow
        Write-Host "  Name: $($_.Name)"
        Write-Host "  Enabled: $($_.Enabled)"
        Write-Host "  Password Required: $($_.PasswordRequired)"
        Write-Host "  Password Never Expires: $($_.PasswordNeverExpires)"
        Write-Host "  Last Logon: $($_.LastLogon)"
        Write-Host ""
    }
    
    # Check installed software
    Get-WmiObject -Class Win32_Product | Select-Object Name, Version | ForEach-Object {
        Write-Log -Message "Checking installed software: $($_.Name)" -Level Info
        Write-Host "Installed Software:" -ForegroundColor Yellow
        Write-Host "  Name: $($_.Name)"
        Write-Host "  Version: $($_.Version)"
        Write-Host ""
    }
    
    # Check system configuration
    $systemInfo = Get-WmiObject -Class Win32_OperatingSystem
    Write-Log -Message "Checking system configuration" -Level Info
    Write-Host "System Information:" -ForegroundColor Yellow
    Write-Host "  OS: $($systemInfo.Caption)"
    Write-Host "  Version: $($systemInfo.Version)"
    Write-Host "  Last Boot: $($systemInfo.ConvertToDateTime($systemInfo.LastBootUpTime))"
    Write-Host "  System Drive: $($systemInfo.SystemDrive)"
    Write-Host "  System Directory: $($systemInfo.SystemDirectory)"
    Write-Host ""
    
    # Check network configuration
    $networkConfig = Get-NetIPConfiguration
    Write-Log -Message "Checking network configuration" -Level Info
    Write-Host "Network Configuration:" -ForegroundColor Yellow
    $networkConfig | ForEach-Object {
        Write-Host "  Interface: $($_.InterfaceAlias)"
        Write-Host "  IP Address: $($_.IPv4Address.IPAddress)"
        Write-Host "  Gateway: $($_.IPv4DefaultGateway.NextHop)"
        Write-Host "  DNS: $($_.DNSServer.ServerAddresses)"
        Write-Host ""
    }
    
    # Check security policies
    $securityPolicies = Get-SecurityPolicy
    Write-Log -Message "Checking security policies" -Level Info
    Write-Host "Security Policies:" -ForegroundColor Yellow
    Write-Host "  Password Policy:"
    Write-Host "    Minimum Length: $($securityPolicies.MinimumPasswordLength)"
    Write-Host "    Maximum Age: $($securityPolicies.MaximumPasswordAge)"
    Write-Host "    Minimum Age: $($securityPolicies.MinimumPasswordAge)"
    Write-Host "  Account Lockout:"
    Write-Host "    Threshold: $($securityPolicies.LockoutThreshold)"
    Write-Host "    Duration: $($securityPolicies.LockoutDuration)"
    Write-Host "    Window: $($securityPolicies.LockoutWindow)"
    Write-Host ""
    
    Write-Log -Message "Security audit completed" -Level Info
}

# Function to generate security report
function New-SecurityReport {
    param (
        [string]$OutputPath = "C:\SecurityTools\Reports\security_report_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"
    )
    
    Write-Log -Message "Generating security report" -Level Info
    
    $report = @"
<!DOCTYPE html>
<html>
<head>
    <title>Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        h2 { color: #34495e; margin-top: 20px; }
        .section { margin: 20px 0; padding: 10px; border: 1px solid #ddd; }
        .warning { color: #e74c3c; }
        .success { color: #27ae60; }
    </style>
</head>
<body>
    <h1>Security Report</h1>
    <div class="section">
        <h2>System Security Status</h2>
        $(Get-SystemSecurityStatus)
    </div>
    <div class="section">
        <h2>Security Audit Results</h2>
        $(Get-SecurityAuditResults)
    </div>
    <div class="section">
        <h2>Recommendations</h2>
        $(Get-SecurityRecommendations)
    </div>
</body>
</html>
"@
    
    $report | Out-File -FilePath $OutputPath
    Write-Log -Message "Security report generated at: $OutputPath" -Level Info
    Write-Host "Security report generated at: $OutputPath" -ForegroundColor Green
}

# Main menu
function Show-Menu {
    Write-Host "`nSecurity Automation Menu" -ForegroundColor Cyan
    Write-Host "1. Check System Security"
    Write-Host "2. Start Security Scan"
    Write-Host "3. Start Security Monitoring"
    Write-Host "4. Start Security Hardening"
    Write-Host "5. Start Security Audit"
    Write-Host "6. Generate Security Report"
    Write-Host "7. Exit"
    
    $choice = Read-Host "`nEnter your choice (1-7)"
    
    switch ($choice) {
        "1" { Check-SystemSecurity }
        "2" { 
            $target = Read-Host "Enter target IP or hostname"
            $scanType = Read-Host "Enter scan type (quick/full) [default: full]"
            if (-not $scanType) { $scanType = "full" }
            Start-SecurityScan -Target $target -ScanType $scanType
        }
        "3" { Start-SecurityMonitoring }
        "4" { Start-SecurityHardening }
        "5" { Start-SecurityAudit }
        "6" { New-SecurityReport }
        "7" { exit }
        default { Write-Host "Invalid choice" -ForegroundColor Red }
    }
}

# Run the menu
while ($true) {
    Show-Menu
    Read-Host "`nPress Enter to continue"
} 