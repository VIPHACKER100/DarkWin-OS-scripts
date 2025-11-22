# DarkWin System Forensics
# Author: viphacker.100
# Description: Performs system forensics and analysis

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$LogFile = "C:\Tools\Logs\forensics_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$EvidenceDir = "C:\Tools\Evidence\$(Get-Date -Format 'yyyyMMdd_HHmmss')"

function Write-Log {
    param($Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    Write-Host $LogMessage
}

function Initialize-Forensics {
    Write-Log "Initializing forensics investigation..."
    
    # Create evidence directory
    New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null
    
    # Create case information
    $CaseInfo = @{
        "case_number" = "CASE-$(Get-Date -Format 'yyyyMMddHHmmss')"
        "investigator" = "DarkWin Forensics"
        "start_time" = Get-Date
        "system_info" = Get-WmiObject Win32_ComputerSystem | Select-Object -Property *
        "os_info" = Get-WmiObject Win32_OperatingSystem | Select-Object -Property *
    }
    
    $CaseInfo | ConvertTo-Json | Out-File "$EvidenceDir\case_info.json"
    Write-Log "Forensics workspace created: $EvidenceDir"
}

function Get-SystemArtifacts {
    Write-Log "Collecting system artifacts..."
    
    # Collect system information
    systeminfo | Out-File "$EvidenceDir\system_info.txt"
    
    # Collect running processes
    Get-Process | Select-Object -Property * | Export-Csv "$EvidenceDir\running_processes.csv"
    
    # Collect services
    Get-Service | Select-Object -Property * | Export-Csv "$EvidenceDir\services.csv"
    
    # Collect network connections
    netstat -anob | Out-File "$EvidenceDir\network_connections.txt"
    
    # Collect scheduled tasks
    Get-ScheduledTask | Select-Object -Property * | Export-Csv "$EvidenceDir\scheduled_tasks.csv"
    
    # Collect installed software
    Get-WmiObject -Class Win32_Product | Select-Object -Property * | Export-Csv "$EvidenceDir\installed_software.csv"
    
    Write-Log "System artifacts collected"
}

function Get-FileSystemArtifacts {
    Write-Log "Collecting file system artifacts..."
    
    # Collect file system information
    Get-PSDrive -PSProvider FileSystem | Select-Object -Property * | Export-Csv "$EvidenceDir\filesystem_info.csv"
    
    # Collect recent files
    Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent" -Recurse | Select-Object -Property * | Export-Csv "$EvidenceDir\recent_files.csv"
    
    # Collect prefetch files
    Get-ChildItem "C:\Windows\Prefetch" -Recurse | Select-Object -Property * | Export-Csv "$EvidenceDir\prefetch_files.csv"
    
    # Collect event logs
    Get-EventLog -LogName * | Export-Csv "$EvidenceDir\event_logs.csv"
    
    # Collect registry hives
    $RegistryHives = @(
        "HKLM\SOFTWARE",
        "HKLM\SYSTEM",
        "HKLM\SAM",
        "HKLM\SECURITY",
        "HKCU\SOFTWARE"
    )
    
    foreach ($Hive in $RegistryHives) {
        $HiveName = $Hive.Split("\")[-1]
        reg export $Hive "$EvidenceDir\registry_$HiveName.reg" /y
    }
    
    Write-Log "File system artifacts collected"
}

function Get-MemoryArtifacts {
    Write-Log "Collecting memory artifacts..."
    
    # Create memory dump
    if (Test-Path "C:\Tools\Additional\WinPMem\winpmem.exe") {
        & "C:\Tools\Additional\WinPMem\winpmem.exe" "$EvidenceDir\memory.aff4"
    }
    
    # Analyze memory with Volatility
    if (Test-Path "C:\Tools\Additional\Volatility\volatility.exe") {
        $VolatilityArgs = @(
            "-f `"$EvidenceDir\memory.aff4`"",
            "imageinfo",
            "pslist",
            "pstree",
            "dlllist",
            "handles",
            "malfind",
            "svcscan",
            "netscan"
        )
        
        foreach ($Arg in $VolatilityArgs) {
            & "C:\Tools\Additional\Volatility\volatility.exe" $Arg | Out-File "$EvidenceDir\volatility_$($Arg.Split()[0]).txt"
        }
    }
    
    Write-Log "Memory artifacts collected"
}

function Get-NetworkArtifacts {
    Write-Log "Collecting network artifacts..."
    
    # Collect network configuration
    ipconfig /all | Out-File "$EvidenceDir\network_config.txt"
    
    # Collect ARP cache
    arp -a | Out-File "$EvidenceDir\arp_cache.txt"
    
    # Collect routing table
    route print | Out-File "$EvidenceDir\routing_table.txt"
    
    # Collect DNS cache
    ipconfig /displaydns | Out-File "$EvidenceDir\dns_cache.txt"
    
    # Collect network shares
    net share | Out-File "$EvidenceDir\network_shares.txt"
    
    Write-Log "Network artifacts collected"
}

function Get-SecurityArtifacts {
    Write-Log "Collecting security artifacts..."
    
    # Collect security policy
    secedit /export /cfg "$EvidenceDir\security_policy.inf"
    
    # Collect firewall rules
    netsh advfirewall show allprofiles | Out-File "$EvidenceDir\firewall_rules.txt"
    
    # Collect antivirus status
    Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct | Select-Object -Property * | Export-Csv "$EvidenceDir\antivirus_status.csv"
    
    # Collect Windows Defender status
    Get-MpComputerStatus | Select-Object -Property * | Export-Csv "$EvidenceDir\defender_status.csv"
    
    Write-Log "Security artifacts collected"
}

function Generate-ForensicsReport {
    param(
        [string]$EvidenceDir
    )
    Write-Log "Generating forensics report..."
    
    $ReportFile = "$EvidenceDir\report.html"
    $ReportContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>DarkWin Forensics Report</title>
    <style>
        body { font-family: 'Consolas', monospace; margin: 20px; background: #1a1a1a; color: #00ff00; }
        h1, h2, h3 { color: #00ff00; }
        .section { margin: 20px 0; padding: 10px; border: 1px solid #333; }
        .artifact { margin: 10px 0; padding: 5px; background: #2a2a2a; }
        .critical { color: #ff0000; }
        .warning { color: #ffff00; }
        .info { color: #00ff00; }
        pre { background: #2a2a2a; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>DarkWin Forensics Report</h1>
    <div class="section">
        <h2>Case Information</h2>
        <p>Date: $(Get-Date)</p>
        <p>Evidence Directory: $EvidenceDir</p>
    </div>
"@
    
    # Add artifacts
    $ReportContent += @"
    <div class="section">
        <h2>Collected Artifacts</h2>
"@
    
    # Add artifact files
    Get-ChildItem -Path $EvidenceDir -Recurse -File | ForEach-Object {
        $ReportContent += @"
        <div class="artifact">
            <h3>$($_.Name)</h3>
            <pre>$(Get-Content $_.FullName -Raw)</pre>
        </div>
"@
    }
    
    $ReportContent += @"
    </div>
</body>
</html>
"@
    
    $ReportContent | Out-File $ReportFile
    Write-Log "Report generated: $ReportFile"
}

# Main execution
try {
    Initialize-Forensics
    
    # Collect artifacts
    Get-SystemArtifacts
    Get-FileSystemArtifacts
    Get-MemoryArtifacts
    Get-NetworkArtifacts
    Get-SecurityArtifacts
    
    # Generate report
    Generate-ForensicsReport -EvidenceDir $EvidenceDir
    
    Write-Log "Forensics investigation completed successfully"
} catch {
    Write-Log "ERROR: Forensics investigation failed - $_"
    exit 1
} 