# DarkWin Network Monitoring
# Author: viphacker.100
# Description: Monitors and analyzes network traffic

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$LogFile = "C:\Tools\Logs\network_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$CaptureDir = "C:\Tools\Captures\$(Get-Date -Format 'yyyyMMdd_HHmmss')"

function Write-Log {
    param($Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    Write-Host $LogMessage
}

function Start-NetworkCapture {
    param(
        [string]$Interface,
        [string]$Filter,
        [string]$OutputFile
    )
    Write-Log "Starting network capture on interface $Interface..."
    
    # Create capture directory
    New-Item -ItemType Directory -Path $CaptureDir -Force | Out-Null
    
    # Start Wireshark capture
    $WiresharkArgs = "-i $Interface -k -w `"$OutputFile.pcap`""
    if ($Filter) {
        $WiresharkArgs += " -f `"$Filter`""
    }
    Start-Process "C:\Program Files\Wireshark\Wireshark.exe" -ArgumentList $WiresharkArgs
    
    # Start tcpdump capture
    $TcpdumpArgs = "-i $Interface -w `"$OutputFile.tcpdump`""
    if ($Filter) {
        $TcpdumpArgs += " `"$Filter`""
    }
    Start-Process "C:\Tools\Additional\tcpdump\tcpdump.exe" -ArgumentList $TcpdumpArgs
    
    Write-Log "Network capture started"
}

function Start-NetworkAnalysis {
    param(
        [string]$CaptureFile
    )
    Write-Log "Starting network analysis..."
    
    # Analyze with tshark
    $TsharkArgs = @(
        "-r `"$CaptureFile`"",
        "-q",
        "-z io,phs",
        "-z io,stat",
        "-z expert"
    )
    & "C:\Program Files\Wireshark\tshark.exe" $TsharkArgs | Out-File "$CaptureFile.analysis.txt"
    
    # Generate statistics
    $StatsArgs = @(
        "-r `"$CaptureFile`"",
        "-q",
        "-z io,stat,1",
        "-z io,stat,1,tcp",
        "-z io,stat,1,udp",
        "-z io,stat,1,ip"
    )
    & "C:\Program Files\Wireshark\tshark.exe" $StatsArgs | Out-File "$CaptureFile.stats.txt"
    
    Write-Log "Network analysis completed"
}

function Start-IDS {
    param(
        [string]$Interface
    )
    Write-Log "Starting Intrusion Detection System..."
    
    # Start Snort
    if (Test-Path "C:\Tools\Additional\Snort\bin\snort.exe") {
        $SnortArgs = @(
            "-i $Interface",
            "-c `"C:\Tools\Additional\Snort\etc\snort.conf`"",
            "-A console",
            "-q"
        )
        Start-Process "C:\Tools\Additional\Snort\bin\snort.exe" -ArgumentList $SnortArgs
    }
    
    # Start Suricata
    if (Test-Path "C:\Tools\Additional\Suricata\bin\suricata.exe") {
        $SuricataArgs = @(
            "-i $Interface",
            "-c `"C:\Tools\Additional\Suricata\etc\suricata.yaml`""
        )
        Start-Process "C:\Tools\Additional\Suricata\bin\suricata.exe" -ArgumentList $SuricataArgs
    }
    
    Write-Log "IDS started"
}

function Start-NetworkScan {
    param(
        [string]$Target
    )
    Write-Log "Starting network scan..."
    
    # Nmap scan
    $NmapArgs = "-sV -sC -O --script vuln -oA `"$CaptureDir\nmap`" $Target"
    nmap $NmapArgs
    
    # Masscan
    if (Test-Path "C:\Tools\Additional\masscan\masscan.exe") {
        $MasscanArgs = "--rate=1000 -p1-65535 -oJ `"$CaptureDir\masscan.json`" $Target"
        & "C:\Tools\Additional\masscan\masscan.exe" $MasscanArgs
    }
    
    Write-Log "Network scan completed"
}

function Start-TrafficAnalysis {
    param(
        [string]$CaptureFile
    )
    Write-Log "Starting traffic analysis..."
    
    # Analyze with Bro/Zeek
    if (Test-Path "C:\Tools\Additional\Zeek\bin\zeek.exe") {
        $ZeekArgs = @(
            "-r `"$CaptureFile`"",
            "-C",
            "-b `"$CaptureDir\zeek`""
        )
        & "C:\Tools\Additional\Zeek\bin\zeek.exe" $ZeekArgs
    }
    
    # Analyze with NetworkMiner
    if (Test-Path "C:\Tools\Additional\NetworkMiner\NetworkMiner.exe") {
        Start-Process "C:\Tools\Additional\NetworkMiner\NetworkMiner.exe" -ArgumentList "`"$CaptureFile`""
    }
    
    Write-Log "Traffic analysis completed"
}

function Generate-NetworkReport {
    param(
        [string]$CaptureDir
    )
    Write-Log "Generating network analysis report..."
    
    $ReportFile = "$CaptureDir\report.html"
    $ReportContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>DarkWin Network Analysis Report</title>
    <style>
        body { font-family: 'Consolas', monospace; margin: 20px; background: #1a1a1a; color: #00ff00; }
        h1, h2, h3 { color: #00ff00; }
        .section { margin: 20px 0; padding: 10px; border: 1px solid #333; }
        .alert { margin: 10px 0; padding: 5px; background: #2a2a2a; }
        .critical { color: #ff0000; }
        .warning { color: #ffff00; }
        .info { color: #00ff00; }
        pre { background: #2a2a2a; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>DarkWin Network Analysis Report</h1>
    <div class="section">
        <h2>Capture Information</h2>
        <p>Date: $(Get-Date)</p>
        <p>Capture Directory: $CaptureDir</p>
    </div>
"@
    
    # Add analysis results
    $ReportContent += @"
    <div class="section">
        <h2>Analysis Results</h2>
"@
    
    # Add analysis files
    Get-ChildItem -Path $CaptureDir -Filter "*.txt" | ForEach-Object {
        $ReportContent += @"
        <div class="alert">
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
    param(
        [Parameter(Mandatory=$true)]
        [string]$Interface,
        
        [Parameter(Mandatory=$false)]
        [string]$Filter,
        
        [Parameter(Mandatory=$false)]
        [string]$Target
    )
    
    # Start network monitoring
    Start-NetworkCapture -Interface $Interface -Filter $Filter -OutputFile "$CaptureDir\capture"
    
    # Start IDS
    Start-IDS -Interface $Interface
    
    # If target specified, run network scan
    if ($Target) {
        Start-NetworkScan -Target $Target
    }
    
    # Wait for capture
    Write-Host "Press Enter to stop capture and generate report..."
    Read-Host
    
    # Stop capture and analyze
    Start-NetworkAnalysis -CaptureFile "$CaptureDir\capture.pcap"
    Start-TrafficAnalysis -CaptureFile "$CaptureDir\capture.pcap"
    
    # Generate report
    Generate-NetworkReport -CaptureDir $CaptureDir
    
    Write-Log "Network monitoring completed successfully"
} catch {
    Write-Log "ERROR: Network monitoring failed - $_"
    exit 1
} 