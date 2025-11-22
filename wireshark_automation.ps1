# Wireshark Automation Script

# Import required modules
Import-Module PSLogging

# Initialize logging
$logPath = "C:\SecurityTools\Logs\wireshark_automation_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
Start-Log -LogPath $logPath -LogLevel Info

# Function to start packet capture
function Start-PacketCapture {
    param (
        [string]$Interface,
        [string]$Filter = "",
        [string]$OutputFile = "C:\SecurityTools\Captures\capture_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').pcapng",
        [int]$Duration = 0
    )
    
    Write-Log -Message "Starting packet capture on interface $Interface" -Level Info
    Write-Host "Starting packet capture..." -ForegroundColor Green
    
    # Create capture directory if it doesn't exist
    $captureDir = Split-Path -Parent $OutputFile
    if (-not (Test-Path $captureDir)) {
        New-Item -ItemType Directory -Path $captureDir -Force | Out-Null
        Write-Log -Message "Created capture directory: $captureDir" -Level Info
    }
    
    # Build Wireshark command
    $wiresharkPath = "C:\Program Files\Wireshark\tshark.exe"
    $command = "& '$wiresharkPath' -i $Interface"
    
    if ($Filter) {
        $command += " -f `"$Filter`""
        Write-Log -Message "Applied capture filter: $Filter" -Level Info
    }
    
    $command += " -w `"$OutputFile`""
    
    if ($Duration -gt 0) {
        $command += " -a duration:$Duration"
        Write-Log -Message "Set capture duration: $Duration seconds" -Level Info
    }
    
    # Start capture
    Write-Log -Message "Executing Wireshark command: $command" -Level Info
    Invoke-Expression $command
    
    Write-Log -Message "Packet capture completed" -Level Info
    Write-Host "Capture saved to: $OutputFile" -ForegroundColor Green
}

# Function to analyze capture file
function Analyze-CaptureFile {
    param (
        [string]$CaptureFile,
        [string]$AnalysisType = "basic"
    )
    
    Write-Log -Message "Starting capture analysis: $CaptureFile" -Level Info
    Write-Host "Analyzing capture file..." -ForegroundColor Green
    
    $wiresharkPath = "C:\Program Files\Wireshark\tshark.exe"
    $analysisDir = "C:\SecurityTools\Analysis\$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
    New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    
    # Basic analysis
    if ($AnalysisType -eq "basic") {
        Write-Log -Message "Performing basic analysis" -Level Info
        
        # Protocol distribution
        $protocolStats = "& '$wiresharkPath' -r `"$CaptureFile`" -q -z io,phs"
        $protocolOutput = "$analysisDir\protocol_stats.txt"
        Invoke-Expression $protocolStats | Out-File -FilePath $protocolOutput
        
        # Top talkers
        $talkerStats = "& '$wiresharkPath' -r `"$CaptureFile`" -q -z endpoints,ip"
        $talkerOutput = "$analysisDir\top_talkers.txt"
        Invoke-Expression $talkerStats | Out-File -FilePath $talkerOutput
        
        # HTTP statistics
        $httpStats = "& '$wiresharkPath' -r `"$CaptureFile`" -q -z http,stat"
        $httpOutput = "$analysisDir\http_stats.txt"
        Invoke-Expression $httpStats | Out-File -FilePath $httpOutput
    }
    
    # Security analysis
    if ($AnalysisType -eq "security") {
        Write-Log -Message "Performing security analysis" -Level Info
        
        # Suspicious traffic patterns
        $suspiciousPatterns = @(
            "tcp.flags.syn==1 and tcp.flags.ack==0",
            "tcp.flags.rst==1",
            "tcp.window_size==0",
            "tcp.analysis.retransmission",
            "tcp.analysis.duplicate_ack",
            "tcp.analysis.lost_segment"
        )
        
        foreach ($pattern in $suspiciousPatterns) {
            $patternName = $pattern -replace "[^a-zA-Z0-9]", "_"
            $patternOutput = "$analysisDir\suspicious_$patternName.txt"
            $patternCmd = "& '$wiresharkPath' -r `"$CaptureFile`" -Y `"$pattern`""
            Invoke-Expression $patternCmd | Out-File -FilePath $patternOutput
        }
        
        # DNS analysis
        $dnsStats = "& '$wiresharkPath' -r `"$CaptureFile`" -q -z dns,stat"
        $dnsOutput = "$analysisDir\dns_stats.txt"
        Invoke-Expression $dnsStats | Out-File -FilePath $dnsOutput
        
        # SSL/TLS analysis
        $sslStats = "& '$wiresharkPath' -r `"$CaptureFile`" -q -z ssl,stat"
        $sslOutput = "$analysisDir\ssl_stats.txt"
        Invoke-Expression $sslStats | Out-File -FilePath $sslOutput
    }
    
    # Performance analysis
    if ($AnalysisType -eq "performance") {
        Write-Log -Message "Performing performance analysis" -Level Info
        
        # IO graphs
        $ioGraphs = "& '$wiresharkPath' -r `"$CaptureFile`" -q -z io,stat"
        $ioOutput = "$analysisDir\io_stats.txt"
        Invoke-Expression $ioGraphs | Out-File -FilePath $ioOutput
        
        # Expert information
        $expertInfo = "& '$wiresharkPath' -r `"$CaptureFile`" -q -z expert"
        $expertOutput = "$analysisDir\expert_info.txt"
        Invoke-Expression $expertInfo | Out-File -FilePath $expertOutput
        
        # Round-trip time
        $rttStats = "& '$wiresharkPath' -r `"$CaptureFile`" -q -z rtt,graph"
        $rttOutput = "$analysisDir\rtt_stats.txt"
        Invoke-Expression $rttStats | Out-File -FilePath $rttOutput
    }
    
    Write-Log -Message "Capture analysis completed" -Level Info
    Write-Host "Analysis results saved to: $analysisDir" -ForegroundColor Green
}

# Function to generate capture report
function New-CaptureReport {
    param (
        [string]$CaptureFile,
        [string]$AnalysisDir
    )
    
    Write-Log -Message "Generating capture report" -Level Info
    Write-Host "Generating capture report..." -ForegroundColor Green
    
    $reportPath = "$AnalysisDir\capture_report.html"
    
    $report = @"
<!DOCTYPE html>
<html>
<head>
    <title>Wireshark Capture Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        h2 { color: #34495e; margin-top: 20px; }
        .section { margin: 20px 0; padding: 10px; border: 1px solid #ddd; }
        .warning { color: #e74c3c; }
        .success { color: #27ae60; }
        pre { background-color: #f8f9fa; padding: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Wireshark Capture Report</h1>
    <div class="section">
        <h2>Capture Information</h2>
        <p>File: $CaptureFile</p>
        <p>Analysis Date: $(Get-Date)</p>
    </div>
    <div class="section">
        <h2>Protocol Statistics</h2>
        <pre>$(Get-Content "$AnalysisDir\protocol_stats.txt" -Raw)</pre>
    </div>
    <div class="section">
        <h2>Top Talkers</h2>
        <pre>$(Get-Content "$AnalysisDir\top_talkers.txt" -Raw)</pre>
    </div>
    <div class="section">
        <h2>HTTP Statistics</h2>
        <pre>$(Get-Content "$AnalysisDir\http_stats.txt" -Raw)</pre>
    </div>
    <div class="section">
        <h2>Security Analysis</h2>
        <h3>Suspicious Traffic</h3>
        <pre>$(Get-Content "$AnalysisDir\suspicious_tcp_flags_syn_1_and_tcp_flags_ack_0.txt" -Raw)</pre>
        <h3>DNS Statistics</h3>
        <pre>$(Get-Content "$AnalysisDir\dns_stats.txt" -Raw)</pre>
        <h3>SSL/TLS Statistics</h3>
        <pre>$(Get-Content "$AnalysisDir\ssl_stats.txt" -Raw)</pre>
    </div>
    <div class="section">
        <h2>Performance Analysis</h2>
        <h3>IO Statistics</h3>
        <pre>$(Get-Content "$AnalysisDir\io_stats.txt" -Raw)</pre>
        <h3>Expert Information</h3>
        <pre>$(Get-Content "$AnalysisDir\expert_info.txt" -Raw)</pre>
        <h3>Round-Trip Time</h3>
        <pre>$(Get-Content "$AnalysisDir\rtt_stats.txt" -Raw)</pre>
    </div>
</body>
</html>
"@
    
    $report | Out-File -FilePath $reportPath
    Write-Log -Message "Capture report generated at: $reportPath" -Level Info
    Write-Host "Report generated at: $reportPath" -ForegroundColor Green
}

# Function to monitor network traffic
function Start-NetworkMonitoring {
    param (
        [string]$Interface,
        [string]$Filter = "",
        [int]$Duration = 0,
        [string]$AlertThreshold = "1000"
    )
    
    Write-Log -Message "Starting network monitoring on interface $Interface" -Level Info
    Write-Host "Starting network monitoring..." -ForegroundColor Green
    
    $wiresharkPath = "C:\Program Files\Wireshark\tshark.exe"
    $monitorDir = "C:\SecurityTools\Monitoring\$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
    New-Item -ItemType Directory -Path $monitorDir -Force | Out-Null
    
    # Start continuous capture
    $captureFile = "$monitorDir\monitor.pcapng"
    $command = "& '$wiresharkPath' -i $Interface"
    
    if ($Filter) {
        $command += " -f `"$Filter`""
    }
    
    $command += " -w `"$captureFile`""
    
    if ($Duration -gt 0) {
        $command += " -a duration:$Duration"
    }
    
    # Start capture in background
    $job = Start-Job -ScriptBlock {
        param($cmd)
        Invoke-Expression $cmd
    } -ArgumentList $command
    
    # Monitor traffic in real-time
    while ($true) {
        $stats = "& '$wiresharkPath' -r `"$captureFile`" -q -z io,stat,1"
        $currentStats = Invoke-Expression $stats
        
        # Check for alert conditions
        if ($currentStats -match "packets") {
            $packetCount = [int]($currentStats -replace "[^0-9]", "")
            if ($packetCount -gt $AlertThreshold) {
                Write-Log -Message "Alert: High packet count detected: $packetCount" -Level Warning
                Write-Host "Alert: High packet count detected: $packetCount" -ForegroundColor Red
            }
        }
        
        Start-Sleep -Seconds 1
    }
    
    Write-Log -Message "Network monitoring completed" -Level Info
}

# Main menu
function Show-Menu {
    Write-Host "`nWireshark Automation Menu" -ForegroundColor Cyan
    Write-Host "1. Start Packet Capture"
    Write-Host "2. Analyze Capture File"
    Write-Host "3. Generate Capture Report"
    Write-Host "4. Start Network Monitoring"
    Write-Host "5. Exit"
    
    $choice = Read-Host "`nEnter your choice (1-5)"
    
    switch ($choice) {
        "1" { 
            $interface = Read-Host "Enter interface name"
            $filter = Read-Host "Enter capture filter (optional)"
            $duration = Read-Host "Enter capture duration in seconds (0 for unlimited)"
            Start-PacketCapture -Interface $interface -Filter $filter -Duration $duration
        }
        "2" { 
            $captureFile = Read-Host "Enter capture file path"
            $analysisType = Read-Host "Enter analysis type (basic/security/performance)"
            Analyze-CaptureFile -CaptureFile $captureFile -AnalysisType $analysisType
        }
        "3" { 
            $captureFile = Read-Host "Enter capture file path"
            $analysisDir = Read-Host "Enter analysis directory path"
            New-CaptureReport -CaptureFile $captureFile -AnalysisDir $analysisDir
        }
        "4" { 
            $interface = Read-Host "Enter interface name"
            $filter = Read-Host "Enter capture filter (optional)"
            $duration = Read-Host "Enter monitoring duration in seconds (0 for unlimited)"
            $threshold = Read-Host "Enter alert threshold (packets per second)"
            Start-NetworkMonitoring -Interface $interface -Filter $filter -Duration $duration -AlertThreshold $threshold
        }
        "5" { exit }
        default { Write-Host "Invalid choice" -ForegroundColor Red }
    }
}

# Run the menu
while ($true) {
    Show-Menu
    Read-Host "`nPress Enter to continue"
} 