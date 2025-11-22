# DarkWin IoT Security
# Author: viphacker.100
# Description: Performs IoT security testing

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$LogFile = "C:\Tools\Logs\iot_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ScanDir = "C:\Tools\Scans\IoT\$(Get-Date -Format 'yyyyMMdd_HHmmss')"

function Write-Log {
    param($Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    Write-Host $LogMessage
}

function Initialize-IoTScan {
    param(
        [string]$DeviceIP,
        [string]$DeviceType
    )
    Write-Log "Initializing IoT security scan..."
    
    # Create scan directory
    New-Item -ItemType Directory -Path $ScanDir -Force | Out-Null
    
    # Create scan workspace
    $Workspace = @{
        "device_ip" = $DeviceIP
        "device_type" = $DeviceType
        "start_time" = Get-Date
        "tools" = @()
        "findings" = @()
    }
    
    $Workspace | ConvertTo-Json | Out-File "$ScanDir\workspace.json"
    Write-Log "Scan workspace created: $ScanDir"
}

function Start-NetworkScan {
    param(
        [string]$DeviceIP
    )
    Write-Log "Starting network scan..."
    
    # Nmap scan
    $NmapArgs = "-sV -sC -O --script vuln -oA `"$ScanDir\nmap`" $DeviceIP"
    nmap $NmapArgs
    
    # Masscan
    if (Test-Path "C:\Tools\Additional\masscan\masscan.exe") {
        $MasscanArgs = "--rate=1000 -p1-65535 -oJ `"$ScanDir\masscan.json`" $DeviceIP"
        & "C:\Tools\Additional\masscan\masscan.exe" $MasscanArgs
    }
    
    Write-Log "Network scan completed"
}

function Start-FirmwareAnalysis {
    param(
        [string]$FirmwarePath
    )
    Write-Log "Starting firmware analysis..."
    
    # Analyze with Binwalk
    if (Test-Path "C:\Tools\Additional\Binwalk\binwalk.exe") {
        & "C:\Tools\Additional\Binwalk\binwalk.exe" -e -M -d $FirmwarePath | Out-File "$ScanDir\binwalk.txt"
    }
    
    # Analyze with Firmware Analysis Toolkit
    if (Test-Path "C:\Tools\Additional\FAT\fat.py") {
        python "C:\Tools\Additional\FAT\fat.py" -i $FirmwarePath -o "$ScanDir\fat"
    }
    
    # Analyze with Firmadyne
    if (Test-Path "C:\Tools\Additional\Firmadyne\firmadyne.py") {
        python "C:\Tools\Additional\Firmadyne\firmadyne.py" -i $FirmwarePath -o "$ScanDir\firmadyne"
    }
    
    Write-Log "Firmware analysis completed"
}

function Start-ProtocolAnalysis {
    param(
        [string]$DeviceIP
    )
    Write-Log "Starting protocol analysis..."
    
    # MQTT analysis
    if (Test-Path "C:\Tools\Additional\MQTT\mqtt.py") {
        python "C:\Tools\Additional\MQTT\mqtt.py" -h $DeviceIP -o "$ScanDir\mqtt.txt"
    }
    
    # CoAP analysis
    if (Test-Path "C:\Tools\Additional\CoAP\coap.py") {
        python "C:\Tools\Additional\CoAP\coap.py" -h $DeviceIP -o "$ScanDir\coap.txt"
    }
    
    # Zigbee analysis
    if (Test-Path "C:\Tools\Additional\Zigbee\zigbee.py") {
        python "C:\Tools\Additional\Zigbee\zigbee.py" -h $DeviceIP -o "$ScanDir\zigbee.txt"
    }
    
    Write-Log "Protocol analysis completed"
}

function Start-RadioAnalysis {
    param(
        [string]$Frequency
    )
    Write-Log "Starting radio analysis..."
    
    # RTL-SDR analysis
    if (Test-Path "C:\Tools\Additional\RTL-SDR\rtl_sdr.exe") {
        & "C:\Tools\Additional\RTL-SDR\rtl_sdr.exe" -f $Frequency -s 2500000 -o "$ScanDir\rtl_sdr.bin"
    }
    
    # GQRX analysis
    if (Test-Path "C:\Tools\Additional\GQRX\gqrx.exe") {
        Start-Process "C:\Tools\Additional\GQRX\gqrx.exe" -ArgumentList "-f $Frequency -o `"$ScanDir\gqrx.wav`""
    }
    
    Write-Log "Radio analysis completed"
}

function Start-SecurityTesting {
    param(
        [string]$DeviceIP
    )
    Write-Log "Starting security testing..."
    
    # Test with IoT Inspector
    if (Test-Path "C:\Tools\Additional\IoT-Inspector\iot_inspector.py") {
        python "C:\Tools\Additional\IoT-Inspector\iot_inspector.py" -i $DeviceIP -o "$ScanDir\iot_inspector.txt"
    }
    
    # Test with IoT Security Framework
    if (Test-Path "C:\Tools\Additional\IoT-SF\iot_sf.py") {
        python "C:\Tools\Additional\IoT-SF\iot_sf.py" -i $DeviceIP -o "$ScanDir\iot_sf.txt"
    }
    
    Write-Log "Security testing completed"
}

function Generate-IoTReport {
    param(
        [string]$ScanDir
    )
    Write-Log "Generating IoT security report..."
    
    $ReportFile = "$ScanDir\report.html"
    $ReportContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>DarkWin IoT Security Report</title>
    <style>
        body { font-family: 'Consolas', monospace; margin: 20px; background: #1a1a1a; color: #00ff00; }
        h1, h2, h3 { color: #00ff00; }
        .section { margin: 20px 0; padding: 10px; border: 1px solid #333; }
        .finding { margin: 10px 0; padding: 5px; background: #2a2a2a; }
        .critical { color: #ff0000; }
        .high { color: #ff6600; }
        .medium { color: #ffff00; }
        .low { color: #00ff00; }
        pre { background: #2a2a2a; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>DarkWin IoT Security Report</h1>
    <div class="section">
        <h2>Scan Information</h2>
        <p>Date: $(Get-Date)</p>
        <p>Device IP: $($Workspace.device_ip)</p>
        <p>Device Type: $($Workspace.device_type)</p>
    </div>
"@
    
    # Add scan results
    $ReportContent += @"
    <div class="section">
        <h2>Scan Results</h2>
"@
    
    # Add scan files
    Get-ChildItem -Path $ScanDir -Filter "*.txt" | ForEach-Object {
        $ReportContent += @"
        <div class="finding">
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
        [string]$DeviceIP,
        
        [Parameter(Mandatory=$true)]
        [string]$DeviceType,
        
        [Parameter(Mandatory=$false)]
        [string]$FirmwarePath,
        
        [Parameter(Mandatory=$false)]
        [string]$Frequency
    )
    
    Initialize-IoTScan -DeviceIP $DeviceIP -DeviceType $DeviceType
    
    # Run scan phases
    Start-NetworkScan -DeviceIP $DeviceIP
    
    if ($FirmwarePath) {
        Start-FirmwareAnalysis -FirmwarePath $FirmwarePath
    }
    
    Start-ProtocolAnalysis -DeviceIP $DeviceIP
    
    if ($Frequency) {
        Start-RadioAnalysis -Frequency $Frequency
    }
    
    Start-SecurityTesting -DeviceIP $DeviceIP
    
    # Generate report
    Generate-IoTReport -ScanDir $ScanDir
    
    Write-Log "IoT security scan completed successfully"
} catch {
    Write-Log "ERROR: IoT security scan failed - $_"
    exit 1
} 