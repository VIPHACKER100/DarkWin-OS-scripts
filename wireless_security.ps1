# DarkWin Wireless Security
# Author: viphacker.100
# Description: Performs wireless security testing

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$LogFile = "C:\Tools\Logs\wireless_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ScanDir = "C:\Tools\Scans\Wireless\$(Get-Date -Format 'yyyyMMdd_HHmmss')"

function Write-Log {
    param($Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    Write-Host $LogMessage
}

function Initialize-WirelessScan {
    param(
        [string]$Interface,
        [string]$ScanType
    )
    Write-Log "Initializing wireless security scan..."
    
    # Create scan directory
    New-Item -ItemType Directory -Path $ScanDir -Force | Out-Null
    
    # Create scan workspace
    $Workspace = @{
        "interface" = $Interface
        "scan_type" = $ScanType
        "start_time" = Get-Date
        "tools" = @()
        "findings" = @()
    }
    
    $Workspace | ConvertTo-Json | Out-File "$ScanDir\workspace.json"
    Write-Log "Scan workspace created: $ScanDir"
}

function Start-WiFiScan {
    param(
        [string]$Interface
    )
    Write-Log "Starting WiFi scan..."
    
    # Airodump-ng scan
    if (Test-Path "C:\Tools\Additional\Aircrack-ng\airodump-ng.exe") {
        Start-Process "C:\Tools\Additional\Aircrack-ng\airodump-ng.exe" -ArgumentList "-w `"$ScanDir\wifi`" --output-format csv $Interface"
    }
    
    # Kismet scan
    if (Test-Path "C:\Tools\Additional\Kismet\kismet.exe") {
        $KismetConfig = @"
source=$Interface
"@
        $KismetConfig | Out-File "$ScanDir\kismet.conf"
        Start-Process "C:\Tools\Additional\Kismet\kismet.exe" -ArgumentList "-c `"$ScanDir\kismet.conf`""
    }
    
    Write-Log "WiFi scan started"
}

function Start-WPA2Test {
    param(
        [string]$Interface,
        [string]$BSSID
    )
    Write-Log "Starting WPA2 security test..."
    
    # Aircrack-ng WPA2 test
    if (Test-Path "C:\Tools\Additional\Aircrack-ng\aircrack-ng.exe") {
        Start-Process "C:\Tools\Additional\Aircrack-ng\aircrack-ng.exe" -ArgumentList "-w `"$ScanDir\wpa2`" -b $BSSID $Interface"
    }
    
    # Hashcat WPA2 test
    if (Test-Path "C:\Tools\Additional\Hashcat\hashcat.exe") {
        Start-Process "C:\Tools\Additional\Hashcat\hashcat.exe" -ArgumentList "-m 2500 -a 0 `"$ScanDir\wpa2.hccapx`" `"$ScanDir\wordlist.txt`""
    }
    
    Write-Log "WPA2 security test started"
}

function Start-WEPTest {
    param(
        [string]$Interface,
        [string]$BSSID
    )
    Write-Log "Starting WEP security test..."
    
    # Aircrack-ng WEP test
    if (Test-Path "C:\Tools\Additional\Aircrack-ng\aircrack-ng.exe") {
        Start-Process "C:\Tools\Additional\Aircrack-ng\aircrack-ng.exe" -ArgumentList "-w `"$ScanDir\wep`" -b $BSSID $Interface"
    }
    
    Write-Log "WEP security test started"
}

function Start-RogueAPTest {
    param(
        [string]$Interface
    )
    Write-Log "Starting rogue AP test..."
    
    # Airbase-ng rogue AP
    if (Test-Path "C:\Tools\Additional\Aircrack-ng\airbase-ng.exe") {
        Start-Process "C:\Tools\Additional\Aircrack-ng\airbase-ng.exe" -ArgumentList "-e `"DarkWin_AP`" -c 1 $Interface"
    }
    
    # Hostapd rogue AP
    if (Test-Path "C:\Tools\Additional\Hostapd\hostapd.exe") {
        $HostapdConfig = @"
interface=$Interface
driver=nl80211
ssid=DarkWin_AP
hw_mode=g
channel=1
auth_algs=1
wpa=2
wpa_passphrase=darkwin123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"@
        $HostapdConfig | Out-File "$ScanDir\hostapd.conf"
        Start-Process "C:\Tools\Additional\Hostapd\hostapd.exe" -ArgumentList "`"$ScanDir\hostapd.conf`""
    }
    
    Write-Log "Rogue AP test started"
}

function Generate-WirelessReport {
    param(
        [string]$ScanDir
    )
    Write-Log "Generating wireless security report..."
    
    $ReportFile = "$ScanDir\report.html"
    $ReportContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>DarkWin Wireless Security Report</title>
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
    <h1>DarkWin Wireless Security Report</h1>
    <div class="section">
        <h2>Scan Information</h2>
        <p>Date: $(Get-Date)</p>
        <p>Interface: $($Workspace.interface)</p>
        <p>Scan Type: $($Workspace.scan_type)</p>
    </div>
"@
    
    # Add scan results
    $ReportContent += @"
    <div class="section">
        <h2>Scan Results</h2>
"@
    
    # Add scan files
    Get-ChildItem -Path $ScanDir -Filter "*.csv" | ForEach-Object {
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
        [string]$Interface,
        
        [Parameter(Mandatory=$true)]
        [string]$ScanType,
        
        [Parameter(Mandatory=$false)]
        [string]$BSSID
    )
    
    Initialize-WirelessScan -Interface $Interface -ScanType $ScanType
    
    # Run scan phases
    switch ($ScanType.ToLower()) {
        "wifi" { Start-WiFiScan -Interface $Interface }
        "wpa2" { Start-WPA2Test -Interface $Interface -BSSID $BSSID }
        "wep" { Start-WEPTest -Interface $Interface -BSSID $BSSID }
        "rogueap" { Start-RogueAPTest -Interface $Interface }
        default { Write-Log "Unsupported scan type: $ScanType" }
    }
    
    # Generate report
    Generate-WirelessReport -ScanDir $ScanDir
    
    Write-Log "Wireless security scan completed successfully"
} catch {
    Write-Log "ERROR: Wireless security scan failed - $_"
    exit 1
} 