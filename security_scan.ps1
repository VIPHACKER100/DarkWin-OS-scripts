# DarkWin Security Scanner
# Author: viphacker.100
# Description: Automated security scanning and reporting

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$ScanDate = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = "C:\Tools\Logs\scan_$ScanDate.log"
$ReportDir = "C:\Tools\Reports\Scans\$ScanDate"

function Write-Log {
    param($Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    Write-Host $LogMessage
}

function Initialize-Scan {
    Write-Log "Initializing security scan..."
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
    Write-Log "Scan directory created: $ReportDir"
}

function Start-NetworkScan {
    param(
        [string]$Target,
        [string]$OutputFile
    )
    Write-Log "Starting network scan of $Target..."
    
    # Nmap scan
    $NmapArgs = "-sV -sC -O --script vuln -oA `"$OutputFile`" $Target"
    nmap $NmapArgs
    
    # Convert to HTML report
    $XmlFile = "$OutputFile.xml"
    if (Test-Path $XmlFile) {
        $XslPath = "C:\Tools\Scripts\nmap-bootstrap.xsl"
        if (Test-Path $XslPath) {
            $Xml = [xml](Get-Content $XmlFile)
            $Xml.Save("$OutputFile.html")
        }
    }
    
    Write-Log "Network scan completed"
}

function Start-WebScan {
    param(
        [string]$Target,
        [string]$OutputFile
    )
    Write-Log "Starting web scan of $Target..."
    
    # Nikto scan
    nikto -h $Target -o "$OutputFile.nikto.txt"
    
    # SQLMap scan
    sqlmap -u $Target --batch --random-agent --output-dir="$OutputFile.sqlmap"
    
    Write-Log "Web scan completed"
}

function Start-SystemScan {
    param(
        [string]$OutputFile
    )
    Write-Log "Starting system security scan..."
    
    # System information
    systeminfo > "$OutputFile.systeminfo.txt"
    
    # Running services
    Get-Service | Where-Object {$_.Status -eq 'Running'} | Export-Csv "$OutputFile.services.csv"
    
    # Installed software
    Get-WmiObject -Class Win32_Product | Export-Csv "$OutputFile.software.csv"
    
    # Network connections
    netstat -anob > "$OutputFile.netstat.txt"
    
    Write-Log "System scan completed"
}

function Generate-Report {
    param(
        [string]$ScanDir
    )
    Write-Log "Generating scan report..."
    
    $ReportFile = "$ScanDir\report.html"
    $ReportContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>DarkWin Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #00ff00; }
        .section { margin: 20px 0; padding: 10px; border: 1px solid #333; }
        .finding { margin: 10px 0; padding: 5px; background: #1a1a1a; }
        .critical { color: #ff0000; }
        .high { color: #ff6600; }
        .medium { color: #ffff00; }
        .low { color: #00ff00; }
    </style>
</head>
<body>
    <h1>DarkWin Security Scan Report</h1>
    <div class="section">
        <h2>Scan Information</h2>
        <p>Date: $(Get-Date)</p>
        <p>System: $env:COMPUTERNAME</p>
    </div>
"@
    
    # Add scan results
    $ReportContent += @"
    <div class="section">
        <h2>Scan Results</h2>
"@
    
    # Add findings from each scan
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
    Initialize-Scan
    
    # Network scan
    Start-NetworkScan -Target "localhost" -OutputFile "$ReportDir\network_scan"
    
    # Web scan (if web server detected)
    if (Test-NetConnection -ComputerName localhost -Port 80 -WarningAction SilentlyContinue) {
        Start-WebScan -Target "http://localhost" -OutputFile "$ReportDir\web_scan"
    }
    
    # System scan
    Start-SystemScan -OutputFile "$ReportDir\system_scan"
    
    # Generate report
    Generate-Report -ScanDir $ReportDir
    
    Write-Log "Security scan completed successfully"
} catch {
    Write-Log "ERROR: Scan failed - $_"
    exit 1
} 