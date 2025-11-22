# DarkWin Web Security Testing
# Author: viphacker.100
# Description: Performs web application security testing

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$LogFile = "C:\Tools\Logs\web_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ScanDir = "C:\Tools\Scans\Web\$(Get-Date -Format 'yyyyMMdd_HHmmss')"

function Write-Log {
    param($Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    Write-Host $LogMessage
}

function Initialize-WebScan {
    param(
        [string]$Target,
        [string]$Scope
    )
    Write-Log "Initializing web security scan for $Target..."
    
    # Create scan directory
    New-Item -ItemType Directory -Path $ScanDir -Force | Out-Null
    
    # Create scan workspace
    $Workspace = @{
        "target" = $Target
        "scope" = $Scope
        "start_time" = Get-Date
        "tools" = @()
        "findings" = @()
    }
    
    $Workspace | ConvertTo-Json | Out-File "$ScanDir\workspace.json"
    Write-Log "Scan workspace created: $ScanDir"
}

function Start-Reconnaissance {
    param(
        [string]$Target
    )
    Write-Log "Starting web reconnaissance..."
    
    # DNS enumeration
    $DnsTools = @(
        "nslookup",
        "dig",
        "host"
    )
    
    foreach ($Tool in $DnsTools) {
        & $Tool $Target | Out-File "$ScanDir\dns.txt" -Append
    }
    
    # WHOIS lookup
    whois $Target | Out-File "$ScanDir\whois.txt"
    
    # Subdomain enumeration
    if (Test-Path "C:\Tools\Additional\Sublist3r\sublist3r.py") {
        python "C:\Tools\Additional\Sublist3r\sublist3r.py" -d $Target -o "$ScanDir\subdomains.txt"
    }
    
    Write-Log "Web reconnaissance completed"
}

function Start-VulnerabilityScan {
    param(
        [string]$Target
    )
    Write-Log "Starting vulnerability scan..."
    
    # Nikto scan
    nikto -h $Target -o "$ScanDir\nikto.txt"
    
    # SQLMap scan
    sqlmap -u $Target --batch --random-agent --output-dir="$ScanDir\sqlmap"
    
    # OWASP ZAP scan
    if (Test-Path "C:\Program Files\OWASP\Zed Attack Proxy\zap.bat") {
        & "C:\Program Files\OWASP\Zed Attack Proxy\zap.bat" -cmd -quickurl $Target -quickprogress -quickout "$ScanDir\zap.html"
    }
    
    # Acunetix scan
    if (Test-Path "C:\Tools\Additional\Acunetix\acunetix.exe") {
        & "C:\Tools\Additional\Acunetix\acunetix.exe" --target $Target --output "$ScanDir\acunetix.html"
    }
    
    Write-Log "Vulnerability scan completed"
}

function Start-DirectoryScan {
    param(
        [string]$Target
    )
    Write-Log "Starting directory scan..."
    
    # Dirb scan
    dirb http://$Target -o "$ScanDir\dirb.txt"
    
    # Gobuster scan
    gobuster dir -u http://$Target -w "C:\Tools\Wordlists\SecLists\Discovery\Web-Content\common.txt" -o "$ScanDir\gobuster.txt"
    
    # Dirsearch scan
    if (Test-Path "C:\Tools\Additional\dirsearch\dirsearch.py") {
        python "C:\Tools\Additional\dirsearch\dirsearch.py" -u http://$Target -o "$ScanDir\dirsearch.txt"
    }
    
    Write-Log "Directory scan completed"
}

function Start-ContentScan {
    param(
        [string]$Target
    )
    Write-Log "Starting content scan..."
    
    # Waybackurls
    if (Test-Path "C:\Tools\Additional\waybackurls\waybackurls.exe") {
        & "C:\Tools\Additional\waybackurls\waybackurls.exe" $Target | Out-File "$ScanDir\waybackurls.txt"
    }
    
    # ParamSpider
    if (Test-Path "C:\Tools\Additional\ParamSpider\paramspider.py") {
        python "C:\Tools\Additional\ParamSpider\paramspider.py" --domain $Target --output "$ScanDir\paramspider.txt"
    }
    
    # Arjun
    if (Test-Path "C:\Tools\Additional\Arjun\arjun.py") {
        python "C:\Tools\Additional\Arjun\arjun.py" -u http://$Target -oJ "$ScanDir\arjun.json"
    }
    
    Write-Log "Content scan completed"
}

function Start-APIScan {
    param(
        [string]$Target
    )
    Write-Log "Starting API scan..."
    
    # API endpoints discovery
    if (Test-Path "C:\Tools\Additional\API-Fuzzer\apifuzzer.py") {
        python "C:\Tools\Additional\API-Fuzzer\apifuzzer.py" -u http://$Target -o "$ScanDir\apifuzzer.txt"
    }
    
    # API security testing
    if (Test-Path "C:\Tools\Additional\API-Security-Tester\apitester.py") {
        python "C:\Tools\Additional\API-Security-Tester\apitester.py" -u http://$Target -o "$ScanDir\apitester.txt"
    }
    
    Write-Log "API scan completed"
}

function Start-JSScan {
    param(
        [string]$Target
    )
    Write-Log "Starting JavaScript scan..."
    
    # JS file discovery
    if (Test-Path "C:\Tools\Additional\JS-Scanner\jsscanner.py") {
        python "C:\Tools\Additional\JS-Scanner\jsscanner.py" -u http://$Target -o "$ScanDir\jsscanner.txt"
    }
    
    # JS analysis
    if (Test-Path "C:\Tools\Additional\JS-Analyzer\jsanalyzer.py") {
        python "C:\Tools\Additional\JS-Analyzer\jsanalyzer.py" -u http://$Target -o "$ScanDir\jsanalyzer.txt"
    }
    
    Write-Log "JavaScript scan completed"
}

function Generate-WebReport {
    param(
        [string]$ScanDir
    )
    Write-Log "Generating web security report..."
    
    $ReportFile = "$ScanDir\report.html"
    $ReportContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>DarkWin Web Security Report</title>
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
    <h1>DarkWin Web Security Report</h1>
    <div class="section">
        <h2>Scan Information</h2>
        <p>Date: $(Get-Date)</p>
        <p>Target: $($Workspace.target)</p>
        <p>Scope: $($Workspace.scope)</p>
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
        [string]$Target,
        
        [Parameter(Mandatory=$true)]
        [string]$Scope
    )
    
    Initialize-WebScan -Target $Target -Scope $Scope
    
    # Run scan phases
    Start-Reconnaissance -Target $Target
    Start-VulnerabilityScan -Target $Target
    Start-DirectoryScan -Target $Target
    Start-ContentScan -Target $Target
    Start-APIScan -Target $Target
    Start-JSScan -Target $Target
    
    # Generate report
    Generate-WebReport -ScanDir $ScanDir
    
    Write-Log "Web security scan completed successfully"
} catch {
    Write-Log "ERROR: Web security scan failed - $_"
    exit 1
} 