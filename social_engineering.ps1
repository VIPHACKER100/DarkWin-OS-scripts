# DarkWin Social Engineering
# Author: viphacker.100
# Description: Performs social engineering and phishing testing

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$LogFile = "C:\Tools\Logs\social_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$TestDir = "C:\Tools\Tests\Social\$(Get-Date -Format 'yyyyMMdd_HHmmss')"

function Write-Log {
    param($Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    Write-Host $LogMessage
}

function Initialize-SocialTest {
    param(
        [string]$Target,
        [string]$TestType
    )
    Write-Log "Initializing social engineering test..."
    
    # Create test directory
    New-Item -ItemType Directory -Path $TestDir -Force | Out-Null
    
    # Create test workspace
    $Workspace = @{
        "target" = $Target
        "test_type" = $TestType
        "start_time" = Get-Date
        "tools" = @()
        "findings" = @()
    }
    
    $Workspace | ConvertTo-Json | Out-File "$TestDir\workspace.json"
    Write-Log "Test workspace created: $TestDir"
}

function Start-PhishingTest {
    param(
        [string]$Target,
        [string]$Template
    )
    Write-Log "Starting phishing test..."
    
    # Set up Gophish
    if (Test-Path "C:\Tools\Additional\Gophish\gophish.exe") {
        $GophishConfig = @"
{
    "admin_server": {
        "listen_url": "0.0.0.0:3333",
        "use_tls": true,
        "cert_path": "gophish_admin.crt",
        "key_path": "gophish_admin.key"
    },
    "phish_server": {
        "listen_url": "0.0.0.0:443",
        "use_tls": true,
        "cert_path": "example.crt",
        "key_path": "example.key"
    }
}
"@
        $GophishConfig | Out-File "$TestDir\gophish_config.json"
        Start-Process "C:\Tools\Additional\Gophish\gophish.exe" -ArgumentList "-config `"$TestDir\gophish_config.json`""
    }
    
    # Set up SET
    if (Test-Path "C:\Tools\Additional\SET\setoolkit.exe") {
        Start-Process "C:\Tools\Additional\SET\setoolkit.exe" -ArgumentList "-t `"$TestDir\set`""
    }
    
    Write-Log "Phishing test started"
}

function Start-SpearPhishingTest {
    param(
        [string]$Target,
        [string]$Template
    )
    Write-Log "Starting spear phishing test..."
    
    # Set up PhishLabs
    if (Test-Path "C:\Tools\Additional\PhishLabs\phishlabs.py") {
        python "C:\Tools\Additional\PhishLabs\phishlabs.py" -t $Target -o "$TestDir\phishlabs"
    }
    
    # Set up PhishLine
    if (Test-Path "C:\Tools\Additional\PhishLine\phishline.py") {
        python "C:\Tools\Additional\PhishLine\phishline.py" -t $Target -o "$TestDir\phishline"
    }
    
    Write-Log "Spear phishing test started"
}

function Start-VishingTest {
    param(
        [string]$Target
    )
    Write-Log "Starting vishing test..."
    
    # Set up Asterisk
    if (Test-Path "C:\Tools\Additional\Asterisk\asterisk.exe") {
        $AsteriskConfig = @"
[general]
context=default
bindaddr=0.0.0.0
"@
        $AsteriskConfig | Out-File "$TestDir\asterisk.conf"
        Start-Process "C:\Tools\Additional\Asterisk\asterisk.exe" -ArgumentList "-c `"$TestDir\asterisk.conf`""
    }
    
    Write-Log "Vishing test started"
}

function Start-PhysicalTest {
    param(
        [string]$Location
    )
    Write-Log "Starting physical security test..."
    
    # Set up BadUSB
    if (Test-Path "C:\Tools\Additional\BadUSB\badusb.py") {
        python "C:\Tools\Additional\BadUSB\badusb.py" -l $Location -o "$TestDir\badusb"
    }
    
    # Set up RFID tools
    if (Test-Path "C:\Tools\Additional\RFID\rfid.py") {
        python "C:\Tools\Additional\RFID\rfid.py" -l $Location -o "$TestDir\rfid"
    }
    
    Write-Log "Physical security test started"
}

function Generate-SocialReport {
    param(
        [string]$TestDir
    )
    Write-Log "Generating social engineering report..."
    
    $ReportFile = "$TestDir\report.html"
    $ReportContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>DarkWin Social Engineering Report</title>
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
    <h1>DarkWin Social Engineering Report</h1>
    <div class="section">
        <h2>Test Information</h2>
        <p>Date: $(Get-Date)</p>
        <p>Target: $($Workspace.target)</p>
        <p>Test Type: $($Workspace.test_type)</p>
    </div>
"@
    
    # Add test results
    $ReportContent += @"
    <div class="section">
        <h2>Test Results</h2>
"@
    
    # Add test files
    Get-ChildItem -Path $TestDir -Filter "*.txt" | ForEach-Object {
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
        [string]$TestType,
        
        [Parameter(Mandatory=$false)]
        [string]$Template,
        
        [Parameter(Mandatory=$false)]
        [string]$Location
    )
    
    Initialize-SocialTest -Target $Target -TestType $TestType
    
    # Run test phases
    switch ($TestType.ToLower()) {
        "phishing" { Start-PhishingTest -Target $Target -Template $Template }
        "spearphishing" { Start-SpearPhishingTest -Target $Target -Template $Template }
        "vishing" { Start-VishingTest -Target $Target }
        "physical" { Start-PhysicalTest -Location $Location }
        default { Write-Log "Unsupported test type: $TestType" }
    }
    
    # Generate report
    Generate-SocialReport -TestDir $TestDir
    
    Write-Log "Social engineering test completed successfully"
} catch {
    Write-Log "ERROR: Social engineering test failed - $_"
    exit 1
} 