# DarkWin Cloud Security
# Author: viphacker.100
# Description: Performs cloud security testing and analysis

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$LogFile = "C:\Tools\Logs\cloud_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ScanDir = "C:\Tools\Scans\Cloud\$(Get-Date -Format 'yyyyMMdd_HHmmss')"

function Write-Log {
    param($Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    Write-Host $LogMessage
}

function Initialize-CloudScan {
    param(
        [string]$Provider,
        [string]$Region
    )
    Write-Log "Initializing cloud security scan..."
    
    # Create scan directory
    New-Item -ItemType Directory -Path $ScanDir -Force | Out-Null
    
    # Create scan workspace
    $Workspace = @{
        "provider" = $Provider
        "region" = $Region
        "start_time" = Get-Date
        "tools" = @()
        "findings" = @()
    }
    
    $Workspace | ConvertTo-Json | Out-File "$ScanDir\workspace.json"
    Write-Log "Scan workspace created: $ScanDir"
}

function Start-AWSScan {
    param(
        [string]$Region
    )
    Write-Log "Starting AWS security scan..."
    
    # Scan with ScoutSuite
    if (Test-Path "C:\Tools\Additional\ScoutSuite\scout.py") {
        python "C:\Tools\Additional\ScoutSuite\scout.py" aws --profile default --region $Region --report-dir "$ScanDir\scoutsuite"
    }
    
    # Scan with Prowler
    if (Test-Path "C:\Tools\Additional\Prowler\prowler.exe") {
        & "C:\Tools\Additional\Prowler\prowler.exe" -r $Region -o "$ScanDir\prowler.txt"
    }
    
    # Scan with CloudSploit
    if (Test-Path "C:\Tools\Additional\CloudSploit\cloudsploit.js") {
        node "C:\Tools\Additional\CloudSploit\cloudsploit.js" scan --region $Region --output "$ScanDir\cloudsploit.json"
    }
    
    Write-Log "AWS security scan completed"
}

function Start-AzureScan {
    param(
        [string]$Region
    )
    Write-Log "Starting Azure security scan..."
    
    # Scan with AzSK
    if (Test-Path "C:\Tools\Additional\AzSK\AzSK.ps1") {
        & "C:\Tools\Additional\AzSK\AzSK.ps1" -SubscriptionId $Region -OutputFolder "$ScanDir\azsk"
    }
    
    # Scan with CloudSploit
    if (Test-Path "C:\Tools\Additional\CloudSploit\cloudsploit.js") {
        node "C:\Tools\Additional\CloudSploit\cloudsploit.js" scan --provider azure --region $Region --output "$ScanDir\cloudsploit.json"
    }
    
    Write-Log "Azure security scan completed"
}

function Start-GCPScan {
    param(
        [string]$Region
    )
    Write-Log "Starting GCP security scan..."
    
    # Scan with Forseti
    if (Test-Path "C:\Tools\Additional\Forseti\forseti.py") {
        python "C:\Tools\Additional\Forseti\forseti.py" scanner run --output-path "$ScanDir\forseti"
    }
    
    # Scan with CloudSploit
    if (Test-Path "C:\Tools\Additional\CloudSploit\cloudsploit.js") {
        node "C:\Tools\Additional\CloudSploit\cloudsploit.js" scan --provider gcp --region $Region --output "$ScanDir\cloudsploit.json"
    }
    
    Write-Log "GCP security scan completed"
}

function Start-ContainerScan {
    param(
        [string]$Image
    )
    Write-Log "Starting container security scan..."
    
    # Scan with Trivy
    if (Test-Path "C:\Tools\Additional\Trivy\trivy.exe") {
        & "C:\Tools\Additional\Trivy\trivy.exe" image -f json -o "$ScanDir\trivy.json" $Image
    }
    
    # Scan with Clair
    if (Test-Path "C:\Tools\Additional\Clair\clair.exe") {
        & "C:\Tools\Additional\Clair\clair.exe" --image $Image --output "$ScanDir\clair.json"
    }
    
    # Scan with Anchore
    if (Test-Path "C:\Tools\Additional\Anchore\anchore-cli.exe") {
        & "C:\Tools\Additional\Anchore\anchore-cli.exe" image add $Image
        & "C:\Tools\Additional\Anchore\anchore-cli.exe" image wait $Image
        & "C:\Tools\Additional\Anchore\anchore-cli.exe" image content $Image > "$ScanDir\anchore.txt"
    }
    
    Write-Log "Container security scan completed"
}

function Start-KubernetesScan {
    param(
        [string]$Config
    )
    Write-Log "Starting Kubernetes security scan..."
    
    # Scan with kube-bench
    if (Test-Path "C:\Tools\Additional\kube-bench\kube-bench.exe") {
        & "C:\Tools\Additional\kube-bench\kube-bench.exe" --benchmark cis-1.6 --json "$ScanDir\kube-bench.json"
    }
    
    # Scan with kube-hunter
    if (Test-Path "C:\Tools\Additional\kube-hunter\kube-hunter.py") {
        python "C:\Tools\Additional\kube-hunter\kube-hunter.py" --report json --output "$ScanDir\kube-hunter.json"
    }
    
    # Scan with kubeaudit
    if (Test-Path "C:\Tools\Additional\kubeaudit\kubeaudit.exe") {
        & "C:\Tools\Additional\kubeaudit\kubeaudit.exe" --format json --output "$ScanDir\kubeaudit.json"
    }
    
    Write-Log "Kubernetes security scan completed"
}

function Start-InfrastructureScan {
    param(
        [string]$TerraformDir
    )
    Write-Log "Starting infrastructure security scan..."
    
    # Scan with tfsec
    if (Test-Path "C:\Tools\Additional\tfsec\tfsec.exe") {
        & "C:\Tools\Additional\tfsec\tfsec.exe" --format json --out "$ScanDir\tfsec.json" $TerraformDir
    }
    
    # Scan with Checkov
    if (Test-Path "C:\Tools\Additional\Checkov\checkov.exe") {
        & "C:\Tools\Additional\Checkov\checkov.exe" -d $TerraformDir -o json --output-file-path "$ScanDir\checkov.json"
    }
    
    Write-Log "Infrastructure security scan completed"
}

function Generate-CloudReport {
    param(
        [string]$ScanDir
    )
    Write-Log "Generating cloud security report..."
    
    $ReportFile = "$ScanDir\report.html"
    $ReportContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>DarkWin Cloud Security Report</title>
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
    <h1>DarkWin Cloud Security Report</h1>
    <div class="section">
        <h2>Scan Information</h2>
        <p>Date: $(Get-Date)</p>
        <p>Provider: $($Workspace.provider)</p>
        <p>Region: $($Workspace.region)</p>
    </div>
"@
    
    # Add scan results
    $ReportContent += @"
    <div class="section">
        <h2>Scan Results</h2>
"@
    
    # Add scan files
    Get-ChildItem -Path $ScanDir -Filter "*.json" | ForEach-Object {
        $ReportContent += @"
        <div class="finding">
            <h3>$($_.Name)</h3>
            <pre>$(Get-Content $_.FullName -Raw | ConvertFrom-Json | ConvertTo-Json -Depth 10)</pre>
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
        [string]$Provider,
        
        [Parameter(Mandatory=$true)]
        [string]$Region,
        
        [Parameter(Mandatory=$false)]
        [string]$Image,
        
        [Parameter(Mandatory=$false)]
        [string]$Config,
        
        [Parameter(Mandatory=$false)]
        [string]$TerraformDir
    )
    
    Initialize-CloudScan -Provider $Provider -Region $Region
    
    # Run provider-specific scan
    switch ($Provider.ToLower()) {
        "aws" { Start-AWSScan -Region $Region }
        "azure" { Start-AzureScan -Region $Region }
        "gcp" { Start-GCPScan -Region $Region }
        default { Write-Log "Unsupported cloud provider: $Provider" }
    }
    
    # Run additional scans if parameters provided
    if ($Image) {
        Start-ContainerScan -Image $Image
    }
    
    if ($Config) {
        Start-KubernetesScan -Config $Config
    }
    
    if ($TerraformDir) {
        Start-InfrastructureScan -TerraformDir $TerraformDir
    }
    
    # Generate report
    Generate-CloudReport -ScanDir $ScanDir
    
    Write-Log "Cloud security scan completed successfully"
} catch {
    Write-Log "ERROR: Cloud security scan failed - $_"
    exit 1
} 