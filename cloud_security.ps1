# DarkWin Cloud Security v2.0
# Author: viphacker.100
# Description: Advanced cloud security testing and analysis with enhanced features
# Version: 2.0
# Last Updated: 2026-01-28

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Cloud provider: AWS, Azure, GCP, Multi")]
    [ValidateSet("AWS", "Azure", "GCP", "Multi")]
    [string]$Provider,
    
    [Parameter(Mandatory=$true, HelpMessage="Region or subscription ID")]
    [string]$Region,
    
    [Parameter(Mandatory=$false, HelpMessage="Container image to scan")]
    [string]$Image,
    
    [Parameter(Mandatory=$false, HelpMessage="Kubernetes config path")]
    [string]$KubeConfig,
    
    [Parameter(Mandatory=$false, HelpMessage="Terraform/IaC directory path")]
    [string]$TerraformDir,
    
    [Parameter(Mandatory=$false, HelpMessage="Output directory for results")]
    [string]$OutputDir = "C:\Tools\Scans\Cloud",
    
    [Parameter(Mandatory=$false, HelpMessage="Severity level filter: Critical, High, Medium, Low, All")]
    [ValidateSet("Critical", "High", "Medium", "Low", "All")]
    [string]$SeverityFilter = "All",
    
    [Parameter(Mandatory=$false, HelpMessage="Enable parallel scanning")]
    [switch]$ParallelScan,
    
    [Parameter(Mandatory=$false, HelpMessage="Export format: JSON, XML, CSV, HTML, All")]
    [ValidateSet("JSON", "XML", "CSV", "HTML", "All")]
    [string]$ExportFormat = "All",
    
    [Parameter(Mandatory=$false, HelpMessage="Enable compliance checks (CIS, NIST, PCI-DSS)")]
    [switch]$ComplianceCheck,
    
    [Parameter(Mandatory=$false, HelpMessage="Send results to webhook URL")]
    [string]$WebhookURL,
    
    [Parameter(Mandatory=$false, HelpMessage="Enable verbose output")]
    [switch]$Verbose
)

$ErrorActionPreference = "Continue"
$Global:ScanStartTime = Get-Date
$Global:Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Global:LogFile = "$OutputDir\Logs\cloud_$Global:Timestamp.log"
$Global:ScanDir = "$OutputDir\$Global:Timestamp"
$Global:Findings = @()
$Global:Statistics = @{
    TotalScans = 0
    SuccessfulScans = 0
    FailedScans = 0
    CriticalFindings = 0
    HighFindings = 0
    MediumFindings = 0
    LowFindings = 0
    InfoFindings = 0
}

# Initialize directories
function Initialize-Directories {
    $directories = @(
        $Global:ScanDir,
        "$Global:ScanDir\AWS",
        "$Global:ScanDir\Azure",
        "$Global:ScanDir\GCP",
        "$Global:ScanDir\Container",
        "$Global:ScanDir\Kubernetes",
        "$Global:ScanDir\Infrastructure",
        "$Global:ScanDir\Reports",
        "$OutputDir\Logs"
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
}

# Enhanced logging with levels
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Console output with colors
    switch ($Level) {
        "INFO"    { Write-Host $logMessage -ForegroundColor Cyan }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        "DEBUG"   { if ($Verbose) { Write-Host $logMessage -ForegroundColor Gray } }
    }
    
    # File output
    Add-Content -Path $Global:LogFile -Value $logMessage -ErrorAction SilentlyContinue
}

# Progress bar helper
function Show-Progress {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete
    )
    
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
}

# Test tool availability
function Test-Tool {
    param(
        [string]$ToolPath,
        [string]$ToolName
    )
    
    if (Test-Path $ToolPath) {
        Write-Log "Tool available: $ToolName" -Level "DEBUG"
        return $true
    } else {
        Write-Log "Tool not found: $ToolName at $ToolPath" -Level "WARNING"
        return $false
    }
}

# Initialize cloud scan
function Initialize-CloudScan {
    Write-Log "=" * 80 -Level "INFO"
    Write-Log "DarkWin Cloud Security Scanner v2.0" -Level "SUCCESS"
    Write-Log "=" * 80 -Level "INFO"
    Write-Log "Initializing cloud security scan..." -Level "INFO"
    
    Initialize-Directories
    
    # Create scan metadata
    $metadata = @{
        Version = "2.0"
        Provider = $Provider
        Region = $Region
        StartTime = $Global:ScanStartTime.ToString("yyyy-MM-dd HH:mm:ss")
        Hostname = $env:COMPUTERNAME
        Username = $env:USERNAME
        ScanID = $Global:Timestamp
        Parameters = @{
            Image = $Image
            KubeConfig = $KubeConfig
            TerraformDir = $TerraformDir
            SeverityFilter = $SeverityFilter
            ParallelScan = $ParallelScan.IsPresent
            ComplianceCheck = $ComplianceCheck.IsPresent
        }
        Tools = @()
        Findings = @()
    }
    
    $metadata | ConvertTo-Json -Depth 10 | Out-File "$Global:ScanDir\metadata.json"
    Write-Log "Scan workspace created: $Global:ScanDir" -Level "SUCCESS"
    Write-Log "Scan ID: $Global:Timestamp" -Level "INFO"
}

# Enhanced AWS scanning
function Start-AWSScan {
    param([string]$Region)
    
    Write-Log "Starting AWS security scan for region: $Region" -Level "INFO"
    $awsDir = "$Global:ScanDir\AWS"
    $toolsRun = 0
    $toolsTotal = 5
    
    try {
        # ScoutSuite - Multi-cloud security auditing
        if (Test-Tool "C:\Tools\Additional\ScoutSuite\scout.py" "ScoutSuite") {
            Show-Progress -Activity "AWS Scan" -Status "Running ScoutSuite..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running ScoutSuite for AWS..." -Level "INFO"
            $scoutOutput = python "C:\Tools\Additional\ScoutSuite\scout.py" aws --profile default --region $Region --report-dir "$awsDir\scoutsuite" --no-browser 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "ScoutSuite scan completed" -Level "SUCCESS"
                Parse-ScoutSuiteResults -ResultPath "$awsDir\scoutsuite"
            }
            $toolsRun++
        }
        
        # Prowler - AWS security best practices
        if (Test-Tool "C:\Tools\Additional\Prowler\prowler.exe" "Prowler") {
            Show-Progress -Activity "AWS Scan" -Status "Running Prowler..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running Prowler for AWS..." -Level "INFO"
            & "C:\Tools\Additional\Prowler\prowler.exe" -r $Region -M json -o "$awsDir\" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Prowler scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # CloudSploit - Cloud security scanning
        if (Test-Tool "C:\Tools\Additional\CloudSploit\index.js" "CloudSploit") {
            Show-Progress -Activity "AWS Scan" -Status "Running CloudSploit..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running CloudSploit for AWS..." -Level "INFO"
            node "C:\Tools\Additional\CloudSploit\index.js" --cloud aws --region $Region --json "$awsDir\cloudsploit.json" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "CloudSploit scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # CloudMapper - AWS environment visualization
        if (Test-Tool "C:\Tools\Additional\CloudMapper\cloudmapper.py" "CloudMapper") {
            Show-Progress -Activity "AWS Scan" -Status "Running CloudMapper..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running CloudMapper for AWS..." -Level "INFO"
            python "C:\Tools\Additional\CloudMapper\cloudmapper.py" collect --account default --region $Region 2>&1 | Out-Null
            python "C:\Tools\Additional\CloudMapper\cloudmapper.py" report --account default --output-file "$awsDir\cloudmapper.html" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "CloudMapper scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # AWS Security Hub findings (if AWS CLI available)
        if (Get-Command aws -ErrorAction SilentlyContinue) {
            Show-Progress -Activity "AWS Scan" -Status "Checking Security Hub..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Fetching AWS Security Hub findings..." -Level "INFO"
            $securityHubFindings = aws securityhub get-findings --region $Region --filters "RecordState={Value=ACTIVE}" --output json 2>&1
            if ($LASTEXITCODE -eq 0) {
                $securityHubFindings | Out-File "$awsDir\security_hub.json"
                Write-Log "Security Hub findings retrieved" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        Write-Log "AWS security scan completed" -Level "SUCCESS"
        $Global:Statistics.SuccessfulScans++
        
    } catch {
        Write-Log "AWS scan error: $_" -Level "ERROR"
        $Global:Statistics.FailedScans++
    }
}

# Enhanced Azure scanning
function Start-AzureScan {
    param([string]$SubscriptionId)
    
    Write-Log "Starting Azure security scan for subscription: $SubscriptionId" -Level "INFO"
    $azureDir = "$Global:ScanDir\Azure"
    $toolsRun = 0
    $toolsTotal = 4
    
    try {
        # AzSK (Azure Security Kit)
        if (Test-Tool "C:\Tools\Additional\AzSK\AzSK.ps1" "AzSK") {
            Show-Progress -Activity "Azure Scan" -Status "Running AzSK..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running AzSK for Azure..." -Level "INFO"
            & "C:\Tools\Additional\AzSK\AzSK.ps1" -SubscriptionId $SubscriptionId -OutputFolder "$azureDir\azsk" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "AzSK scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # ScoutSuite for Azure
        if (Test-Tool "C:\Tools\Additional\ScoutSuite\scout.py" "ScoutSuite") {
            Show-Progress -Activity "Azure Scan" -Status "Running ScoutSuite..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running ScoutSuite for Azure..." -Level "INFO"
            python "C:\Tools\Additional\ScoutSuite\scout.py" azure --report-dir "$azureDir\scoutsuite" --no-browser 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "ScoutSuite scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # CloudSploit for Azure
        if (Test-Tool "C:\Tools\Additional\CloudSploit\index.js" "CloudSploit") {
            Show-Progress -Activity "Azure Scan" -Status "Running CloudSploit..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running CloudSploit for Azure..." -Level "INFO"
            node "C:\Tools\Additional\CloudSploit\index.js" --cloud azure --json "$azureDir\cloudsploit.json" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "CloudSploit scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # Azure Security Center recommendations (if Azure CLI available)
        if (Get-Command az -ErrorAction SilentlyContinue) {
            Show-Progress -Activity "Azure Scan" -Status "Checking Security Center..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Fetching Azure Security Center recommendations..." -Level "INFO"
            az security assessment list --subscription $SubscriptionId --output json | Out-File "$azureDir\security_center.json"
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Security Center recommendations retrieved" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        Write-Log "Azure security scan completed" -Level "SUCCESS"
        $Global:Statistics.SuccessfulScans++
        
    } catch {
        Write-Log "Azure scan error: $_" -Level "ERROR"
        $Global:Statistics.FailedScans++
    }
}

# Enhanced GCP scanning
function Start-GCPScan {
    param([string]$Project)
    
    Write-Log "Starting GCP security scan for project: $Project" -Level "INFO"
    $gcpDir = "$Global:ScanDir\GCP"
    $toolsRun = 0
    $toolsTotal = 4
    
    try {
        # Forseti Security
        if (Test-Tool "C:\Tools\Additional\Forseti\forseti.py" "Forseti") {
            Show-Progress -Activity "GCP Scan" -Status "Running Forseti..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running Forseti for GCP..." -Level "INFO"
            python "C:\Tools\Additional\Forseti\forseti.py" scanner run --output-path "$gcpDir\forseti" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Forseti scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # ScoutSuite for GCP
        if (Test-Tool "C:\Tools\Additional\ScoutSuite\scout.py" "ScoutSuite") {
            Show-Progress -Activity "GCP Scan" -Status "Running ScoutSuite..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running ScoutSuite for GCP..." -Level "INFO"
            python "C:\Tools\Additional\ScoutSuite\scout.py" gcp --project-id $Project --report-dir "$gcpDir\scoutsuite" --no-browser 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "ScoutSuite scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # CloudSploit for GCP
        if (Test-Tool "C:\Tools\Additional\CloudSploit\index.js" "CloudSploit") {
            Show-Progress -Activity "GCP Scan" -Status "Running CloudSploit..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running CloudSploit for GCP..." -Level "INFO"
            node "C:\Tools\Additional\CloudSploit\index.js" --cloud gcp --project $Project --json "$gcpDir\cloudsploit.json" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "CloudSploit scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # GCP Security Command Center (if gcloud CLI available)
        if (Get-Command gcloud -ErrorAction SilentlyContinue) {
            Show-Progress -Activity "GCP Scan" -Status "Checking Security Command Center..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Fetching GCP Security Command Center findings..." -Level "INFO"
            gcloud scc findings list --project=$Project --format=json | Out-File "$gcpDir\scc_findings.json"
            if ($LASTEXITCODE -eq 0) {
                Write-Log "SCC findings retrieved" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        Write-Log "GCP security scan completed" -Level "SUCCESS"
        $Global:Statistics.SuccessfulScans++
        
    } catch {
        Write-Log "GCP scan error: $_" -Level "ERROR"
        $Global:Statistics.FailedScans++
    }
}

# Enhanced container scanning
function Start-ContainerScan {
    param([string]$Image)
    
    Write-Log "Starting container security scan for: $Image" -Level "INFO"
    $containerDir = "$Global:ScanDir\Container"
    $toolsRun = 0
    $toolsTotal = 5
    
    try {
        # Trivy - Vulnerability scanner
        if (Test-Tool "C:\Tools\Additional\Trivy\trivy.exe" "Trivy") {
            Show-Progress -Activity "Container Scan" -Status "Running Trivy..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running Trivy on $Image..." -Level "INFO"
            & "C:\Tools\Additional\Trivy\trivy.exe" image --format json --output "$containerDir\trivy.json" --severity HIGH,CRITICAL $Image 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Trivy scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # Grype - Vulnerability scanner
        if (Test-Tool "C:\Tools\Additional\Grype\grype.exe" "Grype") {
            Show-Progress -Activity "Container Scan" -Status "Running Grype..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running Grype on $Image..." -Level "INFO"
            & "C:\Tools\Additional\Grype\grype.exe" $Image --output json --file "$containerDir\grype.json" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Grype scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # Clair
        if (Test-Tool "C:\Tools\Additional\Clair\clair-scanner.exe" "Clair") {
            Show-Progress -Activity "Container Scan" -Status "Running Clair..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running Clair on $Image..." -Level "INFO"
            & "C:\Tools\Additional\Clair\clair-scanner.exe" --report "$containerDir\clair.json" $Image 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Clair scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # Anchore
        if (Test-Tool "C:\Tools\Additional\Anchore\syft.exe" "Syft") {
            Show-Progress -Activity "Container Scan" -Status "Running Syft..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running Syft on $Image..." -Level "INFO"
            & "C:\Tools\Additional\Anchore\syft.exe" $Image --output json --file "$containerDir\syft.json" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Syft scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # Docker Bench Security (if available)
        if (Test-Tool "C:\Tools\Additional\DockerBench\docker-bench-security.sh" "Docker Bench") {
            Show-Progress -Activity "Container Scan" -Status "Running Docker Bench..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running Docker Bench Security..." -Level "INFO"
            bash "C:\Tools\Additional\DockerBench\docker-bench-security.sh" -l "$containerDir\docker_bench.log" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Docker Bench scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        Write-Log "Container security scan completed" -Level "SUCCESS"
        $Global:Statistics.SuccessfulScans++
        
    } catch {
        Write-Log "Container scan error: $_" -Level "ERROR"
        $Global:Statistics.FailedScans++
    }
}

# Enhanced Kubernetes scanning
function Start-KubernetesScan {
    param([string]$ConfigPath)
    
    Write-Log "Starting Kubernetes security scan" -Level "INFO"
    $k8sDir = "$Global:ScanDir\Kubernetes"
    $toolsRun = 0
    $toolsTotal = 6
    
    try {
        # Set KUBECONFIG if provided
        if ($ConfigPath) {
            $env:KUBECONFIG = $ConfigPath
        }
        
        # kube-bench - CIS Kubernetes Benchmark
        if (Test-Tool "C:\Tools\Additional\kube-bench\kube-bench.exe" "kube-bench") {
            Show-Progress -Activity "Kubernetes Scan" -Status "Running kube-bench..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running kube-bench..." -Level "INFO"
            & "C:\Tools\Additional\kube-bench\kube-bench.exe" --benchmark cis-1.8 --json --outputfile "$k8sDir\kube-bench.json" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "kube-bench scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # kube-hunter - Security weaknesses
        if (Test-Tool "C:\Tools\Additional\kube-hunter\kube-hunter.py" "kube-hunter") {
            Show-Progress -Activity "Kubernetes Scan" -Status "Running kube-hunter..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running kube-hunter..." -Level "INFO"
            python "C:\Tools\Additional\kube-hunter\kube-hunter.py" --report json --output "$k8sDir\kube-hunter.json" --remote 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "kube-hunter scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # kubeaudit - Audit Kubernetes clusters
        if (Test-Tool "C:\Tools\Additional\kubeaudit\kubeaudit.exe" "kubeaudit") {
            Show-Progress -Activity "Kubernetes Scan" -Status "Running kubeaudit..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running kubeaudit..." -Level "INFO"
            & "C:\Tools\Additional\kubeaudit\kubeaudit.exe" all --format json --output "$k8sDir\kubeaudit.json" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "kubeaudit scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # kubesec - Security risk analysis
        if (Test-Tool "C:\Tools\Additional\kubesec\kubesec.exe" "kubesec") {
            Show-Progress -Activity "Kubernetes Scan" -Status "Running kubesec..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running kubesec..." -Level "INFO"
            & "C:\Tools\Additional\kubesec\kubesec.exe" scan --output json > "$k8sDir\kubesec.json" 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "kubesec scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # Polaris - Best practices validation
        if (Test-Tool "C:\Tools\Additional\Polaris\polaris.exe" "Polaris") {
            Show-Progress -Activity "Kubernetes Scan" -Status "Running Polaris..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running Polaris..." -Level "INFO"
            & "C:\Tools\Additional\Polaris\polaris.exe" audit --format json --output-file "$k8sDir\polaris.json" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Polaris scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # Falco - Runtime security (if available)
        if (Test-Tool "C:\Tools\Additional\Falco\falco.exe" "Falco") {
            Show-Progress -Activity "Kubernetes Scan" -Status "Running Falco..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running Falco..." -Level "INFO"
            & "C:\Tools\Additional\Falco\falco.exe" --output json --output-file "$k8sDir\falco.json" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Falco scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        Write-Log "Kubernetes security scan completed" -Level "SUCCESS"
        $Global:Statistics.SuccessfulScans++
        
    } catch {
        Write-Log "Kubernetes scan error: $_" -Level "ERROR"
        $Global:Statistics.FailedScans++
    }
}

# Enhanced Infrastructure as Code scanning
function Start-InfrastructureScan {
    param([string]$IaCDir)
    
    Write-Log "Starting Infrastructure as Code security scan" -Level "INFO"
    $iacDir = "$Global:ScanDir\Infrastructure"
    $toolsRun = 0
    $toolsTotal = 5
    
    try {
        # tfsec - Terraform security scanner
        if (Test-Tool "C:\Tools\Additional\tfsec\tfsec.exe" "tfsec") {
            Show-Progress -Activity "IaC Scan" -Status "Running tfsec..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running tfsec on $IaCDir..." -Level "INFO"
            & "C:\Tools\Additional\tfsec\tfsec.exe" $IaCDir --format json --out "$iacDir\tfsec.json" --soft-fail 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1) {
                Write-Log "tfsec scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # Checkov - Multi-IaC scanner
        if (Test-Tool "C:\Tools\Additional\Checkov\checkov.exe" "Checkov") {
            Show-Progress -Activity "IaC Scan" -Status "Running Checkov..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running Checkov on $IaCDir..." -Level "INFO"
            & "C:\Tools\Additional\Checkov\checkov.exe" -d $IaCDir --output json --output-file-path $iacDir --soft-fail 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1) {
                Write-Log "Checkov scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # Terrascan - IaC scanner
        if (Test-Tool "C:\Tools\Additional\Terrascan\terrascan.exe" "Terrascan") {
            Show-Progress -Activity "IaC Scan" -Status "Running Terrascan..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running Terrascan on $IaCDir..." -Level "INFO"
            & "C:\Tools\Additional\Terrascan\terrascan.exe" scan -d $IaCDir -o json > "$iacDir\terrascan.json" 2>&1
            if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3) {
                Write-Log "Terrascan scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # KICS - Keeping Infrastructure as Code Secure
        if (Test-Tool "C:\Tools\Additional\KICS\kics.exe" "KICS") {
            Show-Progress -Activity "IaC Scan" -Status "Running KICS..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running KICS on $IaCDir..." -Level "INFO"
            & "C:\Tools\Additional\KICS\kics.exe" scan -p $IaCDir --report-formats json --output-path $iacDir 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "KICS scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        # Snyk IaC (if available)
        if (Test-Tool "C:\Tools\Additional\Snyk\snyk.exe" "Snyk") {
            Show-Progress -Activity "IaC Scan" -Status "Running Snyk IaC..." -PercentComplete (($toolsRun/$toolsTotal)*100)
            Write-Log "Running Snyk IaC on $IaCDir..." -Level "INFO"
            & "C:\Tools\Additional\Snyk\snyk.exe" iac test $IaCDir --json --json-file-output="$iacDir\snyk.json" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1) {
                Write-Log "Snyk IaC scan completed" -Level "SUCCESS"
            }
            $toolsRun++
        }
        
        Write-Log "Infrastructure security scan completed" -Level "SUCCESS"
        $Global:Statistics.SuccessfulScans++
        
    } catch {
        Write-Log "Infrastructure scan error: $_" -Level "ERROR"
        $Global:Statistics.FailedScans++
    }
}

# Parse results helper
function Parse-ScoutSuiteResults {
    param([string]$ResultPath)
    
    try {
        $findingsFile = Get-ChildItem -Path $ResultPath -Filter "scoutsuite-results*.js" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($findingsFile) {
            Write-Log "Parsing ScoutSuite results..." -Level "DEBUG"
            # Parse and process findings
        }
    } catch {
        Write-Log "Error parsing ScoutSuite results: $_" -Level "WARNING"
    }
}

# Compliance checks
function Invoke-ComplianceChecks {
    Write-Log "Running compliance checks..." -Level "INFO"
    
    $complianceResults = @{
        CIS = @()
        NIST = @()
        PCIDSS = @()
        HIPAA = @()
        GDPR = @()
    }
    
    # Process findings against compliance frameworks
    foreach ($finding in $Global:Findings) {
        # Map findings to compliance controls
        # This is a simplified example
        if ($finding.Category -match "encryption|data-protection") {
            $complianceResults.PCIDSS += $finding
            $complianceResults.HIPAA += $finding
            $complianceResults.GDPR += $finding
        }
    }
    
    $complianceResults | ConvertTo-Json -Depth 10 | Out-File "$Global:ScanDir\Reports\compliance.json"
    Write-Log "Compliance checks completed" -Level "SUCCESS"
}

# Generate comprehensive report
function Generate-CloudReport {
    Write-Log "Generating comprehensive security report..." -Level "INFO"
    
    $endTime = Get-Date
    $duration = $endTime - $Global:ScanStartTime
    
    # Generate HTML report
    $htmlReport = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DarkWin Cloud Security Report - $Global:Timestamp</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%);
            color: #00ff00;
            padding: 20px;
            line-height: 1.6;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        h1, h2, h3 { color: #00ff00; margin: 20px 0 10px 0; text-shadow: 0 0 10px #00ff00; }
        h1 { font-size: 2.5em; border-bottom: 2px solid #00ff00; padding-bottom: 10px; }
        .header {
            background: rgba(0, 255, 0, 0.1);
            border: 1px solid #00ff00;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
        }
        .section {
            background: rgba(0, 255, 0, 0.05);
            border: 1px solid #333;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            transition: all 0.3s;
        }
        .section:hover {
            border-color: #00ff00;
            box-shadow: 0 0 15px rgba(0, 255, 0, 0.2);
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: rgba(0, 255, 0, 0.1);
            border: 1px solid #00ff00;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            transition: transform 0.3s;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-value {
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }
        .stat-label {
            font-size: 1.1em;
            opacity: 0.8;
        }
        .finding {
            background: rgba(42, 42, 42, 0.8);
            border-left: 4px solid #00ff00;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .critical { border-left-color: #ff0000; color: #ff6666; }
        .high { border-left-color: #ff6600; color: #ff9966; }
        .medium { border-left-color: #ffff00; color: #ffff99; }
        .low { border-left-color: #00ff00; color: #99ff99; }
        .info { border-left-color: #00ccff; color: #99ddff; }
        pre {
            background: #1a1a1a;
            border: 1px solid #333;
            padding: 15px;
            overflow-x: auto;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border: 1px solid #333;
        }
        th {
            background: rgba(0, 255, 0, 0.2);
            font-weight: bold;
        }
        tr:hover { background: rgba(0, 255, 0, 0.05); }
        .footer {
            margin-top: 50px;
            padding: 20px;
            text-align: center;
            border-top: 1px solid #333;
            opacity: 0.7;
        }
        .badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            margin: 5px;
            font-size: 0.9em;
        }
        .badge-critical { background: #ff0000; color: white; }
        .badge-high { background: #ff6600; color: white; }
        .badge-medium { background: #ffff00; color: black; }
        .badge-low { background: #00ff00; color: black; }
        .progress-bar {
            width: 100%;
            height: 30px;
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 15px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #00ff00, #00cc00);
            transition: width 0.3s;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ DarkWin Cloud Security Report v2.0</h1>
            <p style="font-size: 1.2em; margin-top: 10px;">Scan ID: $Global:Timestamp</p>
        </div>

        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="grid">
                <div class="stat-card">
                    <div class="stat-value" style="color: #ff6666;">$($Global:Statistics.CriticalFindings)</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #ff9966;">$($Global:Statistics.HighFindings)</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #ffff99;">$($Global:Statistics.MediumFindings)</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #99ff99;">$($Global:Statistics.LowFindings)</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>ℹ️ Scan Information</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Cloud Provider</td><td>$Provider</td></tr>
                <tr><td>Region/Subscription</td><td>$Region</td></tr>
                <tr><td>Start Time</td><td>$($Global:ScanStartTime.ToString("yyyy-MM-dd HH:mm:ss"))</td></tr>
                <tr><td>End Time</td><td>$($endTime.ToString("yyyy-MM-dd HH:mm:ss"))</td></tr>
                <tr><td>Duration</td><td>$($duration.ToString("hh\:mm\:ss"))</td></tr>
                <tr><td>Hostname</td><td>$env:COMPUTERNAME</td></tr>
                <tr><td>User</td><td>$env:USERNAME</td></tr>
                <tr><td>Total Scans</td><td>$($Global:Statistics.TotalScans)</td></tr>
                <tr><td>Successful Scans</td><td>$($Global:Statistics.SuccessfulScans)</td></tr>
                <tr><td>Failed Scans</td><td>$($Global:Statistics.FailedScans)</td></tr>
            </table>
        </div>

        <div class="section">
            <h2>🔍 Scan Results</h2>
            <p>Detailed results are available in JSON, XML, and CSV formats in the output directory.</p>
            <p><strong>Output Directory:</strong> $Global:ScanDir</p>
        </div>

        <div class="section">
            <h2>💡 Recommendations</h2>
            <div class="finding medium">
                <h3>Immediate Actions Required</h3>
                <ul>
                    <li>Review and remediate all CRITICAL findings immediately</li>
                    <li>Implement missing encryption controls</li>
                    <li>Update security group rules</li>
                    <li>Enable logging and monitoring</li>
                </ul>
            </div>
            <div class="finding low">
                <h3>Best Practices</h3>
                <ul>
                    <li>Regular security scanning schedule (weekly recommended)</li>
                    <li>Implement automated remediation workflows</li>
                    <li>Enable continuous compliance monitoring</li>
                    <li>Regular security training for team members</li>
                </ul>
            </div>
        </div>

        <div class="footer">
            <p>DarkWin Cloud Security v2.0 | Generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p>⚠️ This report contains sensitive security information. Handle with care.</p>
        </div>
    </div>
</body>
</html>
"@
    
    $htmlReport | Out-File "$Global:ScanDir\Reports\report.html" -Encoding UTF8
    Write-Log "HTML report generated: $Global:ScanDir\Reports\report.html" -Level "SUCCESS"
    
    # Generate JSON report
    $jsonReport = @{
        Metadata = @{
            Version = "2.0"
            ScanID = $Global:Timestamp
            Provider = $Provider
            Region = $Region
            StartTime = $Global:ScanStartTime.ToString("yyyy-MM-dd HH:mm:ss")
            EndTime = $endTime.ToString("yyyy-MM-dd HH:mm:ss")
            Duration = $duration.ToString()
        }
        Statistics = $Global:Statistics
        Findings = $Global:Findings
    }
    $jsonReport | ConvertTo-Json -Depth 10 | Out-File "$Global:ScanDir\Reports\report.json"
    Write-Log "JSON report generated" -Level "SUCCESS"
    
    # Generate CSV report
    if ($Global:Findings.Count -gt 0) {
        $Global:Findings | Export-Csv -Path "$Global:ScanDir\Reports\findings.csv" -NoTypeInformation
        Write-Log "CSV report generated" -Level "SUCCESS"
    }
    
    # Generate XML report
    $xmlReport = $jsonReport | ConvertTo-Xml -As String -Depth 10
    $xmlReport | Out-File "$Global:ScanDir\Reports\report.xml"
    Write-Log "XML report generated" -Level "SUCCESS"
}

# Send results to webhook
function Send-ToWebhook {
    param([string]$WebhookURL)
    
    if (-not $WebhookURL) { return }
    
    Write-Log "Sending results to webhook..." -Level "INFO"
    
    try {
        $payload = @{
            scan_id = $Global:Timestamp
            provider = $Provider
            region = $Region
            statistics = $Global:Statistics
            report_url = "$Global:ScanDir\Reports\report.html"
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri $WebhookURL -Method Post -Body $payload -ContentType "application/json"
        Write-Log "Results sent to webhook successfully" -Level "SUCCESS"
    } catch {
        Write-Log "Failed to send results to webhook: $_" -Level "ERROR"
    }
}

# Main execution
try {
    Initialize-CloudScan
    
    $Global:Statistics.TotalScans = 0
    
    # Run provider-specific scans
    switch ($Provider.ToUpper()) {
        "AWS" {
            Start-AWSScan -Region $Region
            $Global:Statistics.TotalScans++
        }
        "AZURE" {
            Start-AzureScan -SubscriptionId $Region
            $Global:Statistics.TotalScans++
        }
        "GCP" {
            Start-GCPScan -Project $Region
            $Global:Statistics.TotalScans++
        }
        "MULTI" {
            if ($ParallelScan) {
                Write-Log "Running parallel multi-cloud scan..." -Level "INFO"
                $jobs = @()
                $jobs += Start-Job -ScriptBlock { param($r) Start-AWSScan -Region $r } -ArgumentList $Region
                $jobs += Start-Job -ScriptBlock { param($s) Start-AzureScan -SubscriptionId $s } -ArgumentList $Region
                $jobs += Start-Job -ScriptBlock { param($p) Start-GCPScan -Project $p } -ArgumentList $Region
                $jobs | Wait-Job | Receive-Job
                $jobs | Remove-Job
            } else {
                Start-AWSScan -Region $Region
                Start-AzureScan -SubscriptionId $Region
                Start-GCPScan -Project $Region
            }
            $Global:Statistics.TotalScans += 3
        }
        default {
            Write-Log "Unsupported cloud provider: $Provider" -Level "ERROR"
            exit 1
        }
    }
    
    # Run additional scans if parameters provided
    if ($Image) {
        Start-ContainerScan -Image $Image
        $Global:Statistics.TotalScans++
    }
    
    if ($KubeConfig) {
        Start-KubernetesScan -ConfigPath $KubeConfig
        $Global:Statistics.TotalScans++
    }
    
    if ($TerraformDir) {
        Start-InfrastructureScan -IaCDir $TerraformDir
        $Global:Statistics.TotalScans++
    }
    
    # Run compliance checks if requested
    if ($ComplianceCheck) {
        Invoke-ComplianceChecks
    }
    
    # Generate comprehensive reports
    Generate-CloudReport
    
    # Send to webhook if configured
    if ($WebhookURL) {
        Send-ToWebhook -WebhookURL $WebhookURL
    }
    
    # Final summary
    Write-Log "=" * 80 -Level "INFO"
    Write-Log "Cloud Security Scan Summary" -Level "SUCCESS"
    Write-Log "=" * 80 -Level "INFO"
    Write-Log "Total Scans: $($Global:Statistics.TotalScans)" -Level "INFO"
    Write-Log "Successful: $($Global:Statistics.SuccessfulScans)" -Level "SUCCESS"
    Write-Log "Failed: $($Global:Statistics.FailedScans)" -Level $(if ($Global:Statistics.FailedScans -gt 0) { "WARNING" } else { "INFO" })
    Write-Log "Critical Findings: $($Global:Statistics.CriticalFindings)" -Level $(if ($Global:Statistics.CriticalFindings -gt 0) { "ERROR" } else { "INFO" })
    Write-Log "High Findings: $($Global:Statistics.HighFindings)" -Level $(if ($Global:Statistics.HighFindings -gt 0) { "WARNING" } else { "INFO" })
    Write-Log "Reports Location: $Global:ScanDir\Reports" -Level "INFO"
    Write-Log "=" * 80 -Level "INFO"
    Write-Log "Cloud security scan completed successfully!" -Level "SUCCESS"
    
} catch {
    Write-Log "CRITICAL ERROR: Cloud security scan failed - $_" -Level "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    exit 1
}
