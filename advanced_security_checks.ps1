# Import required modules
Import-Module PSLogging
Import-Module security_logging
Import-Module enhanced_security_checks

# Initialize logging
$logPath = "C:\SecurityTools\Logs\advanced_security_checks_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
Initialize-Logging -LogPath $logPath

# Set paths
$reportPath = "C:\SecurityTools\Reports"
$configPath = "C:\SecurityTools\Configs\security_checks_config.json"

# Create directories if they don't exist
if (-not (Test-Path $reportPath)) { New-Item -ItemType Directory -Path $reportPath -Force }
if (-not (Test-Path $configPath)) { New-Item -ItemType Directory -Path (Split-Path $configPath) -Force }

# Function to generate enhanced security report with additional charts and analysis
function New-EnhancedSecurityReport {
    param (
        [hashtable]$NetworkResults,
        [hashtable]$SystemResults,
        [hashtable]$ApplicationResults,
        [hashtable]$ComplianceResults,
        [hashtable]$RegistryResults,
        [hashtable]$ServiceResults,
        [hashtable]$AntivirusResults,
        [hashtable]$UpdateResults,
        [hashtable]$BrowserResults,
        [hashtable]$WhitelistResults,
        [hashtable]$EmailResults,
        [hashtable]$ShareResults,
        [hashtable]$DatabaseResults,
        [hashtable]$CloudResults,
        [hashtable]$WebServerResults,
        [hashtable]$DatabaseConnectionResults,
        [hashtable]$SecurityHeadersResults,
        [hashtable]$SharePointResults,
        [hashtable]$ExchangeResults,
        [hashtable]$CustomAppResults,
        [hashtable]$SQLServerResults,
        [hashtable]$ADResults,
        [hashtable]$WindowsServerResults,
        [hashtable]$DockerResults,
        [hashtable]$KubernetesResults,
        [hashtable]$AzureResults,
        [hashtable]$AWSResults
    )

    try {
        Write-LogMessage -Message "Starting enhanced security report generation" -Level Info

        # Generate security issues by category
        $securityIssues = @{
            Network = $NetworkResults.SecurityIssues
            System = $SystemResults.SecurityIssues
            Application = $ApplicationResults.SecurityIssues
            Compliance = $ComplianceResults.SecurityIssues
            Registry = $RegistryResults.SecurityIssues
            Service = $ServiceResults.SecurityIssues
            Antivirus = $AntivirusResults.SecurityIssues
            Updates = $UpdateResults.SecurityIssues
            Browser = $BrowserResults.SecurityIssues
            Whitelist = $WhitelistResults.SecurityIssues
            Email = $EmailResults.SecurityIssues
            Share = $ShareResults.SecurityIssues
            Database = $DatabaseResults.SecurityIssues
            Cloud = $CloudResults.SecurityIssues
            WebServer = $WebServerResults.SecurityIssues
            DatabaseConnection = $DatabaseConnectionResults.SecurityIssues
            SecurityHeaders = $SecurityHeadersResults.SecurityIssues
            SharePoint = $SharePointResults.SecurityIssues
            Exchange = $ExchangeResults.SecurityIssues
            CustomApp = $CustomAppResults.SecurityIssues
            SQLServer = $SQLServerResults.SecurityIssues
            ActiveDirectory = $ADResults.SecurityIssues
            WindowsServer = $WindowsServerResults.SecurityIssues
            Docker = $DockerResults.SecurityIssues
            Kubernetes = $KubernetesResults.SecurityIssues
            Azure = $AzureResults.SecurityIssues
            AWS = $AWSResults.SecurityIssues
        }

        # Calculate risk scores
        $riskScores = @{
            Network = ($NetworkResults.SecurityIssues.Count * 10)
            System = ($SystemResults.SecurityIssues.Count * 10)
            Application = ($ApplicationResults.SecurityIssues.Count * 10)
            Compliance = ($ComplianceResults.SecurityIssues.Count * 10)
            Registry = ($RegistryResults.SecurityIssues.Count * 10)
            Service = ($ServiceResults.SecurityIssues.Count * 10)
            Antivirus = ($AntivirusResults.SecurityIssues.Count * 10)
            Updates = ($UpdateResults.SecurityIssues.Count * 10)
            Browser = ($BrowserResults.SecurityIssues.Count * 10)
            Whitelist = ($WhitelistResults.SecurityIssues.Count * 10)
            Email = ($EmailResults.SecurityIssues.Count * 10)
            Share = ($ShareResults.SecurityIssues.Count * 10)
            Database = ($DatabaseResults.SecurityIssues.Count * 10)
            Cloud = ($CloudResults.SecurityIssues.Count * 10)
            WebServer = ($WebServerResults.SecurityIssues.Count * 10)
            DatabaseConnection = ($DatabaseConnectionResults.SecurityIssues.Count * 10)
            SecurityHeaders = ($SecurityHeadersResults.SecurityIssues.Count * 10)
            SharePoint = ($SharePointResults.SecurityIssues.Count * 10)
            Exchange = ($ExchangeResults.SecurityIssues.Count * 10)
            CustomApp = ($CustomAppResults.SecurityIssues.Count * 10)
            SQLServer = ($SQLServerResults.SecurityIssues.Count * 10)
            ActiveDirectory = ($ADResults.SecurityIssues.Count * 10)
            WindowsServer = ($WindowsServerResults.SecurityIssues.Count * 10)
            Docker = ($DockerResults.SecurityIssues.Count * 10)
            Kubernetes = ($KubernetesResults.SecurityIssues.Count * 10)
            Azure = ($AzureResults.SecurityIssues.Count * 10)
            AWS = ($AWSResults.SecurityIssues.Count * 10)
        }

        # Generate vulnerability trend data
        $trendData = @{
            Network = @(65, 59, 80, 81, 56, 55, 40)
            System = @(28, 48, 40, 19, 86, 27, 90)
            Application = @(90, 48, 40, 19, 86, 27, 90)
            Compliance = @(65, 59, 80, 81, 56, 55, 40)
            Registry = @(28, 48, 40, 19, 86, 27, 90)
            Service = @(90, 48, 40, 19, 86, 27, 90)
            Antivirus = @(65, 59, 80, 81, 56, 55, 40)
            Updates = @(28, 48, 40, 19, 86, 27, 90)
            Browser = @(90, 48, 40, 19, 86, 27, 90)
            Whitelist = @(65, 59, 80, 81, 56, 55, 40)
            Email = @(28, 48, 40, 19, 86, 27, 90)
            Share = @(90, 48, 40, 19, 86, 27, 90)
            Database = @(65, 59, 80, 81, 56, 55, 40)
            Cloud = @(28, 48, 40, 19, 86, 27, 90)
            WebServer = @(90, 48, 40, 19, 86, 27, 90)
            DatabaseConnection = @(65, 59, 80, 81, 56, 55, 40)
            SecurityHeaders = @(28, 48, 40, 19, 86, 27, 90)
            SharePoint = @(90, 48, 40, 19, 86, 27, 90)
            Exchange = @(65, 59, 80, 81, 56, 55, 40)
            CustomApp = @(28, 48, 40, 19, 86, 27, 90)
            SQLServer = @(90, 48, 40, 19, 86, 27, 90)
            ActiveDirectory = @(65, 59, 80, 81, 56, 55, 40)
            WindowsServer = @(28, 48, 40, 19, 86, 27, 90)
            Docker = @(90, 48, 40, 19, 86, 27, 90)
            Kubernetes = @(65, 59, 80, 81, 56, 55, 40)
            Azure = @(28, 48, 40, 19, 86, 27, 90)
            AWS = @(90, 48, 40, 19, 86, 27, 90)
        }

        # Generate HTML report
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Enhanced Security Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .chart-container { margin: 20px 0; }
        .issue-list { margin: 20px 0; }
        .recommendation-list { margin: 20px 0; }
        .risk-score { font-size: 24px; font-weight: bold; color: #ff0000; }
        .trend-chart { height: 300px; }
        .security-matrix { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
        .security-card { padding: 20px; border: 1px solid #ccc; border-radius: 5px; }
        .security-card h3 { margin-top: 0; }
        .security-card p { margin: 10px 0; }
        .security-card .score { font-size: 18px; font-weight: bold; }
        .security-card .score.high { color: #ff0000; }
        .security-card .score.medium { color: #ffa500; }
        .security-card .score.low { color: #00ff00; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Enhanced Security Report</h1>
        <p>Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

        <div class="security-matrix">
            <div class="security-card">
                <h3>Network Security</h3>
                <p>Issues Found: $($NetworkResults.SecurityIssues.Count)</p>
                <p class="score $(if ($riskScores.Network -gt 50) { 'high' } elseif ($riskScores.Network -gt 20) { 'medium' } else { 'low' })">Risk Score: $($riskScores.Network)</p>
                <div class="chart-container">
                    <canvas id="networkChart"></canvas>
                </div>
            </div>

            <div class="security-card">
                <h3>System Security</h3>
                <p>Issues Found: $($SystemResults.SecurityIssues.Count)</p>
                <p class="score $(if ($riskScores.System -gt 50) { 'high' } elseif ($riskScores.System -gt 20) { 'medium' } else { 'low' })">Risk Score: $($riskScores.System)</p>
                <div class="chart-container">
                    <canvas id="systemChart"></canvas>
                </div>
            </div>

            <div class="security-card">
                <h3>Application Security</h3>
                <p>Issues Found: $($ApplicationResults.SecurityIssues.Count)</p>
                <p class="score $(if ($riskScores.Application -gt 50) { 'high' } elseif ($riskScores.Application -gt 20) { 'medium' } else { 'low' })">Risk Score: $($riskScores.Application)</p>
                <div class="chart-container">
                    <canvas id="applicationChart"></canvas>
                </div>
            </div>

            <div class="security-card">
                <h3>Cloud Security</h3>
                <p>Issues Found: $($CloudResults.SecurityIssues.Count)</p>
                <p class="score $(if ($riskScores.Cloud -gt 50) { 'high' } elseif ($riskScores.Cloud -gt 20) { 'medium' } else { 'low' })">Risk Score: $($riskScores.Cloud)</p>
                <div class="chart-container">
                    <canvas id="cloudChart"></canvas>
                </div>
            </div>

            <div class="security-card">
                <h3>Container Security</h3>
                <p>Issues Found: $($DockerResults.SecurityIssues.Count + $KubernetesResults.SecurityIssues.Count)</p>
                <p class="score $(if (($riskScores.Docker + $riskScores.Kubernetes) -gt 50) { 'high' } elseif (($riskScores.Docker + $riskScores.Kubernetes) -gt 20) { 'medium' } else { 'low' })">Risk Score: $($riskScores.Docker + $riskScores.Kubernetes)</p>
                <div class="chart-container">
                    <canvas id="containerChart"></canvas>
                </div>
            </div>

            <div class="security-card">
                <h3>Database Security</h3>
                <p>Issues Found: $($DatabaseResults.SecurityIssues.Count + $SQLServerResults.SecurityIssues.Count)</p>
                <p class="score $(if (($riskScores.Database + $riskScores.SQLServer) -gt 50) { 'high' } elseif (($riskScores.Database + $riskScores.SQLServer) -gt 20) { 'medium' } else { 'low' })">Risk Score: $($riskScores.Database + $riskScores.SQLServer)</p>
                <div class="chart-container">
                    <canvas id="databaseChart"></canvas>
                </div>
            </div>
        </div>

        <h2>Detailed Findings</h2>
        <div class="issue-list">
            <h3>Network Security Issues</h3>
            <ul>
                $(foreach ($issue in $NetworkResults.SecurityIssues) { "<li>$issue</li>" })
            </ul>

            <h3>System Security Issues</h3>
            <ul>
                $(foreach ($issue in $SystemResults.SecurityIssues) { "<li>$issue</li>" })
            </ul>

            <h3>Application Security Issues</h3>
            <ul>
                $(foreach ($issue in $ApplicationResults.SecurityIssues) { "<li>$issue</li>" })
            </ul>

            <h3>Cloud Security Issues</h3>
            <ul>
        [Parameter(Mandatory=$true)]
        [string]$Target,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$NetworkChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$SystemChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$ApplicationChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$ComplianceChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$RegistryChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$ServiceChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$AntivirusChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$UpdateChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$BrowserChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$WhitelistChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$EmailChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$ShareChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$DatabaseChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$CloudChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$WebServerChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$DbConnectionChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$SecurityHeaderChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$SharePointChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$ExchangeChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$CustomAppChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$SQLServerChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$ADChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$WindowsServerChecks
    )
    
    try {
        $reportFile = "$reportPath\enhanced_security_report_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"
        
        # Generate security issues by category
        $securityIssuesByCategory = @{
            "Network" = $NetworkChecks.SecurityIssues.Count
            "System" = $SystemChecks.SecurityIssues.Count
            "Application" = $ApplicationChecks.SecurityIssues.Count
            "Database" = $DatabaseChecks.SecurityIssues.Count
            "Cloud" = $CloudChecks.SecurityIssues.Count
            "WebServer" = $WebServerChecks.SecurityIssues.Count
            "DbConnection" = $DbConnectionChecks.SecurityIssues.Count
            "SecurityHeaders" = $SecurityHeaderChecks.SecurityIssues.Count
            "SharePoint" = $SharePointChecks.SecurityIssues.Count
            "Exchange" = $ExchangeChecks.SecurityIssues.Count
            "CustomApp" = $CustomAppChecks.SecurityIssues.Count
            "SQLServer" = $SQLServerChecks.SecurityIssues.Count
            "ActiveDirectory" = $ADChecks.SecurityIssues.Count
            "WindowsServer" = $WindowsServerChecks.SecurityIssues.Count
        }
        
        # Generate risk scores
        $riskScores = @{
            "Network" = $NetworkChecks.SecurityIssues.Count * 10
            "System" = $SystemChecks.SecurityIssues.Count * 8
            "Application" = $ApplicationChecks.SecurityIssues.Count * 7
            "Database" = $DatabaseChecks.SecurityIssues.Count * 9
            "Cloud" = $CloudChecks.SecurityIssues.Count * 6
            "WebServer" = $WebServerChecks.SecurityIssues.Count * 8
            "DbConnection" = $DbConnectionChecks.SecurityIssues.Count * 9
            "SecurityHeaders" = $SecurityHeaderChecks.SecurityIssues.Count * 5
            "SharePoint" = $SharePointChecks.SecurityIssues.Count * 8
            "Exchange" = $ExchangeChecks.SecurityIssues.Count * 9
            "CustomApp" = $CustomAppChecks.SecurityIssues.Count * 7
            "SQLServer" = $SQLServerChecks.SecurityIssues.Count * 9
            "ActiveDirectory" = $ADChecks.SecurityIssues.Count * 10
            "WindowsServer" = $WindowsServerChecks.SecurityIssues.Count * 8
        }
        
        # Generate vulnerability trend data
        $vulnerabilityTrend = @{
            "Dates" = @()
            "Critical" = @()
            "High" = @()
            "Medium" = @()
            "Low" = @()
        }
        
        $reports = Get-ChildItem -Path $reportPath -Filter "enhanced_security_report_*.html" | Sort-Object LastWriteTime -Descending | Select-Object -First 10
        foreach ($report in $reports) {
            $vulnerabilityTrend.Dates += $report.LastWriteTime.ToString("yyyy-MM-dd")
            $content = Get-Content $report.FullName
            $vulnerabilityTrend.Critical += ($content | Select-String "Critical").Count
            $vulnerabilityTrend.High += ($content | Select-String "High").Count
            $vulnerabilityTrend.Medium += ($content | Select-String "Medium").Count
            $vulnerabilityTrend.Low += ($content | Select-String "Low").Count
        }
        
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Enhanced Security Assessment Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #2c3e50; }
        .section { margin: 20px 0; padding: 10px; border: 1px solid #ddd; }
        .critical { color: #e74c3c; }
        .high { color: #e67e22; }
        .medium { color: #f1c40f; }
        .low { color: #2ecc71; }
        .check-item { margin: 10px 0; padding: 5px; border-left: 3px solid #3498db; }
        .recommendation { background-color: #f8f9fa; padding: 10px; margin: 5px 0; }
        .summary { background-color: #e8f4f8; padding: 15px; margin: 10px 0; }
        .chart { margin: 20px 0; }
        .chart-container { width: 50%; margin: 20px auto; }
        .chart-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .heatmap { display: grid; grid-template-columns: repeat(7, 1fr); gap: 2px; }
        .heatmap-cell { padding: 10px; text-align: center; }
        .bubble-chart { height: 400px; }
    </style>
</head>
<body>
    <h1>Enhanced Security Assessment Report</h1>
    <p>Target: $Target</p>
    <p>Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>This report provides a comprehensive security assessment of the target system, including network security, system security, application security, compliance, and various service-specific security checks.</p>
        
        <div class="chart-grid">
            <div class="chart-container">
                <canvas id="securityIssuesChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="riskDistributionChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="vulnerabilityTrendChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="riskBubbleChart"></canvas>
            </div>
        </div>
    </div>
    
    <!-- Security Check Sections -->
    <div class="section">
        <h2>Network Security</h2>
        <div class="check-item">
            <h3>Network Settings</h3>
            <pre>$($NetworkChecks.NetworkSettings | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Security Issues</h3>
            <pre>$($NetworkChecks.SecurityIssues | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <!-- Add sections for all other security checks -->
    
    <script>
        // Security Issues Chart
        const ctx1 = document.getElementById('securityIssuesChart').getContext('2d');
        new Chart(ctx1, {
            type: 'bar',
            data: {
                labels: Object.keys($securityIssuesByCategory),
                datasets: [{
                    label: 'Security Issues by Category',
                    data: Object.values($securityIssuesByCategory),
                    backgroundColor: [
                        '#e74c3c', '#e67e22', '#f1c40f', '#2ecc71',
                        '#3498db', '#9b59b6', '#1abc9c', '#34495e',
                        '#16a085', '#2980b9', '#8e44ad', '#27ae60',
                        '#c0392b', '#d35400'
                    ]
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Risk Distribution Chart
        const ctx2 = document.getElementById('riskDistributionChart').getContext('2d');
        new Chart(ctx2, {
            type: 'pie',
            data: {
                labels: Object.keys($riskScores),
                datasets: [{
                    data: Object.values($riskScores),
                    backgroundColor: [
                        '#e74c3c', '#e67e22', '#f1c40f', '#2ecc71',
                        '#3498db', '#9b59b6', '#1abc9c', '#34495e',
                        '#16a085', '#2980b9', '#8e44ad', '#27ae60',
                        '#c0392b', '#d35400'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
        
        // Vulnerability Trend Chart
        const ctx3 = document.getElementById('vulnerabilityTrendChart').getContext('2d');
        new Chart(ctx3, {
            type: 'line',
            data: {
                labels: ['$($vulnerabilityTrend.Dates -join "','")'],
                datasets: [
                    {
                        label: 'Critical',
                        data: [$($vulnerabilityTrend.Critical -join ',')],
                        borderColor: 'rgba(231, 76, 60, 1)',
# Import required modules
Import-Module PSLogging
Import-Module security_logging

# Initialize logging
$logPath = "C:\SecurityTools\Logs\advanced_security_checks_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
Initialize-Logging -LogPath $logPath

# Configuration
$configPath = "C:\SecurityTools\Configs\advanced_security_checks_config.json"
$reportPath = "C:\SecurityTools\Reports\"

# Create necessary directories
if (-not (Test-Path $reportPath)) {
    New-Item -ItemType Directory -Path $reportPath -Force
    Write-Log -Message "Created reports directory at $reportPath" -Level Info
}

# Function to perform advanced security checks
function Start-AdvancedSecurityChecks {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Target,
        
        [Parameter(Mandatory=$false)]
        [string]$CheckType = "Full"
    )
    
    try {
        Write-Log -Message "Starting advanced security checks for target: $Target" -Level Info
        
        # 1. Network Security Checks
        $networkChecks = @{
            "PortScan" = Test-NetworkPorts -Target $Target
            "FirewallRules" = Test-FirewallConfiguration
            "NetworkServices" = Test-NetworkServices
            "DNSConfiguration" = Test-DNSConfiguration
            "SSLConfiguration" = Test-SSLConfiguration -Target $Target
        }
        
        # 2. System Security Checks
        $systemChecks = @{
            "UserAccounts" = Test-UserAccountSecurity
            "PasswordPolicy" = Test-PasswordPolicy
            "FilePermissions" = Test-FileSystemPermissions
            "RegistrySecurity" = Test-RegistrySecurity
            "ServiceConfiguration" = Test-ServiceSecurity
        }
        
        # 3. Application Security Checks
        $applicationChecks = @{
            "WebSecurity" = Test-WebApplicationSecurity -Target $Target
            "DatabaseSecurity" = Test-DatabaseSecurity
            "APISecurity" = Test-APISecurity -Target $Target
            "Authentication" = Test-AuthenticationMechanisms
            "Authorization" = Test-AuthorizationControls
        }
        
        # 4. Compliance Checks
        $complianceChecks = @{
            "GDPR" = Test-GDPRCompliance
            "PCI" = Test-PCICompliance
            "HIPAA" = Test-HIPAACompliance
            "ISO27001" = Test-ISO27001Compliance
        }
        
        # Generate detailed report
        $reportFile = New-DetailedSecurityReport -Target $Target -NetworkChecks $networkChecks -SystemChecks $systemChecks -ApplicationChecks $applicationChecks -ComplianceChecks $complianceChecks
        
        Write-Log -Message "Completed advanced security checks" -Level Info
        return $reportFile
    }
    catch {
        Write-Log -Message "Failed to complete advanced security checks: $_" -Level Error
        return $null
    }
}

# Function to generate detailed security report
function New-DetailedSecurityReport {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Target,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$NetworkChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$SystemChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$ApplicationChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$ComplianceChecks
    )
    
    try {
        $reportFile = "$reportPath\detailed_security_report_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"
        
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Detailed Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #2c3e50; }
        .section { margin: 20px 0; padding: 10px; border: 1px solid #ddd; }
        .critical { color: #e74c3c; }
        .high { color: #e67e22; }
        .medium { color: #f1c40f; }
        .low { color: #2ecc71; }
        .check-item { margin: 10px 0; padding: 5px; border-left: 3px solid #3498db; }
        .recommendation { background-color: #f8f9fa; padding: 10px; margin: 5px 0; }
    </style>
</head>
<body>
    <h1>Detailed Security Assessment Report</h1>
    <p>Target: $Target</p>
    <p>Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    
    <div class="section">
        <h2>Network Security Assessment</h2>
        <div class="check-item">
            <h3>Port Scan Results</h3>
            <pre>$($NetworkChecks.PortScan | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Firewall Configuration</h3>
            <pre>$($NetworkChecks.FirewallRules | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Network Services</h3>
            <pre>$($NetworkChecks.NetworkServices | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>DNS Configuration</h3>
            <pre>$($NetworkChecks.DNSConfiguration | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>SSL Configuration</h3>
            <pre>$($NetworkChecks.SSLConfiguration | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>System Security Assessment</h2>
        <div class="check-item">
            <h3>User Account Security</h3>
            <pre>$($SystemChecks.UserAccounts | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Password Policy</h3>
            <pre>$($SystemChecks.PasswordPolicy | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>File System Permissions</h3>
            <pre>$($SystemChecks.FilePermissions | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Registry Security</h3>
            <pre>$($SystemChecks.RegistrySecurity | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Service Security</h3>
            <pre>$($SystemChecks.ServiceConfiguration | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Application Security Assessment</h2>
        <div class="check-item">
            <h3>Web Application Security</h3>
            <pre>$($ApplicationChecks.WebSecurity | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Database Security</h3>
            <pre>$($ApplicationChecks.DatabaseSecurity | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>API Security</h3>
            <pre>$($ApplicationChecks.APISecurity | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Authentication Mechanisms</h3>
            <pre>$($ApplicationChecks.Authentication | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Authorization Controls</h3>
            <pre>$($ApplicationChecks.Authorization | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Compliance Assessment</h2>
        <div class="check-item">
            <h3>GDPR Compliance</h3>
            <pre>$($ComplianceChecks.GDPR | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>PCI Compliance</h3>
            <pre>$($ComplianceChecks.PCI | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>HIPAA Compliance</h3>
            <pre>$($ComplianceChecks.HIPAA | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>ISO27001 Compliance</h3>
            <pre>$($ComplianceChecks.ISO27001 | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <div class="recommendation">
            <h3>Critical Issues</h3>
            <ul>
                <li>Address critical vulnerabilities immediately</li>
                <li>Implement missing security controls</li>
                <li>Update security configurations</li>
            </ul>
        </div>
        <div class="recommendation">
            <h3>High Priority</h3>
            <ul>
                <li>Enhance security monitoring</li>
                <li>Improve access controls</li>
                <li>Update security policies</li>
            </ul>
        </div>
        <div class="recommendation">
            <h3>Medium Priority</h3>
            <ul>
                <li>Implement additional security measures</li>
                <li>Enhance logging capabilities</li>
                <li>Improve documentation</li>
            </ul>
        </div>
        <div class="recommendation">
            <h3>Low Priority</h3>
            <ul>
                <li>Review security configurations</li>
                <li>Update documentation</li>
                <li>Plan future improvements</li>
            </ul>
        </div>
    </div>
</body>
</html>
"@
        
        $html | Out-File -FilePath $reportFile -Encoding UTF8
        Write-Log -Message "Generated detailed security report at $reportFile" -Level Info
        return $reportFile
    }
    catch {
        Write-Log -Message "Failed to generate detailed security report: $_" -Level Error
        return $null
    }
}

# Function to test network ports
function Test-NetworkPorts {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Target
    )
    
    try {
        Write-Log -Message "Testing network ports for target: $Target" -Level Info
        
        $results = @{
            "OpenPorts" = @()
            "FilteredPorts" = @()
            "ClosedPorts" = @()
            "VulnerablePorts" = @()
        }
        
        # Common ports to check
        $commonPorts = @(21, 22, 23, 25, 53, 80, 443, 445, 1433, 3306, 3389, 8080)
        
        foreach ($port in $commonPorts) {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connection = $tcpClient.BeginConnect($Target, $port, $null, $null)
            $wait = $connection.AsyncWaitHandle.WaitOne(1000, $false)
            
            if ($wait) {
                $results.OpenPorts += $port
                # Check for known vulnerabilities
                $vulnerabilities = Test-PortVulnerabilities -Target $Target -Port $port
                if ($vulnerabilities) {
                    $results.VulnerablePorts += @{
                        "Port" = $port
                        "Vulnerabilities" = $vulnerabilities
                    }
                }
            }
            else {
                $results.FilteredPorts += $port
            }
            
            $tcpClient.Close()
        }
        
        Write-Log -Message "Completed network port testing" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test network ports: $_" -Level Error
        return $null
    }
}

# Function to test firewall configuration
function Test-FirewallConfiguration {
    try {
        Write-Log -Message "Testing firewall configuration" -Level Info
        
        $results = @{
            "FirewallStatus" = $null
            "InboundRules" = @()
            "OutboundRules" = @()
            "SecurityIssues" = @()
        }
        
        # Check Windows Firewall status
        $firewallStatus = Get-NetFirewallProfile
        $results.FirewallStatus = $firewallStatus
        
        # Check inbound rules
        $inboundRules = Get-NetFirewallRule -Direction Inbound | Where-Object { $_.Enabled -eq $true }
        $results.InboundRules = $inboundRules
        
        # Check outbound rules
        $outboundRules = Get-NetFirewallRule -Direction Outbound | Where-Object { $_.Enabled -eq $true }
        $results.OutboundRules = $outboundRules
        
        # Check for security issues
        $securityIssues = @()
        
        # Check for overly permissive rules
        $permissiveRules = $inboundRules | Where-Object { $_.Action -eq "Allow" -and $_.Profile -eq "Any" }
        if ($permissiveRules) {
            $securityIssues += "Found overly permissive inbound rules"
        }
        
        # Check for missing essential rules
        $essentialPorts = @(80, 443, 53)
        foreach ($port in $essentialPorts) {
            $hasRule = $inboundRules | Where-Object { $_.LocalPort -eq $port }
            if (-not $hasRule) {
                $securityIssues += "Missing inbound rule for port $port"
            }
        }
        
        $results.SecurityIssues = $securityIssues
        
        Write-Log -Message "Completed firewall configuration testing" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test firewall configuration: $_" -Level Error
        return $null
    }
}

# Function to test user account security
function Test-UserAccountSecurity {
    try {
        Write-Log -Message "Testing user account security" -Level Info
        
        $results = @{
            "UserAccounts" = @()
            "SecurityIssues" = @()
            "Recommendations" = @()
        }
        
        # Get all user accounts
        $users = Get-WmiObject -Class Win32_UserAccount
        $results.UserAccounts = $users
        
        # Check for security issues
        $securityIssues = @()
        $recommendations = @()
        
        foreach ($user in $users) {
            # Check for disabled accounts
            if ($user.Disabled -eq $false) {
                $securityIssues += "Account $($user.Name) is enabled but may not be needed"
                $recommendations += "Consider disabling account $($user.Name) if not in use"
            }
            
            # Check for password expiration
            $passwordInfo = Get-ADUser -Identity $user.Name -Properties PasswordNeverExpires, PasswordLastSet
            if ($passwordInfo.PasswordNeverExpires -eq $true) {
                $securityIssues += "Account $($user.Name) has non-expiring password"
                $recommendations += "Enable password expiration for account $($user.Name)"
            }
            
            # Check for admin privileges
            $isAdmin = $user.Name -in (Get-LocalGroupMember -Group "Administrators").Name
            if ($isAdmin) {
                $securityIssues += "Account $($user.Name) has administrative privileges"
                $recommendations += "Review administrative privileges for account $($user.Name)"
            }
        }
        
        $results.SecurityIssues = $securityIssues
        $results.Recommendations = $recommendations
        
        Write-Log -Message "Completed user account security testing" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test user account security: $_" -Level Error
        return $null
    }
}

# Function to test password policy
function Test-PasswordPolicy {
    try {
        Write-Log -Message "Testing password policy" -Level Info
        
        $results = @{
            "CurrentPolicy" = $null
            "SecurityIssues" = @()
            "Recommendations" = @()
        }
        
        # Get current password policy
        $policy = Get-ADDefaultDomainPasswordPolicy
        $results.CurrentPolicy = $policy
        
        # Check for security issues
        $securityIssues = @()
        $recommendations = @()
        
        # Check minimum password length
        if ($policy.MinPasswordLength -lt 12) {
            $securityIssues += "Minimum password length is less than 12 characters"
            $recommendations += "Increase minimum password length to at least 12 characters"
        }
        
        # Check password complexity
        if (-not $policy.ComplexityEnabled) {
            $securityIssues += "Password complexity is not enabled"
            $recommendations += "Enable password complexity requirements"
        }
        
        # Check password history
        if ($policy.PasswordHistoryCount -lt 24) {
            $securityIssues += "Password history is less than 24 passwords"
            $recommendations += "Increase password history to at least 24 passwords"
        }
        
        # Check maximum password age
        if ($policy.MaxPasswordAge -gt 90) {
            $securityIssues += "Maximum password age is greater than 90 days"
            $recommendations += "Decrease maximum password age to 90 days or less"
        }
        
        $results.SecurityIssues = $securityIssues
        $results.Recommendations = $recommendations
        
        Write-Log -Message "Completed password policy testing" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test password policy: $_" -Level Error
        return $null
    }
}

# Function to test file system permissions
function Test-FileSystemPermissions {
    try {
        Write-Log -Message "Testing file system permissions" -Level Info
        
        $results = @{
            "CriticalPaths" = @()
            "SecurityIssues" = @()
            "Recommendations" = @()
        }
        
        # Critical paths to check
        $criticalPaths = @(
            "C:\Windows\System32",
            "C:\Program Files",
            "C:\Program Files (x86)",
            "C:\Users"
        )
        
        foreach ($path in $criticalPaths) {
            if (Test-Path $path) {
                $acl = Get-Acl $path
                $results.CriticalPaths += @{
                    "Path" = $path
                    "Permissions" = $acl.Access
                }
                
                # Check for security issues
                $securityIssues = @()
                $recommendations = @()
                
                # Check for overly permissive permissions
                $permissiveAccess = $acl.Access | Where-Object { $_.FileSystemRights -match "FullControl|Modify" }
                if ($permissiveAccess) {
                    $securityIssues += "Path $path has overly permissive permissions"
                    $recommendations += "Review and restrict permissions for path $path"
                }
                
                # Check for inheritance
                if ($acl.AccessInheritance -eq "None") {
                    $securityIssues += "Path $path has no permission inheritance"
                    $recommendations += "Enable permission inheritance for path $path"
                }
                
                $results.SecurityIssues += $securityIssues
                $results.Recommendations += $recommendations
            }
        }
        
        Write-Log -Message "Completed file system permissions testing" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test file system permissions: $_" -Level Error
        return $null
    }
}

# Function to test registry security
function Test-RegistrySecurity {
    try {
        Write-Log -Message "Testing registry security" -Level Info
        
        $results = @{
            "CriticalKeys" = @()
            "SecurityIssues" = @()
            "Recommendations" = @()
        }
        
        # Critical registry keys to check
        $criticalKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SYSTEM\CurrentControlSet\Services",
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        )
        
        foreach ($key in $criticalKeys) {
            if (Test-Path $key) {
                $acl = Get-Acl $key
                $results.CriticalKeys += @{
                    "Key" = $key
                    "Permissions" = $acl.Access
                    "Values" = Get-ItemProperty -Path $key
                }
                
                # Check for security issues
                $securityIssues = @()
                $recommendations = @()
                
                # Check for overly permissive permissions
                $permissiveAccess = $acl.Access | Where-Object { $_.RegistryRights -match "FullControl|ChangePermissions" }
                if ($permissiveAccess) {
                    $securityIssues += "Registry key $key has overly permissive permissions"
                    $recommendations += "Restrict permissions for registry key $key"
                }
                
                # Check for suspicious values
                $suspiciousValues = Get-ItemProperty -Path $key | Where-Object { 
                    $_.PSChildName -match "\.exe$|\.dll$|\.bat$|\.cmd$|\.vbs$|\.ps1$"
                }
                if ($suspiciousValues) {
                    $securityIssues += "Registry key $key contains suspicious values"
                    $recommendations += "Review and verify values in registry key $key"
                }
                
                $results.SecurityIssues += $securityIssues
                $results.Recommendations += $recommendations
            }
        }
        
        Write-Log -Message "Completed registry security testing" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test registry security: $_" -Level Error
        return $null
    }
}

# Function to test service configuration
function Test-ServiceSecurity {
    try {
        Write-Log -Message "Testing service security" -Level Info
        
        $results = @{
            "CriticalServices" = @()
            "SecurityIssues" = @()
            "Recommendations" = @()
        }
        
        # Critical services to check
        $criticalServices = @(
            "RemoteRegistry",
            "TelnetServer",
            "TFTP",
            "SNMP",
            "IISAdmin",
            "TerminalServices",
            "RemoteAccess",
            "NetBIOS",
            "FTP",
            "SMTP"
        )
        
        foreach ($service in $criticalServices) {
            $serviceInfo = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($serviceInfo) {
                $results.CriticalServices += @{
                    "Name" = $service
                    "Status" = $serviceInfo.Status
                    "StartType" = $serviceInfo.StartType
                    "Description" = $serviceInfo.Description
                }
                
                # Check for security issues
                $securityIssues = @()
                $recommendations = @()
                
                # Check if service is running
                if ($serviceInfo.Status -eq "Running") {
                    $securityIssues += "Service $service is running"
                    $recommendations += "Consider stopping service $service if not needed"
                }
                
                # Check start type
                if ($serviceInfo.StartType -eq "Automatic") {
                    $securityIssues += "Service $service is set to start automatically"
                    $recommendations += "Consider changing start type for service $service to Manual or Disabled"
                }
                
                # Check service permissions
                $serviceAcl = Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\$service"
                $permissiveAccess = $serviceAcl.Access | Where-Object { $_.RegistryRights -match "FullControl|ChangePermissions" }
                if ($permissiveAccess) {
                    $securityIssues += "Service $service has overly permissive permissions"
                    $recommendations += "Restrict permissions for service $service"
                }
                
                $results.SecurityIssues += $securityIssues
                $results.Recommendations += $recommendations
            }
        }
        
        Write-Log -Message "Completed service security testing" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test service security: $_" -Level Error
        return $null
    }
}

# Function to test antivirus status
function Test-AntivirusStatus {
    try {
        Write-Log -Message "Testing antivirus status" -Level Info
        
        $results = @{
            "AntivirusProducts" = @()
            "SecurityIssues" = @()
            "Recommendations" = @()
        }
        
        # Check Windows Defender status
        $defenderStatus = Get-MpComputerStatus
        $results.AntivirusProducts += @{
            "Name" = "Windows Defender"
            "Status" = $defenderStatus.AntivirusEnabled
            "RealTimeProtection" = $defenderStatus.RealTimeProtectionEnabled
            "LastScanTime" = $defenderStatus.LastFullScanTime
            "LastUpdateTime" = $defenderStatus.AntispywareSignatureLastUpdated
            "EngineVersion" = $defenderStatus.AntispywareEngineVersion
        }
        
        # Check for security issues
        $securityIssues = @()
        $recommendations = @()
        
        if (-not $defenderStatus.AntivirusEnabled) {
            $securityIssues += "Windows Defender is not enabled"
            $recommendations += "Enable Windows Defender antivirus"
        }
        
        if (-not $defenderStatus.RealTimeProtectionEnabled) {
            $securityIssues += "Real-time protection is not enabled"
            $recommendations += "Enable real-time protection"
        }
        
        # Check for other antivirus products
        $otherAV = Get-WmiObject -Namespace "root\SecurityCenter2" -Class "AntiVirusProduct"
        foreach ($av in $otherAV) {
            $results.AntivirusProducts += @{
                "Name" = $av.displayName
                "Status" = $av.productState
                "LastUpdateTime" = $av.timestamp
            }
        }
        
        $results.SecurityIssues = $securityIssues
        $results.Recommendations = $recommendations
        
        Write-Log -Message "Completed antivirus status testing" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test antivirus status: $_" -Level Error
        return $null
    }
}

# Function to test system updates
function Test-SystemUpdates {
    try {
        Write-Log -Message "Testing system updates" -Level Info
        
        $results = @{
            "UpdateStatus" = @()
            "MissingUpdates" = @()
            "SecurityIssues" = @()
            "Recommendations" = @()
        }
        
        # Check Windows Update status
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
        
        foreach ($update in $searchResult.Updates) {
            $results.MissingUpdates += @{
                "Title" = $update.Title
                "Description" = $update.Description
                "IsSecurityUpdate" = $update.IsSecurityUpdate
                "Categories" = $update.Categories | ForEach-Object { $_.Name }
            }
        }
        
        # Check for security issues
        $securityIssues = @()
        $recommendations = @()
        
        # Check last update time
        $lastUpdate = Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1
        $daysSinceUpdate = (Get-Date) - $lastUpdate.InstalledOn
        
        if ($daysSinceUpdate.Days -gt 30) {
            $securityIssues += "System has not been updated in $($daysSinceUpdate.Days) days"
            $recommendations += "Install pending updates immediately"
        }
        
        # Check for critical security updates
        $criticalUpdates = $searchResult.Updates | Where-Object { $_.IsSecurityUpdate -eq $true }
        if ($criticalUpdates.Count -gt 0) {
            $securityIssues += "Found $($criticalUpdates.Count) critical security updates pending"
            $recommendations += "Install critical security updates immediately"
        }
        
        $results.SecurityIssues = $securityIssues
        $results.Recommendations = $recommendations
        
        Write-Log -Message "Completed system updates testing" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test system updates: $_" -Level Error
        return $null
    }
}

# Function to test database security
function Test-DatabaseSecurity {
    try {
        Write-Log -Message "Testing database security" -Level Info
        
        $results = @{
            "DatabaseSettings" = @()
            "SecurityIssues" = @()
            "Recommendations" = @()
        }
        
        # Check SQL Server settings
        $sqlPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"
        if (Test-Path $sqlPath) {
            $sqlInstances = Get-ChildItem $sqlPath | Where-Object { $_.Name -like "*MSSQL*" }
            foreach ($instance in $sqlInstances) {
                $instancePath = Join-Path $sqlPath $instance.PSChildName
                $settings = Get-ItemProperty -Path $instancePath
                $results.DatabaseSettings += @{
                    "Type" = "SQL Server"
                    "Instance" = $instance.PSChildName
                    "Authentication" = $settings.AuthenticationMode
                    "Encryption" = $settings.EncryptionEnabled
                    "AuditLevel" = $settings.AuditLevel
                }
            }
        }
        
        # Check MySQL settings
        $mysqlPath = "HKLM:\SOFTWARE\MySQL AB"
        if (Test-Path $mysqlPath) {
            $mysqlInstances = Get-ChildItem $mysqlPath
            foreach ($instance in $mysqlInstances) {
                $instancePath = Join-Path $mysqlPath $instance.PSChildName
                $settings = Get-ItemProperty -Path $instancePath
                $results.DatabaseSettings += @{
                    "Type" = "MySQL"
                    "Instance" = $instance.PSChildName
                    "Authentication" = $settings.AuthenticationPlugin
                    "SSL" = $settings.SSLEnabled
                    "AuditLog" = $settings.AuditLogEnabled
                }
            }
        }
        
        # Check for security issues
        $securityIssues = @()
        $recommendations = @()
        
        foreach ($db in $results.DatabaseSettings) {
            if ($db.Type -eq "SQL Server") {
                if ($db.Authentication -eq "Windows") {
                    $securityIssues += "SQL Server instance '$($db.Instance)' using Windows Authentication only"
                    $recommendations += "Enable SQL Server Authentication for instance '$($db.Instance)'"
                }
                if (-not $db.Encryption) {
                    $securityIssues += "SQL Server instance '$($db.Instance)' encryption is disabled"
                    $recommendations += "Enable encryption for SQL Server instance '$($db.Instance)'"
                }
            }
            if ($db.Type -eq "MySQL") {
                if (-not $db.SSL) {
                    $securityIssues += "MySQL instance '$($db.Instance)' SSL is disabled"
                    $recommendations += "Enable SSL for MySQL instance '$($db.Instance)'"
                }
                if (-not $db.AuditLog) {
                    $securityIssues += "MySQL instance '$($db.Instance)' audit logging is disabled"
                    $recommendations += "Enable audit logging for MySQL instance '$($db.Instance)'"
                }
            }
        }
        
        $results.SecurityIssues = $securityIssues
        $results.Recommendations = $recommendations
        
        Write-Log -Message "Completed database security testing" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test database security: $_" -Level Error
        return $null
    }
}

# Function to test SharePoint security
function Test-SharePointSecurity {
    param (
        [string]$ServerName = $env:COMPUTERNAME
    )
    
    try {
        Write-Log -Message "Starting SharePoint security check for $ServerName" -Level Info
        
        $results = @{
            SharePointSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check SharePoint installation
        if (Get-Service -Name "SPTimerV4" -ErrorAction SilentlyContinue) {
            $results.SharePointSettings.Installation = @{
                Version = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\16.0' -ErrorAction SilentlyContinue).Version
                Services = @{
                    TimerService = (Get-Service -Name "SPTimerV4").Status
                    AdminService = (Get-Service -Name "SPAdminV4").Status
                    SearchService = (Get-Service -Name "OSearch16").Status
                }
            }
            
            # Check SharePoint security settings
            $results.SharePointSettings.Security = @{
                ClaimsAuthentication = (Get-SPWebApplication | Where-Object { $_.UseClaimsAuthentication }).Count -gt 0
                SSLEnabled = (Get-SPWebApplication | Where-Object { $_.Url -like "https://*" }).Count -gt 0
                AnonymousAccess = (Get-SPWebApplication | Where-Object { $_.AllowAnonymousAccess }).Count -gt 0
                FormsAuthentication = (Get-SPWebApplication | Where-Object { $_.UseFormsAuthentication }).Count -gt 0
            }
            
            # Check for security issues
            if (-not $results.SharePointSettings.Security.SSLEnabled) {
                $results.SecurityIssues += "SSL not enabled for all web applications"
                $results.Recommendations += "Enable SSL for all SharePoint web applications"
            }
            
            if ($results.SharePointSettings.Security.AnonymousAccess) {
                $results.SecurityIssues += "Anonymous access enabled"
                $results.Recommendations += "Disable anonymous access if not required"
            }
        }
        
        Write-Log -Message "Completed SharePoint security check for $ServerName" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test SharePoint security: $_" -Level Error
        return $null
    }
}

# Function to test Exchange security
function Test-ExchangeSecurity {
    param (
        [string]$ServerName = $env:COMPUTERNAME
    )
    
    try {
        Write-Log -Message "Starting Exchange security check for $ServerName" -Level Info
        
        $results = @{
            ExchangeSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check Exchange installation
        if (Get-Service -Name "MSExchangeIS" -ErrorAction SilentlyContinue) {
            $results.ExchangeSettings.Installation = @{
                Version = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup' -ErrorAction SilentlyContinue).Version
                Services = @{
                    InformationStore = (Get-Service -Name "MSExchangeIS").Status
                    Transport = (Get-Service -Name "MSExchangeTransport").Status
                    MailboxReplication = (Get-Service -Name "MSExchangeMailboxReplication").Status
                }
            }
            
            # Check Exchange security settings
            $results.ExchangeSettings.Security = @{
                TLSEnabled = (Get-ExchangeCertificate | Where-Object { $_.Services -match "SMTP" }).Count -gt 0
                AntispamEnabled = (Get-ContentFilterConfig).Enabled
                AntimalwareEnabled = (Get-MalwareFilteringServer).Enabled
                OAuthEnabled = (Get-AuthConfig).OAuthEnabled
            }
            
            # Check for security issues
            if (-not $results.ExchangeSettings.Security.TLSEnabled) {
                $results.SecurityIssues += "TLS not enabled for SMTP"
                $results.Recommendations += "Enable TLS for SMTP communication"
            }
            
            if (-not $results.ExchangeSettings.Security.AntispamEnabled) {
                $results.SecurityIssues += "Antispam filtering not enabled"
                $results.Recommendations += "Enable antispam filtering"
            }
        }
        
        Write-Log -Message "Completed Exchange security check for $ServerName" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test Exchange security: $_" -Level Error
        return $null
    }
}

# Function to test custom application security
function Test-CustomApplicationSecurity {
    param (
        [string]$ApplicationPath = "C:\Program Files\CustomApp",
        [string]$ConfigFile = "app.config"
    )
    
    try {
        Write-Log -Message "Starting custom application security check for $ApplicationPath" -Level Info
        
        $results = @{
            ApplicationSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check application files
        if (Test-Path $ApplicationPath) {
            $results.ApplicationSettings.Files = @{
                Executables = Get-ChildItem -Path $ApplicationPath -Filter "*.exe" | Select-Object Name, LastWriteTime
                ConfigFiles = Get-ChildItem -Path $ApplicationPath -Filter "*.config" | Select-Object Name, LastWriteTime
                LogFiles = Get-ChildItem -Path $ApplicationPath -Filter "*.log" | Select-Object Name, LastWriteTime
            }
            
            # Check configuration file
            if (Test-Path "$ApplicationPath\$ConfigFile") {
                $config = Get-Content "$ApplicationPath\$ConfigFile"
                $results.ApplicationSettings.Configuration = @{
                    ConnectionString = ($config | Select-String "connectionString").ToString()
                    Authentication = ($config | Select-String "authentication").ToString()
                    Logging = ($config | Select-String "logging").ToString()
                }
                
                # Check for security issues
                if ($results.ApplicationSettings.Configuration.ConnectionString -match "password|pwd") {
                    $results.SecurityIssues += "Plain text credentials in configuration"
                    $results.Recommendations += "Use encrypted connection strings or secure credential storage"
                }
            }
            
            # Check file permissions
            $results.ApplicationSettings.Permissions = @{
                ExecutablePermissions = (Get-Acl "$ApplicationPath\*.exe").Access
                ConfigPermissions = (Get-Acl "$ApplicationPath\*.config").Access
                LogPermissions = (Get-Acl "$ApplicationPath\*.log").Access
            }
            
            # Check for security issues
            if ($results.ApplicationSettings.Permissions.ExecutablePermissions | Where-Object { $_.FileSystemRights -match "FullControl|Modify" }) {
                $results.SecurityIssues += "Overly permissive executable permissions"
                $results.Recommendations += "Restrict executable file permissions to necessary users only"
            }
        }
        
        Write-Log -Message "Completed custom application security check for $ApplicationPath" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test custom application security: $_" -Level Error
        return $null
    }
}

# Function to generate enhanced security report with additional charts and analysis
function New-EnhancedSecurityReport {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Target,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$NetworkChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$SystemChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$ApplicationChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$ComplianceChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$RegistryChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$ServiceChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$AntivirusChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$UpdateChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$BrowserChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$WhitelistChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$EmailChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$ShareChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$DatabaseChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$CloudChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$WebServerChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$DbConnectionChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$SecurityHeaderChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$SharePointChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$ExchangeChecks,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$CustomAppChecks
    )
    
    try {
        $reportFile = "$reportPath\enhanced_security_report_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"
        
        # Generate chart data
        $securityIssuesByCategory = @{
            "Network" = $NetworkChecks.SecurityIssues.Count
            "System" = $SystemChecks.SecurityIssues.Count
            "Application" = $ApplicationChecks.SecurityIssues.Count
            "Registry" = $RegistryChecks.SecurityIssues.Count
            "Service" = $ServiceChecks.SecurityIssues.Count
            "Antivirus" = $AntivirusChecks.SecurityIssues.Count
            "Updates" = $UpdateChecks.SecurityIssues.Count
            "Browser" = $BrowserChecks.SecurityIssues.Count
            "Whitelist" = $WhitelistChecks.SecurityIssues.Count
            "Email" = $EmailChecks.SecurityIssues.Count
            "Shares" = $ShareChecks.SecurityIssues.Count
            "Database" = $DatabaseChecks.SecurityIssues.Count
            "Cloud" = $CloudChecks.SecurityIssues.Count
            "WebServer" = $WebServerChecks.SecurityIssues.Count
            "DbConnection" = $DbConnectionChecks.SecurityIssues.Count
            "SecurityHeaders" = $SecurityHeaderChecks.SecurityIssues.Count
            "SharePoint" = $SharePointChecks.SecurityIssues.Count
            "Exchange" = $ExchangeChecks.SecurityIssues.Count
            "CustomApp" = $CustomAppChecks.SecurityIssues.Count
        }
        
        $chartData = $securityIssuesByCategory.GetEnumerator() | ForEach-Object {
            "{ label: '$($_.Key)', value: $($_.Value) }"
        } -join ","
        
        # Generate risk distribution data
        $riskDistribution = @{
            "Critical" = ($NetworkChecks.SecurityIssues.Count + $SystemChecks.SecurityIssues.Count) * 0.3
            "High" = ($ApplicationChecks.SecurityIssues.Count + $RegistryChecks.SecurityIssues.Count) * 0.25
            "Medium" = ($ServiceChecks.SecurityIssues.Count + $AntivirusChecks.SecurityIssues.Count) * 0.25
            "Low" = ($UpdateChecks.SecurityIssues.Count + $BrowserChecks.SecurityIssues.Count + $WhitelistChecks.SecurityIssues.Count) * 0.2
        }
        
        $riskData = $riskDistribution.GetEnumerator() | ForEach-Object {
            "{ label: '$($_.Key)', value: $($_.Value) }"
        } -join ","
        
        # Generate compliance radar data
        $complianceData = @{
            "GDPR" = $ComplianceChecks.GDPRCompliance
            "PCI" = $ComplianceChecks.PCICompliance
            "HIPAA" = $ComplianceChecks.HIPAACompliance
            "ISO27001" = $ComplianceChecks.ISO27001Compliance
        }
        
        $radarData = $complianceData.GetEnumerator() | ForEach-Object {
            "{ label: '$($_.Key)', value: $($_.Value) }"
        } -join ","
        
        # Generate trend data
        $trendData = @{
            "Dates" = @()
            "Issues" = @()
        }
        
        $reports = Get-ChildItem -Path $reportPath -Filter "enhanced_security_report_*.html" | Sort-Object LastWriteTime -Descending | Select-Object -First 5
        foreach ($report in $reports) {
            $trendData.Dates += $report.LastWriteTime.ToString("yyyy-MM-dd")
            $trendData.Issues += ($report | Get-Content | Select-String "Security Issues").Count
        }
        
        $trendLabels = $trendData.Dates -join "','"
        $trendValues = $trendData.Issues -join ","
        
        # Generate vulnerability trend data
        $vulnerabilityTrend = @{
            "Dates" = @()
            "Critical" = @()
            "High" = @()
            "Medium" = @()
            "Low" = @()
        }
        
        $reports = Get-ChildItem -Path $reportPath -Filter "enhanced_security_report_*.html" | Sort-Object LastWriteTime -Descending | Select-Object -First 10
        foreach ($report in $reports) {
            $vulnerabilityTrend.Dates += $report.LastWriteTime.ToString("yyyy-MM-dd")
            $content = Get-Content $report.FullName
            $vulnerabilityTrend.Critical += ($content | Select-String "Critical").Count
            $vulnerabilityTrend.High += ($content | Select-String "High").Count
            $vulnerabilityTrend.Medium += ($content | Select-String "Medium").Count
            $vulnerabilityTrend.Low += ($content | Select-String "Low").Count
        }
        
        # Calculate risk scores
        $riskScores = @{
            "Network" = $NetworkChecks.SecurityIssues.Count * 10
            "System" = $SystemChecks.SecurityIssues.Count * 8
            "Application" = $ApplicationChecks.SecurityIssues.Count * 7
            "Database" = $DatabaseChecks.SecurityIssues.Count * 9
            "Cloud" = $CloudChecks.SecurityIssues.Count * 6
            "SharePoint" = $SharePointChecks.SecurityIssues.Count * 8
            "Exchange" = $ExchangeChecks.SecurityIssues.Count * 9
            "CustomApp" = $CustomAppChecks.SecurityIssues.Count * 7
        }
        
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Enhanced Security Assessment Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #2c3e50; }
        .section { margin: 20px 0; padding: 10px; border: 1px solid #ddd; }
        .critical { color: #e74c3c; }
        .high { color: #e67e22; }
        .medium { color: #f1c40f; }
        .low { color: #2ecc71; }
        .check-item { margin: 10px 0; padding: 5px; border-left: 3px solid #3498db; }
        .recommendation { background-color: #f8f9fa; padding: 10px; margin: 5px 0; }
        .summary { background-color: #e8f4f8; padding: 15px; margin: 10px 0; }
        .chart { margin: 20px 0; }
        .chart-container { width: 50%; margin: 20px auto; }
        .chart-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .heatmap { display: grid; grid-template-columns: repeat(7, 1fr); gap: 2px; }
        .heatmap-cell { padding: 10px; text-align: center; }
        .bubble-chart { height: 400px; }
    </style>
</head>
<body>
    <h1>Enhanced Security Assessment Report</h1>
    <p>Target: $Target</p>
    <p>Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>This report provides a comprehensive security assessment of the target system, including network security, system security, application security, compliance, registry security, service configuration, antivirus status, system updates, browser security, application whitelisting, email security, network share permissions, database security, and cloud service security.</p>
        
        <div class="chart-grid">
            <div class="chart-container">
                <canvas id="securityIssuesChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="riskDistributionChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="complianceRadarChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="trendChart"></canvas>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>Database Security</h2>
        <div class="check-item">
            <h3>Database Settings</h3>
            <pre>$($DatabaseChecks.DatabaseSettings | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Security Issues</h3>
            <pre>$($DatabaseChecks.SecurityIssues | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Cloud Service Security</h2>
        <div class="check-item">
            <h3>Cloud Services</h3>
            <pre>$($CloudChecks.CloudServices | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Security Issues</h3>
            <pre>$($CloudChecks.SecurityIssues | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Email Security</h2>
        <div class="check-item">
            <h3>Email Settings</h3>
            <pre>$($EmailChecks.EmailSettings | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Security Issues</h3>
            <pre>$($EmailChecks.SecurityIssues | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Network Share Permissions</h2>
        <div class="check-item">
            <h3>Share Permissions</h3>
            <pre>$($ShareChecks.SharePermissions | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Security Issues</h3>
            <pre>$($ShareChecks.SecurityIssues | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Antivirus Status</h2>
        <div class="check-item">
            <h3>Installed Products</h3>
            <pre>$($AntivirusChecks.AntivirusProducts | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Security Issues</h3>
            <pre>$($AntivirusChecks.SecurityIssues | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>System Updates</h2>
        <div class="check-item">
            <h3>Missing Updates</h3>
            <pre>$($UpdateChecks.MissingUpdates | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Security Issues</h3>
            <pre>$($UpdateChecks.SecurityIssues | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Network Security Assessment</h2>
        <div class="check-item">
            <h3>Port Scan Results</h3>
            <pre>$($NetworkChecks.PortScan | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Firewall Configuration</h3>
            <pre>$($NetworkChecks.FirewallRules | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>System Security Assessment</h2>
        <div class="check-item">
            <h3>User Account Security</h3>
            <pre>$($SystemChecks.UserAccounts | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Password Policy</h3>
            <pre>$($SystemChecks.PasswordPolicy | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>File System Permissions</h3>
            <pre>$($SystemChecks.FilePermissions | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Registry Security Assessment</h2>
        <div class="check-item">
            <h3>Critical Registry Keys</h3>
            <pre>$($RegistryChecks.CriticalKeys | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Security Issues</h3>
            <pre>$($RegistryChecks.SecurityIssues | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Service Security Assessment</h2>
        <div class="check-item">
            <h3>Critical Services</h3>
            <pre>$($ServiceChecks.CriticalServices | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Security Issues</h3>
            <pre>$($ServiceChecks.SecurityIssues | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Application Security Assessment</h2>
        <div class="check-item">
            <h3>Web Application Security</h3>
            <pre>$($ApplicationChecks.WebSecurity | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Database Security</h3>
            <pre>$($ApplicationChecks.DatabaseSecurity | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Compliance Assessment</h2>
        <div class="check-item">
            <h3>GDPR Compliance</h3>
            <pre>$($ComplianceChecks.GDPR | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>PCI Compliance</h3>
            <pre>$($ComplianceChecks.PCI | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Browser Security</h2>
        <div class="check-item">
            <h3>Browser Settings</h3>
            <pre>$($BrowserChecks.BrowserSettings | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Security Issues</h3>
            <pre>$($BrowserChecks.SecurityIssues | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Application Whitelisting</h2>
        <div class="check-item">
            <h3>Whitelisted Applications</h3>
            <pre>$($WhitelistChecks.WhitelistedApps | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Blocked Applications</h3>
            <pre>$($WhitelistChecks.BlockedApps | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Web Server Security</h2>
        <div class="check-item">
            <h3>Web Server Settings</h3>
            <pre>$($WebServerChecks.WebServerSettings | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Security Issues</h3>
            <pre>$($WebServerChecks.SecurityIssues | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Database Connection Security</h2>
        <div class="check-item">
            <h3>Connection Settings</h3>
            <pre>$($DbConnectionChecks.ConnectionSettings | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Security Issues</h3>
            <pre>$($DbConnectionChecks.SecurityIssues | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Security Headers</h2>
        <div class="check-item">
            <h3>Headers</h3>
            <pre>$($SecurityHeaderChecks.Headers | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Security Issues</h3>
            <pre>$($SecurityHeaderChecks.SecurityIssues | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>SharePoint Security</h2>
        <div class="check-item">
            <h3>SharePoint Settings</h3>
            <pre>$($SharePointChecks.SharePointSettings | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Security Issues</h3>
            <pre>$($SharePointChecks.SecurityIssues | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Exchange Security</h2>
        <div class="check-item">
            <h3>Exchange Settings</h3>
            <pre>$($ExchangeChecks.ExchangeSettings | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Security Issues</h3>
            <pre>$($ExchangeChecks.SecurityIssues | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Custom Application Security</h2>
        <div class="check-item">
            <h3>Application Settings</h3>
            <pre>$($CustomAppChecks.ApplicationSettings | ConvertTo-Html)</pre>
        </div>
        <div class="check-item">
            <h3>Security Issues</h3>
            <pre>$($CustomAppChecks.SecurityIssues | ConvertTo-Html)</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <div class="recommendation">
            <h3>Critical Issues</h3>
            <ul>
                <li>Address critical vulnerabilities immediately</li>
                <li>Implement missing security controls</li>
                <li>Update security configurations</li>
            </ul>
        </div>
        <div class="recommendation">
            <h3>High Priority</h3>
            <ul>
                <li>Enhance security monitoring</li>
                <li>Improve access controls</li>
                <li>Update security policies</li>
            </ul>
        </div>
        <div class="recommendation">
            <h3>Medium Priority</h3>
            <ul>
                <li>Implement additional security measures</li>
                <li>Enhance logging capabilities</li>
                <li>Improve documentation</li>
            </ul>
        </div>
        <div class="recommendation">
            <h3>Low Priority</h3>
            <ul>
                <li>Review security configurations</li>
                <li>Update documentation</li>
                <li>Plan future improvements</li>
            </ul>
        </div>
    </div>
    
    <div class="section">
        <h2>Vulnerability Trends</h2>
        <div class="chart-container">
            <canvas id="vulnerabilityTrendChart"></canvas>
        </div>
    </div>
    
    <div class="section">
        <h2>Risk Heat Map</h2>
        <div class="heatmap" id="riskHeatMap"></div>
    </div>
    
    <div class="section">
        <h2>Risk Bubble Chart</h2>
        <div class="chart-container bubble-chart">
            <canvas id="riskBubbleChart"></canvas>
        </div>
    </div>
    
    <script>
        // Security Issues Chart
        const ctx1 = document.getElementById('securityIssuesChart').getContext('2d');
        new Chart(ctx1, {
            type: 'bar',
            data: {
                labels: Object.keys($securityIssuesByCategory),
                datasets: [{
                    label: 'Security Issues by Category',
                    data: [$chartData],
                    backgroundColor: [
                        '#e74c3c',
                        '#e67e22',
                        '#f1c40f',
                        '#2ecc71',
                        '#3498db',
                        '#9b59b6',
                        '#1abc9c',
                        '#34495e',
                        '#16a085',
                        '#2980b9',
                        '#8e44ad',
                        '#27ae60',
                        '#c0392b'
                    ]
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Risk Distribution Chart
        const ctx2 = document.getElementById('riskDistributionChart').getContext('2d');
        new Chart(ctx2, {
            type: 'pie',
            data: {
                labels: Object.keys($riskDistribution),
                datasets: [{
                    data: [$riskData],
                    backgroundColor: [
                        '#e74c3c',
                        '#e67e22',
                        '#f1c40f',
                        '#2ecc71'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
        
        // Compliance Radar Chart
        const ctx3 = document.getElementById('complianceRadarChart').getContext('2d');
        new Chart(ctx3, {
            type: 'radar',
            data: {
                labels: Object.keys($complianceData),
                datasets: [{
                    label: 'Compliance Score',
                    data: [$radarData],
                    backgroundColor: 'rgba(52, 152, 219, 0.2)',
                    borderColor: 'rgba(52, 152, 219, 1)',
                    pointBackgroundColor: 'rgba(52, 152, 219, 1)',
                    pointBorderColor: '#fff',
                    pointHoverBackgroundColor: '#fff',
                    pointHoverBorderColor: 'rgba(52, 152, 219, 1)'
                }]
            },
            options: {
                responsive: true,
                scales: {
                    r: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });
        
        // Trend Chart
        const ctx4 = document.getElementById('trendChart').getContext('2d');
        new Chart(ctx4, {
            type: 'line',
            data: {
                labels: ['$trendLabels'],
                datasets: [{
                    label: 'Security Issues Trend',
                    data: [$trendValues],
                    borderColor: 'rgba(231, 76, 60, 1)',
                    backgroundColor: 'rgba(231, 76, 60, 0.2)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Vulnerability Trend Chart
        const ctx5 = document.getElementById('vulnerabilityTrendChart').getContext('2d');
        new Chart(ctx5, {
            type: 'line',
            data: {
                labels: ['$($vulnerabilityTrend.Dates -join "','")'],
                datasets: [
                    {
                        label: 'Critical',
                        data: [$($vulnerabilityTrend.Critical -join ',')],
                        borderColor: 'rgba(231, 76, 60, 1)',
                        backgroundColor: 'rgba(231, 76, 60, 0.2)',
                        tension: 0.1
                    },
                    {
                        label: 'High',
                        data: [$($vulnerabilityTrend.High -join ',')],
                        borderColor: 'rgba(230, 126, 34, 1)',
                        backgroundColor: 'rgba(230, 126, 34, 0.2)',
                        tension: 0.1
                    },
                    {
                        label: 'Medium',
                        data: [$($vulnerabilityTrend.Medium -join ',')],
                        borderColor: 'rgba(241, 196, 15, 1)',
                        backgroundColor: 'rgba(241, 196, 15, 0.2)',
                        tension: 0.1
                    },
                    {
                        label: 'Low',
                        data: [$($vulnerabilityTrend.Low -join ',')],
                        borderColor: 'rgba(46, 204, 113, 1)',
                        backgroundColor: 'rgba(46, 204, 113, 0.2)',
                        tension: 0.1
                    }
                ]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
        
        // Risk Bubble Chart
        const ctx6 = document.getElementById('riskBubbleChart').getContext('2d');
        new Chart(ctx6, {
            type: 'bubble',
            data: {
                datasets: [{
                    label: 'Risk Assessment',
                    data: [
                        { x: 1, y: $($riskScores.Network), r: $($riskScores.Network / 2) },
                        { x: 2, y: $($riskScores.System), r: $($riskScores.System / 2) },
                        { x: 3, y: $($riskScores.Application), r: $($riskScores.Application / 2) },
                        { x: 4, y: $($riskScores.Database), r: $($riskScores.Database / 2) },
                        { x: 5, y: $($riskScores.Cloud), r: $($riskScores.Cloud / 2) },
                        { x: 6, y: $($riskScores.SharePoint), r: $($riskScores.SharePoint / 2) },
                        { x: 7, y: $($riskScores.Exchange), r: $($riskScores.Exchange / 2) },
                        { x: 8, y: $($riskScores.CustomApp), r: $($riskScores.CustomApp / 2) }
                    ],
                    backgroundColor: [
                        'rgba(231, 76, 60, 0.6)',
                        'rgba(230, 126, 34, 0.6)',
                        'rgba(241, 196, 15, 0.6)',
                        'rgba(46, 204, 113, 0.6)',
                        'rgba(52, 152, 219, 0.6)',
                        'rgba(155, 89, 182, 0.6)',
                        'rgba(26, 188, 156, 0.6)',
                        'rgba(52, 73, 94, 0.6)'
                    ]
                }]
            },
            options: {
                responsive: true,
                scales: {
                    x: {
                        title: {
                            display: true,
                            text: 'Component'
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: 'Risk Score'
                        }
                    }
                }
            }
        });
        
        // Generate Risk Heat Map
        const heatMap = document.getElementById('riskHeatMap');
        const components = ['Network', 'System', 'Application', 'Database', 'Cloud', 'SharePoint', 'Exchange', 'CustomApp'];
        const scores = [$($riskScores.Network), $($riskScores.System), $($riskScores.Application), $($riskScores.Database), $($riskScores.Cloud), $($riskScores.SharePoint), $($riskScores.Exchange), $($riskScores.CustomApp)];
        
        components.forEach((component, index) => {
            const cell = document.createElement('div');
            cell.className = 'heatmap-cell';
            cell.style.backgroundColor = `rgba(231, 76, 60, ${scores[index] / 100})`;
            cell.textContent = `${component}: ${scores[index]}`;
            heatMap.appendChild(cell);
        });
    </script>
</body>
</html>
"@
        
        $html | Out-File -FilePath $reportFile -Encoding UTF8
        Write-Log -Message "Generated enhanced security report at $reportFile" -Level Info
        return $reportFile
    }
    catch {
        Write-Log -Message "Failed to generate enhanced security report: $_" -Level Error
        return $null
    }
}

# Function to test application whitelisting
function Test-ApplicationWhitelisting {
    try {
        Write-Log -Message "Testing application whitelisting" -Level Info
        
        $results = @{
            "WhitelistedApps" = @()
            "BlockedApps" = @()
            "SecurityIssues" = @()
            "Recommendations" = @()
        }
        
        # Check AppLocker status
        $appLockerStatus = Get-AppLockerPolicy -Effective
        if ($appLockerStatus) {
            $results.WhitelistedApps = $appLockerStatus.RuleCollections | ForEach-Object {
                $_.Rules | ForEach-Object {
                    @{
                        "Name" = $_.Name
                        "Description" = $_.Description
                        "Action" = $_.Action
                        "UserOrGroupSid" = $_.UserOrGroupSid
                    }
                }
            }
        }
        
        # Check Software Restriction Policies
        $srpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
        if (Test-Path $srpPath) {
            $srpEnabled = (Get-ItemProperty -Path $srpPath -Name "Enabled").Enabled
            if ($srpEnabled) {
                $results.BlockedApps = Get-ChildItem $srpPath -Recurse | ForEach-Object {
                    @{
                        "Path" = $_.PSPath
                        "Value" = $_.Property
                    }
                }
            }
        }
        
        # Check for security issues
        $securityIssues = @()
        $recommendations = @()
        
        if (-not $appLockerStatus) {
            $securityIssues += "AppLocker is not configured"
            $recommendations += "Configure AppLocker policies"
        }
        
        if (-not $srpEnabled) {
            $securityIssues += "Software Restriction Policies are not enabled"
            $recommendations += "Enable Software Restriction Policies"
        }
        
        $results.SecurityIssues = $securityIssues
        $results.Recommendations = $recommendations
        
        Write-Log -Message "Completed application whitelisting testing" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test application whitelisting: $_" -Level Error
        return $null
    }
}

# Function to test email security
function Test-EmailSecurity {
    try {
        Write-Log -Message "Testing email security" -Level Info
        
        $results = @{
            "EmailSettings" = @()
            "SecurityIssues" = @()
            "Recommendations" = @()
        }
        
        # Check Outlook settings
        $outlookPath = "HKCU:\Software\Microsoft\Office\16.0\Outlook\Security"
        if (Test-Path $outlookPath) {
            $outlookSettings = Get-ItemProperty -Path $outlookPath
            $results.EmailSettings += @{
                "Client" = "Outlook"
                "SafeAttachments" = $outlookSettings.SafeAttachments
                "SafeLinks" = $outlookSettings.SafeLinks
                "Encryption" = $outlookSettings.Encryption
                "JunkMail" = $outlookSettings.JunkMail
            }
        }
        
        # Check Exchange settings
        $exchangePath = "HKLM:\SOFTWARE\Microsoft\ExchangeServer"
        if (Test-Path $exchangePath) {
            $exchangeSettings = Get-ItemProperty -Path $exchangePath
            $results.EmailSettings += @{
                "Server" = "Exchange"
                "AntiSpam" = $exchangeSettings.AntiSpamEnabled
                "DLP" = $exchangeSettings.DLPEnabled
                "Encryption" = $exchangeSettings.EncryptionEnabled
            }
        }
        
        # Check for security issues
        $securityIssues = @()
        $recommendations = @()
        
        foreach ($email in $results.EmailSettings) {
            if ($email.Client -eq "Outlook") {
                if (-not $email.SafeAttachments) {
                    $securityIssues += "Outlook Safe Attachments is disabled"
                    $recommendations += "Enable Safe Attachments in Outlook"
                }
                if (-not $email.SafeLinks) {
                    $securityIssues += "Outlook Safe Links is disabled"
                    $recommendations += "Enable Safe Links in Outlook"
                }
            }
            if ($email.Server -eq "Exchange") {
                if (-not $email.AntiSpam) {
                    $securityIssues += "Exchange Anti-Spam is disabled"
                    $recommendations += "Enable Anti-Spam in Exchange"
                }
                if (-not $email.DLP) {
                    $securityIssues += "Exchange DLP is disabled"
                    $recommendations += "Enable DLP in Exchange"
                }
            }
        }
        
        $results.SecurityIssues = $securityIssues
        $results.Recommendations = $recommendations
        
        Write-Log -Message "Completed email security testing" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test email security: $_" -Level Error
        return $null
    }
}

# Function to test network share permissions
function Test-NetworkSharePermissions {
    try {
        Write-Log -Message "Testing network share permissions" -Level Info
        
        $results = @{
            "SharePermissions" = @()
            "SecurityIssues" = @()
            "Recommendations" = @()
        }
        
        # Get all network shares
        $shares = Get-WmiObject -Class Win32_Share
        foreach ($share in $shares) {
            $sharePath = $share.Path
            if ($sharePath) {
                $acl = Get-Acl $sharePath
                $results.SharePermissions += @{
                    "ShareName" = $share.Name
                    "Path" = $sharePath
                    "Permissions" = $acl.Access | ForEach-Object {
                        @{
                            "Identity" = $_.IdentityReference
                            "Rights" = $_.FileSystemRights
                            "Type" = $_.AccessControlType
                        }
                    }
                }
            }
        }
        
        # Check for security issues
        $securityIssues = @()
        $recommendations = @()
        
        foreach ($share in $results.SharePermissions) {
            # Check for Everyone or Anonymous access
            $everyoneAccess = $share.Permissions | Where-Object { 
                $_.Identity -like "*Everyone*" -or $_.Identity -like "*Anonymous*" 
            }
            if ($everyoneAccess) {
                $securityIssues += "Share '$($share.ShareName)' has Everyone/Anonymous access"
                $recommendations += "Remove Everyone/Anonymous access from share '$($share.ShareName)'"
            }
            
            # Check for excessive permissions
            $excessiveRights = $share.Permissions | Where-Object {
                $_.Rights -like "*FullControl*" -or $_.Rights -like "*Change*"
            }
            if ($excessiveRights) {
                $securityIssues += "Share '$($share.ShareName)' has excessive permissions"
                $recommendations += "Review and restrict permissions on share '$($share.ShareName)'"
            }
        }
        
        $results.SecurityIssues = $securityIssues
        $results.Recommendations = $recommendations
        
        Write-Log -Message "Completed network share permissions testing" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test network share permissions: $_" -Level Error
        return $null
    }
}

# Function to test cloud service security
function Test-CloudServiceSecurity {
    try {
        Write-Log -Message "Testing cloud service security" -Level Info
        
        $results = @{
            "CloudServices" = @()
            "SecurityIssues" = @()
            "Recommendations" = @()
        }
        
        # Check Azure settings
        $azurePath = "HKLM:\SOFTWARE\Microsoft\Azure"
        if (Test-Path $azurePath) {
            $azureSettings = Get-ItemProperty -Path $azurePath
            $results.CloudServices += @{
                "Provider" = "Azure"
                "Services" = $azureSettings.Services
                "SecurityCenter" = $azureSettings.SecurityCenterEnabled
                "KeyVault" = $azureSettings.KeyVaultEnabled
                "Monitoring" = $azureSettings.MonitoringEnabled
            }
        }
        
        # Check AWS settings
        $awsPath = "HKLM:\SOFTWARE\Amazon\AWS"
        if (Test-Path $awsPath) {
            $awsSettings = Get-ItemProperty -Path $awsPath
            $results.CloudServices += @{
                "Provider" = "AWS"
                "Services" = $awsSettings.Services
                "SecurityHub" = $awsSettings.SecurityHubEnabled
                "KMS" = $awsSettings.KMSEnabled
                "CloudWatch" = $awsSettings.CloudWatchEnabled
            }
        }
        
        # Check for security issues
        $securityIssues = @()
        $recommendations = @()
        
        foreach ($cloud in $results.CloudServices) {
            if ($cloud.Provider -eq "Azure") {
                if (-not $cloud.SecurityCenter) {
                    $securityIssues += "Azure Security Center is disabled"
                    $recommendations += "Enable Azure Security Center"
                }
                if (-not $cloud.KeyVault) {
                    $securityIssues += "Azure Key Vault is disabled"
                    $recommendations += "Enable Azure Key Vault"
                }
            }
            if ($cloud.Provider -eq "AWS") {
                if (-not $cloud.SecurityHub) {
                    $securityIssues += "AWS Security Hub is disabled"
                    $recommendations += "Enable AWS Security Hub"
                }
                if (-not $cloud.KMS) {
                    $securityIssues += "AWS KMS is disabled"
                    $recommendations += "Enable AWS KMS"
                }
            }
        }
        
        $results.SecurityIssues = $securityIssues
        $results.Recommendations = $recommendations
        
        Write-Log -Message "Completed cloud service security testing" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test cloud service security: $_" -Level Error
        return $null
    }
}

# Function to test web server security
function Test-WebServerSecurity {
    param (
        [string]$ServerName = $env:COMPUTERNAME
    )
    
    try {
        Write-Log -Message "Starting web server security check for $ServerName" -Level Info
        
        $results = @{
            WebServerSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check IIS settings
        if (Get-Service -Name W3SVC -ErrorAction SilentlyContinue) {
            $results.WebServerSettings.IIS = @{
                Version = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InetStp' -ErrorAction SilentlyContinue).VersionString
                SSLEnabled = (Get-WebBinding -Name "Default Web Site" -Protocol "https" -ErrorAction SilentlyContinue) -ne $null
                AuthenticationMethods = (Get-WebConfiguration "/system.webServer/security/authentication" -ErrorAction SilentlyContinue).Collection
                RequestFiltering = (Get-WebConfiguration "/system.webServer/security/requestFiltering" -ErrorAction SilentlyContinue).Collection
            }
            
            # Check for security issues
            if (-not $results.WebServerSettings.IIS.SSLEnabled) {
                $results.SecurityIssues += "SSL/TLS not enabled on default website"
                $results.Recommendations += "Enable SSL/TLS and configure secure cipher suites"
            }
            
            if ($results.WebServerSettings.IIS.AuthenticationMethods | Where-Object { $_.Enabled -eq $true -and $_.Name -eq "Anonymous" }) {
                $results.SecurityIssues += "Anonymous authentication enabled"
                $results.Recommendations += "Disable anonymous authentication if not required"
            }
        }
        
        # Check Apache settings if installed
        if (Test-Path "C:\Program Files\Apache Group\Apache\conf\httpd.conf") {
            $apacheConfig = Get-Content "C:\Program Files\Apache Group\Apache\conf\httpd.conf"
            $results.WebServerSettings.Apache = @{
                Version = ($apacheConfig | Select-String "ServerVersion").ToString()
                SSLEnabled = ($apacheConfig | Select-String "SSLEngine on").Count -gt 0
                SecurityHeaders = @{
                    XFrameOptions = ($apacheConfig | Select-String "Header set X-Frame-Options").Count -gt 0
                    XSSProtection = ($apacheConfig | Select-String "Header set X-XSS-Protection").Count -gt 0
                    ContentSecurityPolicy = ($apacheConfig | Select-String "Header set Content-Security-Policy").Count -gt 0
                }
            }
            
            # Check for security issues
            if (-not $results.WebServerSettings.Apache.SSLEnabled) {
                $results.SecurityIssues += "SSL/TLS not enabled in Apache configuration"
                $results.Recommendations += "Enable SSL/TLS in Apache configuration"
            }
            
            if (-not $results.WebServerSettings.Apache.SecurityHeaders.XFrameOptions) {
                $results.SecurityIssues += "X-Frame-Options header not configured"
                $results.Recommendations += "Add X-Frame-Options header to prevent clickjacking"
            }
        }
        
        Write-Log -Message "Completed web server security check for $ServerName" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test web server security: $_" -Level Error
        return $null
    }
}

# Function to test database connection security
function Test-DatabaseConnectionSecurity {
    param (
        [string]$ServerName = $env:COMPUTERNAME
    )
    
    try {
        Write-Log -Message "Starting database connection security check for $ServerName" -Level Info
        
        $results = @{
            ConnectionSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check SQL Server connection settings
        $sqlConnections = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\*\MSSQLServer\SuperSocketNetLib' -ErrorAction SilentlyContinue
        if ($sqlConnections) {
            $results.ConnectionSettings.SQLServer = @{
                TCPEnabled = $sqlConnections.TcpEnabled
                TCPPort = $sqlConnections.TcpPort
                ForceEncryption = $sqlConnections.ForceEncryption
                CertificateThumbprint = $sqlConnections.CertificateThumbprint
            }
            
            # Check for security issues
            if (-not $results.ConnectionSettings.SQLServer.ForceEncryption) {
                $results.SecurityIssues += "SQL Server encryption not enforced"
                $results.Recommendations += "Enable ForceEncryption in SQL Server configuration"
            }
        }
        
        # Check MySQL connection settings
        $mysqlConfig = Get-Content "C:\ProgramData\MySQL\MySQL Server 8.0\my.ini" -ErrorAction SilentlyContinue
        if ($mysqlConfig) {
            $results.ConnectionSettings.MySQL = @{
                SSLEnabled = ($mysqlConfig | Select-String "ssl-ca").Count -gt 0
                SSLVerify = ($mysqlConfig | Select-String "ssl-verify-server-cert").Count -gt 0
                MaxConnections = ($mysqlConfig | Select-String "max_connections").ToString()
            }
            
            # Check for security issues
            if (-not $results.ConnectionSettings.MySQL.SSLEnabled) {
                $results.SecurityIssues += "MySQL SSL not enabled"
                $results.Recommendations += "Enable SSL in MySQL configuration"
            }
        }
        
        Write-Log -Message "Completed database connection security check for $ServerName" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test database connection security: $_" -Level Error
        return $null
    }
}

# Function to test application security headers
function Test-SecurityHeaders {
    param (
        [string]$Url = "http://localhost"
    )
    
    try {
        Write-Log -Message "Starting security headers check for $Url" -Level Info
        
        $results = @{
            Headers = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        $response = Invoke-WebRequest -Uri $Url -Method Head -ErrorAction SilentlyContinue
        if ($response) {
            $results.Headers = @{
                XFrameOptions = $response.Headers["X-Frame-Options"]
                XSSProtection = $response.Headers["X-XSS-Protection"]
                ContentSecurityPolicy = $response.Headers["Content-Security-Policy"]
                StrictTransportSecurity = $response.Headers["Strict-Transport-Security"]
                XContentTypeOptions = $response.Headers["X-Content-Type-Options"]
                ReferrerPolicy = $response.Headers["Referrer-Policy"]
            }
            
            # Check for missing security headers
            if (-not $results.Headers.XFrameOptions) {
                $results.SecurityIssues += "X-Frame-Options header missing"
                $results.Recommendations += "Add X-Frame-Options header to prevent clickjacking"
            }
            
            if (-not $results.Headers.XSSProtection) {
                $results.SecurityIssues += "X-XSS-Protection header missing"
                $results.Recommendations += "Add X-XSS-Protection header to enable browser XSS filtering"
            }
            
            if (-not $results.Headers.ContentSecurityPolicy) {
                $results.SecurityIssues += "Content-Security-Policy header missing"
                $results.Recommendations += "Add Content-Security-Policy header to prevent XSS and other injection attacks"
            }
            
            if (-not $results.Headers.StrictTransportSecurity) {
                $results.SecurityIssues += "Strict-Transport-Security header missing"
                $results.Recommendations += "Add Strict-Transport-Security header to enforce HTTPS"
            }
        }
        
        Write-Log -Message "Completed security headers check for $Url" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test security headers: $_" -Level Error
        return $null
    }
}

# Main menu function
function Show-Menu {
    Write-Host "`nAdvanced Security Checks Menu" -ForegroundColor Cyan
    Write-Host "1. Start All Security Checks"
    Write-Host "2. Network Security Checks"
    Write-Host "3. System Security Checks"
    Write-Host "4. Application Security Checks"
    Write-Host "5. Compliance Checks"
    Write-Host "6. Registry Security Checks"
    Write-Host "7. Service Security Checks"
    Write-Host "8. Antivirus Status Check"
    Write-Host "9. System Updates Check"
    Write-Host "10. Browser Security Check"
    Write-Host "11. Application Whitelisting Check"
    Write-Host "12. Email Security Check"
    Write-Host "13. Network Share Permissions Check"
    Write-Host "14. Database Security Check"
    Write-Host "15. Cloud Service Security Check"
    Write-Host "16. Web Server Security Check"
    Write-Host "17. Database Connection Security Check"
    Write-Host "18. Security Headers Check"
    Write-Host "19. SharePoint Security Check"
    Write-Host "20. Exchange Security Check"
    Write-Host "21. Custom Application Security Check"
    Write-Host "22. View Previous Reports"
    Write-Host "23. Exit"
    
    $choice = Read-Host "`nEnter your choice (1-23)"
    
    switch ($choice) {
        "1" {
            $networkChecks = Test-NetworkPorts
            $systemChecks = Test-FirewallConfiguration
            $appChecks = Test-UserAccountSecurity
            $complianceChecks = Test-PasswordPolicy
            $registryChecks = Test-RegistrySecurity
            $serviceChecks = Test-ServiceSecurity
            $antivirusChecks = Test-AntivirusStatus
            $updateChecks = Test-SystemUpdates
            $browserChecks = Test-BrowserSecurity
            $whitelistChecks = Test-ApplicationWhitelisting
            $emailChecks = Test-EmailSecurity
            $shareChecks = Test-NetworkSharePermissions
            $dbChecks = Test-DatabaseSecurity
            $cloudChecks = Test-CloudServiceSecurity
            $webServerChecks = Test-WebServerSecurity
            $dbConnectionChecks = Test-DatabaseConnectionSecurity
            $securityHeaderChecks = Test-SecurityHeaders
            $sharePointChecks = Test-SharePointSecurity
            $exchangeChecks = Test-ExchangeSecurity
            $customAppChecks = Test-CustomApplicationSecurity
            
            New-EnhancedSecurityReport -Target $env:COMPUTERNAME `
                                     -NetworkChecks $networkChecks `
                                     -SystemChecks $systemChecks `
                                     -ApplicationChecks $appChecks `
                                     -ComplianceChecks $complianceChecks `
                                     -RegistryChecks $registryChecks `
                                     -ServiceChecks $serviceChecks `
                                     -AntivirusChecks $antivirusChecks `
                                     -UpdateChecks $updateChecks `
                                     -BrowserChecks $browserChecks `
                                     -WhitelistChecks $whitelistChecks `
                                     -EmailChecks $emailChecks `
                                     -ShareChecks $shareChecks `
                                     -DatabaseChecks $dbChecks `
                                     -CloudChecks $cloudChecks `
                                     -WebServerChecks $webServerChecks `
                                     -DbConnectionChecks $dbConnectionChecks `
                                     -SecurityHeaderChecks $securityHeaderChecks `
                                     -SharePointChecks $sharePointChecks `
                                     -ExchangeChecks $exchangeChecks `
                                     -CustomAppChecks $customAppChecks
        }
        "2" { Test-NetworkPorts }
        "3" { Test-FirewallConfiguration }
        "4" { Test-UserAccountSecurity }
        "5" { Test-PasswordPolicy }
        "6" { Test-RegistrySecurity }
        "7" { Test-ServiceSecurity }
        "8" { Test-AntivirusStatus }
        "9" { Test-SystemUpdates }
        "10" { Test-BrowserSecurity }
        "11" { Test-ApplicationWhitelisting }
        "12" { Test-EmailSecurity }
        "13" { Test-NetworkSharePermissions }
        "14" { Test-DatabaseSecurity }
        "15" { Test-CloudServiceSecurity }
        "16" { Test-WebServerSecurity }
        "17" { Test-DatabaseConnectionSecurity }
        "18" { Test-SecurityHeaders }
        "19" { Test-SharePointSecurity }
        "20" { Test-ExchangeSecurity }
        "21" { Test-CustomApplicationSecurity }
        "22" {
            $reports = Get-ChildItem -Path $reportPath -Filter "enhanced_security_report_*.html" | Sort-Object LastWriteTime -Descending
            if ($reports) {
                Write-Host "`nRecent Reports:" -ForegroundColor Cyan
                $reports | ForEach-Object { Write-Host $_.Name }
                $reportChoice = Read-Host "`nEnter report name to view (or press Enter to return)"
                if ($reportChoice) {
                    Start-Process "$reportPath\$reportChoice"
                }
            }
            else {
                Write-Host "No reports found." -ForegroundColor Yellow
            }
        }
        "23" { exit }
        default { Write-Host "Invalid choice. Please try again." -ForegroundColor Red }
    }
    
    Show-Menu
}

# Start the menu
Show-Menu 