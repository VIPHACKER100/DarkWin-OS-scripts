# advanced_security_checks_enhanced.ps1
# Advanced Security Assessment Tool - Enhanced Version
# Version: 2.0
# Description: Comprehensive security assessment with enhanced reporting and automation

# ============================================
# MODULE IMPORTS AND INITIALIZATION
# ============================================

# Import required modules with error handling
try {
    Import-Module PSLogging -ErrorAction Stop
    Write-Host "PSLogging module loaded successfully" -ForegroundColor Green
} catch {
    Write-Warning "PSLogging module not found. Installing..."
    Install-Module PSLogging -Force -AllowClobber -Scope CurrentUser
    Import-Module PSLogging
}

try {
    # Attempt to load custom security logging module
    Import-Module security_logging -ErrorAction SilentlyContinue
} catch {
    Write-Host "security_logging module not available, using built-in logging" -ForegroundColor Yellow
}

# Script metadata
$ScriptVersion = "2.0"
$ScriptName = "Advanced Security Assessment Tool"
$Author = "Security Team"
$LastUpdated = "2026-01-28"

# ============================================
# CONFIGURATION MANAGEMENT
# ============================================

# Default configuration paths
$Config = @{
    BasePath = "C:\SecurityTools"
    LogPath = "C:\SecurityTools\Logs"
    ReportPath = "C:\SecurityTools\Reports"
    ConfigPath = "C:\SecurityTools\Configs"
    CachePath = "C:\SecurityTools\Cache"
    ConfigFile = "advanced_security_config.json"
    DefaultTarget = $env:COMPUTERNAME
    DefaultCheckType = "Comprehensive"
    LogLevel = "Detailed"
    MaxReportHistory = 30
    EnableAutoUpdates = $true
    EnableEmailNotifications = $false
    EnableRealTimeMonitoring = $false
    RiskThreshold = "High"
}

# Initialize configuration system
function Initialize-Configuration {
    <#
    .SYNOPSIS
    Initializes configuration directories and files
    #>
    
    Write-Log -Message "Initializing configuration system" -Level Info
    
    # Create all required directories
    $directories = @(
        $Config.BasePath,
        $Config.LogPath,
        $Config.ReportPath,
        $Config.ConfigPath,
        $Config.CachePath
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Log -Message "Created directory: $dir" -Level Info
        }
    }
    
    # Create default configuration file if it doesn't exist
    $configFile = Join-Path $Config.ConfigPath $Config.ConfigFile
    if (-not (Test-Path $configFile)) {
        $defaultConfig = @{
            General = @{
                ScriptVersion = $ScriptVersion
                LastRun = $null
                AutoSaveReports = $true
                EnableLogRotation = $true
                MaxLogSizeMB = 50
                LogRetentionDays = 90
            }
            Scanning = @{
                DefaultPortRange = "1-1024,1433,3306,3389,8080,8443"
                ScanTimeoutSeconds = 5
                ConcurrentScans = 10
                EnableServiceDetection = $true
                EnableOSDetection = $true
            }
            Reporting = @{
                DefaultFormat = "HTML"
                IncludeExecutiveSummary = $true
                IncludeDetailedFindings = $true
                IncludeRemediationSteps = $true
                EnableCharts = $true
                EnableTrendAnalysis = $true
                RiskScoreWeights = @{
                    Critical = 10
                    High = 7
                    Medium = 4
                    Low = 1
                }
            }
            Notifications = @{
                EnableEmailAlerts = $false
                EnableSlackNotifications = $false
                EnableTeamsNotifications = $false
                CriticalRiskThreshold = "High"
            }
            Checks = @{
                EnableNetworkChecks = $true
                EnableSystemChecks = $true
                EnableApplicationChecks = $true
                EnableComplianceChecks = $true
                EnableDatabaseChecks = $true
                EnableCloudChecks = $true
                EnableContainerChecks = $true
                EnableWebChecks = $true
            }
        }
        
        $defaultConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $configFile -Encoding UTF8
        Write-Log -Message "Created default configuration file: $configFile" -Level Info
    }
    
    # Load configuration
    $loadedConfig = Get-Content $configFile | ConvertFrom-Json -AsHashtable
    $Config = $Config + $loadedConfig
    
    Write-Log -Message "Configuration loaded successfully" -Level Info
    return $true
}

# ============================================
# ENHANCED LOGGING SYSTEM
# ============================================

# Logging configuration
$LoggingConfig = @{
    LogFile = Join-Path $Config.LogPath "advanced_security_$(Get-Date -Format 'yyyy-MM-dd').log"
    MaxLogSize = 50MB
    LogRetentionDays = 90
    EnableConsoleOutput = $true
    EnableFileOutput = $true
    LogLevels = @("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
}

# Enhanced logging function
function Write-EnhancedLog {
    <#
    .SYNOPSIS
    Enhanced logging function with multiple output options
    .PARAMETER Message
    The message to log
    .PARAMETER Level
    Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    .PARAMETER Component
    Component or module name
    .PARAMETER Exception
    Exception object for error logging
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")]
        [string]$Level = "INFO",
        
        [Parameter(Mandatory=$false)]
        [string]$Component = "Main",
        
        [Parameter(Mandatory=$false)]
        [Exception]$Exception = $null
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "$timestamp [$Level] [$Component] $Message"
    
    if ($Exception) {
        $logEntry += "`nException: $($Exception.Message)`nStackTrace: $($Exception.StackTrace)"
    }
    
    # Console output with colors
    if ($LoggingConfig.EnableConsoleOutput) {
        $colorMap = @{
            "DEBUG" = "Gray"
            "INFO" = "White"
            "WARNING" = "Yellow"
            "ERROR" = "Red"
            "CRITICAL" = "DarkRed"
        }
        
        Write-Host $logEntry -ForegroundColor $colorMap[$Level]
    }
    
    # File output
    if ($LoggingConfig.EnableFileOutput) {
        # Check log rotation
        if (Test-Path $LoggingConfig.LogFile) {
            $logFile = Get-Item $LoggingConfig.LogFile
            if ($logFile.Length -gt $LoggingConfig.MaxLogSize) {
                $archiveFile = $LoggingConfig.LogFile -replace '\.log$', "_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                Move-Item $LoggingConfig.LogFile $archiveFile
                Write-EnhancedLog -Message "Log file rotated: $archiveFile" -Level INFO -Component "Logging"
            }
        }
        
        $logEntry | Out-File -FilePath $LoggingConfig.LogFile -Append -Encoding UTF8
    }
    
    # Optional: Send to external logging system (Splunk, ELK, etc.)
    if ($Config.Notifications.EnableExternalLogging) {
        # Implementation for external logging systems
        # This is a placeholder for integration
    }
}

# ============================================
# SECURITY CHECK MODULES
# ============================================

# Network Security Module
class NetworkSecurityModule {
    [hashtable] PerformChecks([string]$Target) {
        Write-EnhancedLog -Message "Starting network security checks for: $Target" -Level INFO -Component "NetworkSecurity"
        
        $results = @{
            Timestamp = Get-Date
            Target = $Target
            Checks = @()
            Findings = @()
            RiskScore = 0
            Status = "Completed"
        }
        
        try {
            # 1. Port Scanning
            $openPorts = $this.ScanPorts($Target)
            $results.Checks += @{
                Name = "Port Scan"
                Status = "Completed"
                Details = $openPorts
            }
            
            # 2. Firewall Analysis
            $firewallStatus = $this.CheckFirewall()
            $results.Checks += @{
                Name = "Firewall Analysis"
                Status = "Completed"
                Details = $firewallStatus
            }
            
            # 3. Network Services
            $services = $this.AnalyzeNetworkServices()
            $results.Checks += @{
                Name = "Network Services Analysis"
                Status = "Completed"
                Details = $services
            }
            
            # 4. DNS Security
            $dnsSecurity = $this.CheckDNSSecurity($Target)
            $results.Checks += @{
                Name = "DNS Security"
                Status = "Completed"
                Details = $dnsSecurity
            }
            
            # 5. SSL/TLS Analysis
            $sslAnalysis = $this.AnalyzeSSL($Target)
            $results.Checks += @{
                Name = "SSL/TLS Analysis"
                Status = "Completed"
                Details = $sslAnalysis
            }
            
            # Calculate risk score
            $results.RiskScore = $this.CalculateRiskScore($results.Checks)
            
        } catch {
            Write-EnhancedLog -Message "Network security checks failed: $_" -Level ERROR -Component "NetworkSecurity" -Exception $_
            $results.Status = "Failed"
            $results.Findings += "Network checks failed: $_"
        }
        
        return $results
    }
    
    [array] ScanPorts([string]$Target) {
        $openPorts = @()
        $commonPorts = @(21, 22, 23, 25, 53, 80, 443, 445, 1433, 3306, 3389, 8080, 8443)
        
        foreach ($port in $commonPorts) {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connection = $tcpClient.BeginConnect($Target, $port, $null, $null)
            $wait = $connection.AsyncWaitHandle.WaitOne(1000, $false)
            
            if ($wait) {
                try {
                    $tcpClient.EndConnect($connection)
                    $openPorts += @{
                        Port = $port
                        Service = $this.GetServiceName($port)
                        Status = "Open"
                        Risk = $this.AssessPortRisk($port)
                    }
                } catch {
                    # Port might be filtered
                }
            }
            
            $tcpClient.Close()
        }
        
        return $openPorts
    }
    
    [hashtable] CheckFirewall() {
        $firewallStatus = @{
            ProfileStatus = @{}
            Rules = @()
            Issues = @()
        }
        
        try {
            # Get firewall profiles
            $profiles = Get-NetFirewallProfile
            foreach ($profile in $profiles) {
                $firewallStatus.ProfileStatus[$profile.Name] = @{
                    Enabled = $profile.Enabled
                    DefaultInboundAction = $profile.DefaultInboundAction
                    DefaultOutboundAction = $profile.DefaultOutboundAction
                }
            }
            
            # Get firewall rules
            $rules = Get-NetFirewallRule | Select-Object -First 50
            $firewallStatus.Rules = $rules
            
            # Check for common issues
            if ($firewallStatus.ProfileStatus.Domain.Enabled -eq $false) {
                $firewallStatus.Issues += "Domain firewall profile is disabled"
            }
            
            if ($firewallStatus.ProfileStatus.Public.DefaultInboundAction -eq "Allow") {
                $firewallStatus.Issues += "Public profile allows inbound connections by default"
            }
            
        } catch {
            Write-EnhancedLog -Message "Firewall check failed: $_" -Level WARNING -Component "NetworkSecurity"
        }
        
        return $firewallStatus
    }
    
    [string] GetServiceName([int]$Port) {
        $serviceMap = @{
            21 = "FTP"
            22 = "SSH"
            23 = "Telnet"
            25 = "SMTP"
            53 = "DNS"
            80 = "HTTP"
            443 = "HTTPS"
            445 = "SMB"
            1433 = "MSSQL"
            3306 = "MySQL"
            3389 = "RDP"
            8080 = "HTTP-Proxy"
            8443 = "HTTPS-Alt"
        }
        
        return $serviceMap[$Port] ?? "Unknown"
    }
    
    [string] AssessPortRisk([int]$Port) {
        $highRiskPorts = @(21, 23, 445, 3389)  # FTP, Telnet, SMB, RDP
        $mediumRiskPorts = @(22, 25, 1433, 3306)  # SSH, SMTP, MSSQL, MySQL
        
        if ($Port -in $highRiskPorts) { return "High" }
        if ($Port -in $mediumRiskPorts) { return "Medium" }
        return "Low"
    }
    
    [int] CalculateRiskScore([array]$Checks) {
        $score = 0
        
        foreach ($check in $Checks) {
            if ($check.Details -is [array]) {
                foreach ($detail in $check.Details) {
                    if ($detail.Risk -eq "High") { $score += 10 }
                    elseif ($detail.Risk -eq "Medium") { $score += 5 }
                    elseif ($detail.Risk -eq "Low") { $score += 2 }
                }
            }
            
            if ($check.Details.Issues -and $check.Details.Issues.Count -gt 0) {
                $score += $check.Details.Issues.Count * 3
            }
        }
        
        return [Math]::Min($score, 100)
    }
}

# System Security Module
class SystemSecurityModule {
    [hashtable] PerformChecks() {
        Write-EnhancedLog -Message "Starting system security checks" -Level INFO -Component "SystemSecurity"
        
        $results = @{
            Timestamp = Get-Date
            Checks = @()
            Findings = @()
            RiskScore = 0
            Status = "Completed"
        }
        
        try {
            # 1. User Account Analysis
            $userAccounts = $this.AnalyzeUserAccounts()
            $results.Checks += @{
                Name = "User Account Analysis"
                Status = "Completed"
                Details = $userAccounts
            }
            
            # 2. Password Policy Review
            $passwordPolicy = $this.CheckPasswordPolicy()
            $results.Checks += @{
                Name = "Password Policy Review"
                Status = "Completed"
                Details = $passwordPolicy
            }
            
            # 3. File System Permissions
            $filePermissions = $this.CheckFilePermissions()
            $results.Checks += @{
                Name = "File System Permissions"
                Status = "Completed"
                Details = $filePermissions
            }
            
            # 4. Registry Security
            $registrySecurity = $this.CheckRegistrySecurity()
            $results.Checks += @{
                Name = "Registry Security"
                Status = "Completed"
                Details = $registrySecurity
            }
            
            # 5. Service Configuration
            $services = $this.AnalyzeServices()
            $results.Checks += @{
                Name = "Service Configuration Analysis"
                Status = "Completed"
                Details = $services
            }
            
            # 6. Patch Management
            $patches = $this.CheckPatchStatus()
            $results.Checks += @{
                Name = "Patch Management"
                Status = "Completed"
                Details = $patches
            }
            
            # Calculate risk score
            $results.RiskScore = $this.CalculateRiskScore($results.Checks)
            
        } catch {
            Write-EnhancedLog -Message "System security checks failed: $_" -Level ERROR -Component "SystemSecurity" -Exception $_
            $results.Status = "Failed"
            $results.Findings += "System checks failed: $_"
        }
        
        return $results
    }
    
    [hashtable] AnalyzeUserAccounts() {
        $analysis = @{
            LocalUsers = @()
            DomainUsers = @()
            Issues = @()
            Recommendations = @()
        }
        
        try {
            # Get local users
            $localUsers = Get-LocalUser
            foreach ($user in $localUsers) {
                $analysis.LocalUsers += @{
                    Name = $user.Name
                    Enabled = $user.Enabled
                    LastLogon = $user.LastLogon
                    PasswordChangeable = $user.PasswordChangeable
                    PasswordExpires = $user.PasswordExpires
                }
                
                # Check for issues
                if ($user.Enabled -and $user.Name -notin @("Administrator", "Guest", "DefaultAccount")) {
                    if ($user.PasswordExpires -eq $false) {
                        $analysis.Issues += "User '$($user.Name)' has non-expiring password"
                    }
                }
            }
            
            # Check for inactive accounts
            $inactiveThreshold = (Get-Date).AddDays(-90)
            $inactiveUsers = $analysis.LocalUsers | Where-Object { 
                $_.LastLogon -and $_.LastLogon -lt $inactiveThreshold -and $_.Enabled
            }
            
            if ($inactiveUsers.Count -gt 0) {
                $analysis.Issues += "Found $($inactiveUsers.Count) inactive user accounts"
                $analysis.Recommendations += "Review and disable inactive user accounts"
            }
            
            # Check for default accounts
            $defaultAccounts = $analysis.LocalUsers | Where-Object { 
                $_.Name -in @("Administrator", "Guest") -and $_.Enabled
            }
            
            if ($defaultAccounts.Count -gt 0) {
                $analysis.Issues += "Default accounts are enabled"
                $analysis.Recommendations += "Disable or rename default accounts"
            }
            
        } catch {
            Write-EnhancedLog -Message "User account analysis failed: $_" -Level WARNING -Component "SystemSecurity"
        }
        
        return $analysis
    }
    
    [hashtable] CheckPasswordPolicy() {
        $policy = @{
            CurrentSettings = $null
            Issues = @()
            Recommendations = @()
            Compliance = @{
                NIST = $false
                CIS = $false
                Microsoft = $false
            }
        }
        
        try {
            # Get domain password policy
            $domainPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
            if ($domainPolicy) {
                $policy.CurrentSettings = @{
                    ComplexityEnabled = $domainPolicy.ComplexityEnabled
                    LockoutDuration = $domainPolicy.LockoutDuration
                    LockoutObservationWindow = $domainPolicy.LockoutObservationWindow
                    LockoutThreshold = $domainPolicy.LockoutThreshold
                    MaxPasswordAge = $domainPolicy.MaxPasswordAge
                    MinPasswordAge = $domainPolicy.MinPasswordAge
                    MinPasswordLength = $domainPolicy.MinPasswordLength
                    PasswordHistoryCount = $domainPolicy.PasswordHistoryCount
                    ReversibleEncryptionEnabled = $domainPolicy.ReversibleEncryptionEnabled
                }
                
                # Check compliance
                if ($domainPolicy.MinPasswordLength -ge 12) {
                    $policy.Compliance.NIST = $true
                }
                
                if ($domainPolicy.ComplexityEnabled -and $domainPolicy.MinPasswordLength -ge 8) {
                    $policy.Compliance.CIS = $true
                }
                
                if ($domainPolicy.LockoutThreshold -le 10) {
                    $policy.Compliance.Microsoft = $true
                }
                
                # Identify issues
                if ($domainPolicy.MinPasswordLength -lt 8) {
                    $policy.Issues += "Minimum password length is less than 8 characters"
                    $policy.Recommendations += "Increase minimum password length to at least 12 characters"
                }
                
                if (-not $domainPolicy.ComplexityEnabled) {
                    $policy.Issues += "Password complexity is disabled"
                    $policy.Recommendations += "Enable password complexity requirements"
                }
                
                if ($domainPolicy.ReversibleEncryptionEnabled) {
                    $policy.Issues += "Reversible encryption is enabled (stores passwords in plain text)"
                    $policy.Recommendations += "Disable reversible encryption immediately"
                }
                
                if ($domainPolicy.MaxPasswordAge.TotalDays -gt 90) {
                    $policy.Issues += "Maximum password age exceeds 90 days"
                    $policy.Recommendations += "Set maximum password age to 90 days or less"
                }
            }
            
        } catch {
            Write-EnhancedLog -Message "Password policy check failed: $_" -Level WARNING -Component "SystemSecurity"
        }
        
        return $policy
    }
}

# Compliance Module
class ComplianceModule {
    [hashtable] PerformChecks() {
        Write-EnhancedLog -Message "Starting compliance checks" -Level INFO -Component "Compliance"
        
        $results = @{
            Timestamp = Get-Date
            Standards = @()
            OverallCompliance = 0
            Status = "Completed"
        }
        
        try {
            # GDPR Compliance
            $gdpr = $this.CheckGDPRCompliance()
            $results.Standards += @{
                Standard = "GDPR"
                Compliance = $gdpr.ComplianceScore
                Findings = $gdpr.Findings
                Recommendations = $gdpr.Recommendations
            }
            
            # PCI DSS Compliance
            $pci = $this.CheckPCICompliance()
            $results.Standards += @{
                Standard = "PCI DSS"
                Compliance = $pci.ComplianceScore
                Findings = $pci.Findings
                Recommendations = $pci.Recommendations
            }
            
            # HIPAA Compliance
            $hipaa = $this.CheckHIPAACompliance()
            $results.Standards += @{
                Standard = "HIPAA"
                Compliance = $hipaa.ComplianceScore
                Findings = $hipaa.Findings
                Recommendations = $hipaa.Recommendations
            }
            
            # ISO 27001 Compliance
            $iso = $this.CheckISO27001Compliance()
            $results.Standards += @{
                Standard = "ISO 27001"
                Compliance = $iso.ComplianceScore
                Findings = $iso.Findings
                Recommendations = $iso.Recommendations
            }
            
            # Calculate overall compliance
            $totalScore = 0
            foreach ($standard in $results.Standards) {
                $totalScore += $standard.Compliance
            }
            $results.OverallCompliance = [Math]::Round($totalScore / $results.Standards.Count, 2)
            
        } catch {
            Write-EnhancedLog -Message "Compliance checks failed: $_" -Level ERROR -Component "Compliance" -Exception $_
            $results.Status = "Failed"
        }
        
        return $results
    }
    
    [hashtable] CheckGDPRCompliance() {
        $gdprCheck = @{
            ComplianceScore = 0
            Findings = @()
            Recommendations = @()
            Requirements = @()
        }
        
        try {
            # Check data protection measures
            $gdprCheck.Requirements = @(
                @{ Name = "Data Inventory"; Status = $this.CheckDataInventory() },
                @{ Name = "Consent Management"; Status = $this.CheckConsentManagement() },
                @{ Name = "Data Protection Officer"; Status = $this.CheckDPO() },
                @{ Name = "Privacy by Design"; Status = $this.CheckPrivacyByDesign() },
                @{ Name = "Data Breach Notification"; Status = $this.CheckBreachNotification() },
                @{ Name = "Data Subject Rights"; Status = $this.CheckDataSubjectRights() },
                @{ Name = "Data Transfer Safeguards"; Status = $this.CheckDataTransfer() }
            )
            
            # Calculate compliance score
            $metRequirements = ($gdprCheck.Requirements | Where-Object { $_.Status -eq $true }).Count
            $gdprCheck.ComplianceScore = [Math]::Round(($metRequirements / $gdprCheck.Requirements.Count) * 100, 2)
            
            # Generate findings and recommendations
            if ($gdprCheck.ComplianceScore -lt 80) {
                $gdprCheck.Findings += "GDPR compliance is below acceptable threshold"
                $gdprCheck.Recommendations += "Implement missing GDPR requirements"
            }
            
        } catch {
            Write-EnhancedLog -Message "GDPR compliance check failed: $_" -Level WARNING -Component "Compliance"
        }
        
        return $gdprCheck
    }
    
    [hashtable] CheckPCICompliance() {
        $pciCheck = @{
            ComplianceScore = 0
            Findings = @()
            Recommendations = @()
            Requirements = @()
        }
        
        try {
            # Check PCI DSS requirements
            $pciCheck.Requirements = @(
                @{ Name = "Firewall Configuration"; Status = $this.CheckPCIFirewall() },
                @{ Name = "Cardholder Data Protection"; Status = $this.CheckCardholderData() },
                @{ Name = "Vulnerability Management"; Status = $this.CheckVulnerabilityManagement() },
                @{ Name = "Access Control"; Status = $this.CheckPCIAccessControl() },
                @{ Name = "Network Monitoring"; Status = $this.CheckNetworkMonitoring() },
                @{ Name = "Security Policies"; Status = $this.CheckSecurityPolicies() }
            )
            
            # Calculate compliance score
            $metRequirements = ($pciCheck.Requirements | Where-Object { $_.Status -eq $true }).Count
            $pciCheck.ComplianceScore = [Math]::Round(($metRequirements / $pciCheck.Requirements.Count) * 100, 2)
            
            # Critical findings
            if (-not $this.CheckCardholderData()) {
                $pciCheck.Findings += "Cardholder data is not properly protected"
                $pciCheck.Recommendations += "Implement encryption for cardholder data"
            }
            
        } catch {
            Write-EnhancedLog -Message "PCI compliance check failed: $_" -Level WARNING -Component "Compliance"
        }
        
        return $pciCheck
    }
}

# ============================================
# ENHANCED REPORTING SYSTEM
# ============================================

class AdvancedReportGenerator {
    [string] GenerateComprehensiveReport([hashtable]$NetworkResults, [hashtable]$SystemResults, [hashtable]$ComplianceResults) {
        Write-EnhancedLog -Message "Generating comprehensive security report" -Level INFO -Component "Reporting"
        
        $reportId = [Guid]::NewGuid().ToString()
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $reportFile = Join-Path $Config.ReportPath "security_assessment_$timestamp.html"
        
        try {
            # Calculate overall risk score
            $overallRisk = $this.CalculateOverallRisk($NetworkResults, $SystemResults, $ComplianceResults)
            
            # Generate executive summary
            $executiveSummary = $this.GenerateExecutiveSummary($overallRisk, $NetworkResults, $SystemResults, $ComplianceResults)
            
            # Generate detailed findings
            $detailedFindings = $this.GenerateDetailedFindings($NetworkResults, $SystemResults, $ComplianceResults)
            
            # Generate remediation plan
            $remediationPlan = $this.GenerateRemediationPlan($NetworkResults, $SystemResults, $ComplianceResults)
            
            # Generate charts data
            $chartsData = $this.GenerateChartsData($NetworkResults, $SystemResults, $ComplianceResults)
            
            # Create HTML report
            $html = $this.CreateHTMLReport($executiveSummary, $detailedFindings, $remediationPlan, $chartsData, $overallRisk)
            
            $html | Out-File -FilePath $reportFile -Encoding UTF8
            Write-EnhancedLog -Message "Report generated: $reportFile" -Level INFO -Component "Reporting"
            
            return $reportFile
            
        } catch {
            Write-EnhancedLog -Message "Report generation failed: $_" -Level ERROR -Component "Reporting" -Exception $_
            return $null
        }
    }
    
    [hashtable] CalculateOverallRisk([hashtable]$NetworkResults, [hashtable]$SystemResults, [hashtable]$ComplianceResults) {
        $riskScore = @{
            Network = $NetworkResults.RiskScore
            System = $SystemResults.RiskScore
            Compliance = (100 - $ComplianceResults.OverallCompliance)
            Overall = 0
            Level = "Low"
            Trend = "Stable"
        }
        
        # Weighted average
        $riskScore.Overall = [Math]::Round((
            ($riskScore.Network * 0.4) + 
            ($riskScore.System * 0.4) + 
            ($riskScore.Compliance * 0.2)
        ), 2)
        
        # Determine risk level
        if ($riskScore.Overall -ge 80) { $riskScore.Level = "Critical" }
        elseif ($riskScore.Overall -ge 60) { $riskScore.Level = "High" }
        elseif ($riskScore.Overall -ge 40) { $riskScore.Level = "Medium" }
        elseif ($riskScore.Overall -ge 20) { $riskScore.Level = "Low" }
        else { $riskScore.Level = "Very Low" }
        
        return $riskScore
    }
    
    [hashtable] GenerateExecutiveSummary([hashtable]$RiskScore, [hashtable]$Network, [hashtable]$System, [hashtable]$Compliance) {
        $summary = @{
            ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Target = $Network.Target
            OverallRisk = $RiskScore.Level
            RiskScore = $RiskScore.Overall
            KeyFindings = @()
            TopRecommendations = @()
            ComplianceStatus = "$($Compliance.OverallCompliance)%"
        }
        
        # Extract key findings
        if ($Network.Findings.Count -gt 0) {
            $summary.KeyFindings += "Network: $($Network.Findings[0])"
        }
        
        if ($System.Findings.Count -gt 0) {
            $summary.KeyFindings += "System: $($System.Findings[0])"
        }
        
        if ($Compliance.Standards.Count -gt 0) {
            $lowestCompliance = $Compliance.Standards | Sort-Object Compliance | Select-Object -First 1
            $summary.KeyFindings += "Compliance: $($lowestCompliance.Standard) compliance is $($lowestCompliance.Compliance)%"
        }
        
        # Generate top recommendations
        $allIssues = @()
        $allIssues += $Network.Checks | Where-Object { $_.Details.Issues } | ForEach-Object { $_.Details.Issues }
        $allIssues += $System.Checks | Where-Object { $_.Details.Issues } | ForEach-Object { $_.Details.Issues }
        
        $summary.TopRecommendations = $allIssues | Select-Object -First 5 | ForEach-Object {
            "Address: $_"
        }
        
        return $summary
    }
    
    [string] CreateHTMLReport([hashtable]$ExecutiveSummary, [hashtable]$DetailedFindings, [hashtable]$RemediationPlan, [hashtable]$ChartsData, [hashtable]$RiskScore) {
        $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comprehensive Security Assessment Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-datalabels@2.0.0"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background-color: #f5f7fa;
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50, #4a6491);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            font-weight: 300;
        }
        
        .header .subtitle {
            font-size: 1.2rem;
            opacity: 0.9;
        }
        
        .risk-banner {
            padding: 20px;
            margin: 20px;
            border-radius: 8px;
            text-align: center;
            font-size: 1.3rem;
            font-weight: bold;
        }
        
        .risk-critical { background: linear-gradient(135deg, #e74c3c, #c0392b); color: white; }
        .risk-high { background: linear-gradient(135deg, #e67e22, #d35400); color: white; }
        .risk-medium { background: linear-gradient(135deg, #f1c40f, #f39c12); color: white; }
        .risk-low { background: linear-gradient(135deg, #2ecc71, #27ae60); color: white; }
        .risk-very-low { background: linear-gradient(135deg, #3498db, #2980b9); color: white; }
        
        .executive-summary {
            background: #f8f9fa;
            padding: 30px;
            margin: 20px;
            border-radius: 8px;
            border-left: 5px solid #3498db;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        
        .summary-card h3 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 1.1rem;
        }
        
        .chart-container {
            padding: 20px;
            margin: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        
        .chart-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .findings-section {
            padding: 30px;
            margin: 20px;
            background: white;
            border-radius: 8px;
        }
        
        .finding-category {
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }
        
        .finding-item {
            background: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid;
        }
        
        .finding-critical { border-left-color: #e74c3c; }
        .finding-high { border-left-color: #e67e22; }
        .finding-medium { border-left-color: #f1c40f; }
        .finding-low { border-left-color: #2ecc71; }
        
        .remediation-section {
            padding: 30px;
            margin: 20px;
            background: linear-gradient(135deg, #1abc9c, #16a085);
            color: white;
            border-radius: 8px;
        }
        
        .remediation-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .remediation-card {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 8px;
            backdrop-filter: blur(10px);
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #7f8c8d;
            font-size: 0.9rem;
            border-top: 1px solid #eee;
        }
        
        @media (max-width: 768px) {
            .chart-grid {
                grid-template-columns: 1fr;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>Comprehensive Security Assessment Report</h1>
            <div class="subtitle">
                Generated on: $($ExecutiveSummary.ReportDate) | Target: $($ExecutiveSummary.Target)
            </div>
        </div>
        
        <!-- Risk Banner -->
        <div class="risk-banner risk-$($RiskScore.Level.ToLower().Replace(' ', '-'))">
            <h2>Overall Risk: $($RiskScore.Level) ($($RiskScore.Overall)%)</h2>
            <p>Risk Trend: $($RiskScore.Trend)</p>
        </div>
        
        <!-- Executive Summary -->
        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Risk Assessment</h3>
                    <p><strong>Overall Risk:</strong> $($RiskScore.Level)</p>
                    <p><strong>Risk Score:</strong> $($RiskScore.Overall)%</p>
                    <p><strong>Network Risk:</strong> $($RiskScore.Network)%</p>
                    <p><strong>System Risk:</strong> $($RiskScore.System)%</p>
                </div>
                
                <div class="summary-card">
                    <h3>Compliance Status</h3>
                    <p><strong>Overall Compliance:</strong> $($ExecutiveSummary.ComplianceStatus)</p>
                    <p><strong>GDPR:</strong> $($Compliance.Standards | Where-Object { $_.Standard -eq 'GDPR' } | Select-Object -ExpandProperty Compliance)%</p>
                    <p><strong>PCI DSS:</strong> $($Compliance.Standards | Where-Object { $_.Standard -eq 'PCI DSS' } | Select-Object -ExpandProperty Compliance)%</p>
                    <p><strong>HIPAA:</strong> $($Compliance.Standards | Where-Object { $_.Standard -eq 'HIPAA' } | Select-Object -ExpandProperty Compliance)%</p>
                </div>
                
                <div class="summary-card">
                    <h3>Key Metrics</h3>
                    <p><strong>Network Checks:</strong> $($Network.Checks.Count) completed</p>
                    <p><strong>System Checks:</strong> $($System.Checks.Count) completed</p>
                    <p><strong>Open Ports Found:</strong> $(($Network.Checks | Where-Object { $_.Name -eq 'Port Scan' }).Details.Count)</p>
                    <p><strong>Security Issues:</strong> $(($Network.Findings + $System.Findings).Count)</p>
                </div>
            </div>
            
            <div style="margin-top: 20px;">
                <h3>Top Recommendations</h3>
                <ul style="margin-left: 20px;">
                    $(foreach ($rec in $ExecutiveSummary.TopRecommendations) {
                        "<li>$rec</li>"
                    })
                </ul>
            </div>
        </div>
        
        <!-- Charts Section -->
        <div class="chart-container">
            <h2>Security Assessment Dashboard</h2>
            <div class="chart-grid">
                <div>
                    <canvas id="riskDistributionChart"></canvas>
                </div>
                <div>
                    <canvas id="complianceRadarChart"></canvas>
                </div>
                <div>
                    <canvas id="vulnerabilityTrendChart"></canvas>
                </div>
                <div>
                    <canvas id="serviceAnalysisChart"></canvas>
                </div>
            </div>
        </div>
        
        <!-- Detailed Findings -->
        <div class="findings-section">
            <h2>Detailed Security Findings</h2>
            
            <!-- Network Findings -->
            <div class="finding-category">
                <h3>Network Security Findings</h3>
                $(foreach ($check in $Network.Checks) {
                    if ($check.Details.Issues -and $check.Details.Issues.Count -gt 0) {
                        "<h4>$($check.Name)</h4>"
                        foreach ($issue in $check.Details.Issues) {
                            $riskLevel = "medium"
                            if ($issue -match "critical|high risk") { $riskLevel = "critical" }
                            elseif ($issue -match "medium") { $riskLevel = "medium" }
                            elseif ($issue -match "low") { $riskLevel = "low" }
                            "<div class='finding-item finding-$riskLevel'>$issue</div>"
                        }
                    }
                })
            </div>
            
            <!-- System Findings -->
            <div class="finding-category">
                <h3>System Security Findings</h3>
                $(foreach ($check in $System.Checks) {
                    if ($check.Details.Issues -and $check.Details.Issues.Count -gt 0) {
                        "<h4>$($check.Name)</h4>"
                        foreach ($issue in $check.Details.Issues) {
                            $riskLevel = "medium"
                            if ($issue -match "critical|high risk") { $riskLevel = "critical" }
                            elseif ($issue -match "medium") { $riskLevel = "medium" }
                            elseif ($issue -match "low") { $riskLevel = "low" }
                            "<div class='finding-item finding-$riskLevel'>$issue</div>"
                        }
                    }
                })
            </div>
            
            <!-- Compliance Findings -->
            <div class="finding-category">
                <h3>Compliance Findings</h3>
                $(foreach ($standard in $Compliance.Standards) {
                    if ($standard.Findings.Count -gt 0) {
                        "<h4>$($standard.Standard) ($($standard.Compliance)% Compliance)</h4>"
                        foreach ($finding in $standard.Findings) {
                            "<div class='finding-item finding-medium'>$finding</div>"
                        }
                        "<h5>Recommendations:</h5>"
                        foreach ($rec in $standard.Recommendations) {
                            "<div class='finding-item finding-low'>$rec</div>"
                        }
                    }
                })
            </div>
        </div>
        
        <!-- Remediation Plan -->
        <div class="remediation-section">
            <h2>Remediation Action Plan</h2>
            <div class="remediation-grid">
                <div class="remediation-card">
                    <h3>Immediate Actions (0-7 days)</h3>
                    <ul>
                        <li>Address critical network vulnerabilities</li>
                        <li>Patch high-risk system vulnerabilities</li>
                        <li>Review and update firewall rules</li>
                        <li>Disable unnecessary services</li>
                    </ul>
                </div>
                
                <div class="remediation-card">
                    <h3>Short-term Actions (8-30 days)</h3>
                    <ul>
                        <li>Implement security monitoring</li>
                        <li>Enhance user access controls</li>
                        <li>Update security policies</li>
                        <li>Conduct security awareness training</li>
                    </ul>
                </div>
                
                <div class="remediation-card">
                    <h3>Long-term Actions (31-90 days)</h3>
                    <ul>
                        <li>Implement advanced threat protection</li>
                        <li>Enhance incident response capabilities</li>
                        <li>Conduct regular security assessments</li>
                        <li>Implement continuous compliance monitoring</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>Generated by $ScriptName v$ScriptVersion | Confidential Security Report</p>
            <p>For internal use only | © $(Get-Date -Format 'yyyy') Security Team</p>
        </div>
    </div>
    
    <script>
        // Chart colors
        const colors = {
            critical: '#e74c3c',
            high: '#e67e22',
            medium: '#f1c40f',
            low: '#2ecc71',
            veryLow: '#3498db'
        };
        
        // Risk Distribution Chart
        const riskCtx = document.getElementById('riskDistributionChart').getContext('2d');
        new Chart(riskCtx, {
            type: 'doughnut',
            data: {
                labels: ['Network Risk', 'System Risk', 'Compliance Gap'],
                datasets: [{
                    data: [$($RiskScore.Network), $($RiskScore.System), $($RiskScore.Compliance)],
                    backgroundColor: [colors.high, colors.medium, colors.low],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 20,
                            usePointStyle: true
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return context.label + ': ' + context.parsed + '%';
                            }
                        }
                    }
                }
            }
        });
        
        // Compliance Radar Chart
        const complianceCtx = document.getElementById('complianceRadarChart').getContext('2d');
        new Chart(complianceCtx, {
            type: 'radar',
            data: {
                labels: [$($Compliance.Standards | ForEach-Object { "'$($_.Standard)'" } -join ',')],
                datasets: [{
                    label: 'Compliance Score',
                    data: [$($Compliance.Standards | ForEach-Object { $_.Compliance } -join ',')],
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
                        max: 100,
                        ticks: {
                            stepSize: 20,
                            callback: function(value) {
                                return value + '%';
                            }
                        }
                    }
                },
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
        
        // Vulnerability Trend Chart (mock data)
        const trendCtx = document.getElementById('vulnerabilityTrendChart').getContext('2d');
        new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
                datasets: [
                    {
                        label: 'Critical',
                        data: [12, 8, 15, 10, 7, 5, 9],
                        borderColor: colors.critical,
                        backgroundColor: 'rgba(231, 76, 60, 0.1)',
                        tension: 0.3
                    },
                    {
                        label: 'High',
                        data: [25, 30, 22, 28, 20, 18, 22],
                        borderColor: colors.high,
                        backgroundColor: 'rgba(230, 126, 34, 0.1)',
                        tension: 0.3
                    },
                    {
                        label: 'Medium',
                        data: [40, 35, 45, 38, 42, 39, 41],
                        borderColor: colors.medium,
                        backgroundColor: 'rgba(241, 196, 15, 0.1)',
                        tension: 0.3
                    }
                ]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Number of Vulnerabilities'
                        }
                    }
                }
            }
        });
        
        // Service Analysis Chart
        const serviceCtx = document.getElementById('serviceAnalysisChart').getContext('2d');
        new Chart(serviceCtx, {
            type: 'bar',
            data: {
                labels: ['HTTP', 'HTTPS', 'SSH', 'RDP', 'SQL', 'FTP', 'SMTP'],
                datasets: [{
                    label: 'Security Risk Level',
                    data: [3, 1, 4, 5, 4, 5, 2],
                    backgroundColor: [
                        colors.medium,
                        colors.low,
                        colors.medium,
                        colors.high,
                        colors.medium,
                        colors.high,
                        colors.low
                    ]
                }]
            },
            options: {
                responsive: true,
                indexAxis: 'y',
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        max: 5,
                        title: {
                            display: true,
                            text: 'Risk Level (1-5)'
                        }
                    }
                }
            }
        });
    </script>
</body>
</html>
"@
        
        return $html
    }
}

# ============================================
# MAIN EXECUTION ENGINE
# ============================================

class SecurityAssessmentEngine {
    [void] RunComprehensiveAssessment([string]$Target) {
        Write-EnhancedLog -Message "Starting comprehensive security assessment for: $Target" -Level INFO -Component "Engine"
        
        $startTime = Get-Date
        $assessmentId = [Guid]::NewGuid().ToString()
        
        Write-Host "`n" + "="*60 -ForegroundColor Cyan
        Write-Host "COMPREHENSIVE SECURITY ASSESSMENT" -ForegroundColor Yellow
        Write-Host "="*60 -ForegroundColor Cyan
        Write-Host "Assessment ID: $assessmentId" -ForegroundColor White
        Write-Host "Target: $Target" -ForegroundColor White
        Write-Host "Start Time: $startTime" -ForegroundColor White
        Write-Host "`n"
        
        # Initialize modules
        $networkModule = [NetworkSecurityModule]::new()
        $systemModule = [SystemSecurityModule]::new()
        $complianceModule = [ComplianceModule]::new()
        $reportGenerator = [AdvancedReportGenerator]::new()
        
        # Execute checks in parallel (where possible)
        Write-Host "Executing security checks..." -ForegroundColor Cyan
        
        # Network checks
        Write-Host "`n[1/3] Network Security Checks" -ForegroundColor Green
        $networkResults = $networkModule.PerformChecks($Target)
        $this.DisplayCheckResults($networkResults, "Network")
        
        # System checks
        Write-Host "`n[2/3] System Security Checks" -ForegroundColor Green
        $systemResults = $systemModule.PerformChecks()
        $this.DisplayCheckResults($systemResults, "System")
        
        # Compliance checks
        Write-Host "`n[3/3] Compliance Checks" -ForegroundColor Green
        $complianceResults = $complianceModule.PerformChecks()
        $this.DisplayCheckResults($complianceResults, "Compliance")
        
        # Generate report
        Write-Host "`n" + "-"*60 -ForegroundColor Gray
        Write-Host "GENERATING REPORT..." -ForegroundColor Cyan
        $reportFile = $reportGenerator.GenerateComprehensiveReport($networkResults, $systemResults, $complianceResults)
        
        $endTime = Get-Date
        $duration = $endTime - $startTime
        
        # Display summary
        $this.DisplayAssessmentSummary($assessmentId, $startTime, $endTime, $duration, $reportFile)
        
        # Optional: Send notifications
        if ($Config.Notifications.EnableEmailAlerts) {
            $this.SendNotification($assessmentId, $reportFile)
        }
    }
    
    [void] DisplayCheckResults([hashtable]$Results, [string]$Category) {
        $color = @{
            "Completed" = "Green"
            "Failed" = "Red"
            "Warning" = "Yellow"
        }[$Results.Status]
        
        Write-Host "  Status: " -NoNewline -ForegroundColor White
        Write-Host $Results.Status -ForegroundColor $color
        
        Write-Host "  Checks Completed: " -NoNewline -ForegroundColor White
        Write-Host $Results.Checks.Count -ForegroundColor Cyan
        
        Write-Host "  Risk Score: " -NoNewline -ForegroundColor White
        Write-Host "$($Results.RiskScore)%" -ForegroundColor Cyan
        
        if ($Results.Findings.Count -gt 0) {
            Write-Host "  Findings: " -ForegroundColor White
            foreach ($finding in $Results.Findings | Select-Object -First 3) {
                Write-Host "    • $finding" -ForegroundColor Yellow
            }
            if ($Results.Findings.Count -gt 3) {
                Write-Host "    ... and $($Results.Findings.Count - 3) more" -ForegroundColor Gray
            }
        }
        
        Write-Host ""
    }
    
    [void] DisplayAssessmentSummary([string]$Id, [DateTime]$Start, [DateTime]$End, [TimeSpan]$Duration, [string]$ReportFile) {
        Write-Host "`n" + "="*60 -ForegroundColor Cyan
        Write-Host "ASSESSMENT COMPLETE" -ForegroundColor Green
        Write-Host "="*60 -ForegroundColor Cyan
        
        Write-Host "`nAssessment Details:" -ForegroundColor White
        Write-Host "  ID: $Id" -ForegroundColor Gray
        Write-Host "  Started: $($Start.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
        Write-Host "  Completed: $($End.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
        Write-Host "  Duration: $($Duration.TotalMinutes.ToString('F1')) minutes" -ForegroundColor Gray
        
        if ($ReportFile) {
            Write-Host "`nReport Generated:" -ForegroundColor White
            Write-Host "  Location: $ReportFile" -ForegroundColor Green
            Write-Host "  File Size: $([math]::Round((Get-Item $ReportFile).Length/1KB, 2)) KB" -ForegroundColor Gray
            
            Write-Host "`nTo view the report:" -ForegroundColor White
            Write-Host "  1. Open the file in a web browser" -ForegroundColor Gray
            Write-Host "  2. Review the executive summary" -ForegroundColor Gray
            Write-Host "  3. Address critical findings first" -ForegroundColor Gray
        } else {
            Write-Host "`nReport generation failed!" -ForegroundColor Red
        }
        
        Write-Host "`n" + "="*60 -ForegroundColor Cyan
    }
    
    [void] SendNotification([string]$AssessmentId, [string]$ReportFile) {
        # Placeholder for notification system
        # Can be extended to send emails, Slack messages, etc.
        Write-EnhancedLog -Message "Notification would be sent for assessment: $AssessmentId" -Level INFO -Component "Notifications"
    }
}

# ============================================
# USER INTERFACE AND MENU SYSTEM
# ============================================

function Show-EnhancedMenu {
    <#
    .SYNOPSIS
    Enhanced menu system for security assessment tool
    #>
    
    while ($true) {
        Clear-Host
        Write-Host "`n" + "="*70 -ForegroundColor Cyan
        Write-Host "ADVANCED SECURITY ASSESSMENT TOOL v$ScriptVersion" -ForegroundColor Yellow
        Write-Host "="*70 -ForegroundColor Cyan
        Write-Host ""
        
        Write-Host "Main Menu:" -ForegroundColor White
        Write-Host ""
        Write-Host "  1. Run Comprehensive Security Assessment" -ForegroundColor Green
        Write-Host "  2. Run Specific Security Checks" -ForegroundColor Cyan
        Write-Host "  3. View Previous Reports" -ForegroundColor Cyan
        Write-Host "  4. Configuration Management" -ForegroundColor Cyan
        Write-Host "  5. System Information" -ForegroundColor Cyan
        Write-Host "  6. Help & Documentation" -ForegroundColor Cyan
        Write-Host "  7. Exit" -ForegroundColor Red
        Write-Host ""
        
        $choice = Read-Host "Enter your choice (1-7)"
        
        switch ($choice) {
            "1" {
                Run-ComprehensiveAssessment
                Pause
            }
            "2" {
                Show-SpecificChecksMenu
            }
            "3" {
                View-PreviousReports
                Pause
            }
            "4" {
                Show-ConfigurationMenu
            }
            "5" {
                Show-SystemInfo
                Pause
            }
            "6" {
                Show-Help
                Pause
            }
            "7" {
                Write-EnhancedLog -Message "User exited the application" -Level INFO -Component "UI"
                Write-Host "`nThank you for using the Advanced Security Assessment Tool!" -ForegroundColor Green
                Write-Host "Exiting..." -ForegroundColor Gray
                Start-Sleep -Seconds 2
                exit 0
            }
            default {
                Write-Host "Invalid choice. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

function Run-ComprehensiveAssessment {
    Clear-Host
    Write-Host "`n" + "="*60 -ForegroundColor Cyan
    Write-Host "COMPREHENSIVE SECURITY ASSESSMENT" -ForegroundColor Yellow
    Write-Host "="*60 -ForegroundColor Cyan
    Write-Host ""
    
    # Get target
    $defaultTarget = $Config.DefaultTarget
    $target = Read-Host "Enter target hostname or IP (default: $defaultTarget)"
    if (-not $target) { $target = $defaultTarget }
    
    # Get assessment type
    Write-Host "`nSelect Assessment Type:" -ForegroundColor White
    Write-Host "  1. Full Comprehensive (All checks)" -ForegroundColor Green
    Write-Host "  2. Standard (Essential checks)" -ForegroundColor Yellow
    Write-Host "  3. Quick (Critical checks only)" -ForegroundColor Cyan
    Write-Host ""
    
    $typeChoice = Read-Host "Enter choice (1-3)"
    $assessmentTypes = @{
        "1" = "Comprehensive"
        "2" = "Standard"
        "3" = "Quick"
    }
    
    $assessmentType = $assessmentTypes[$typeChoice] ?? "Standard"
    
    # Confirmation
    Write-Host "`nReady to start assessment:" -ForegroundColor White
    Write-Host "  Target: $target" -ForegroundColor Gray
    Write-Host "  Type: $assessmentType" -ForegroundColor Gray
    Write-Host "  Estimated Time: 5-15 minutes" -ForegroundColor Gray
    Write-Host ""
    
    $confirm = Read-Host "Start assessment? (Y/N)"
    if ($confirm -notmatch "^[Yy]$") {
        Write-Host "Assessment cancelled." -ForegroundColor Yellow
        return
    }
    
    # Run assessment
    $engine = [SecurityAssessmentEngine]::new()
    $engine.RunComprehensiveAssessment($target)
}

function Show-SpecificChecksMenu {
    while ($true) {
        Clear-Host
        Write-Host "`n" + "="*60 -ForegroundColor Cyan
        Write-Host "SPECIFIC SECURITY CHECKS" -ForegroundColor Yellow
        Write-Host "="*60 -ForegroundColor Cyan
        Write-Host ""
        
        Write-Host "Select Check Category:" -ForegroundColor White
        Write-Host ""
        Write-Host "  1. Network Security Checks" -ForegroundColor Green
        Write-Host "  2. System Security Checks" -ForegroundColor Green
        Write-Host "  3. Compliance Checks" -ForegroundColor Green
        Write-Host "  4. Application Security Checks" -ForegroundColor Cyan
        Write-Host "  5. Database Security Checks" -ForegroundColor Cyan
        Write-Host "  6. Cloud Security Checks" -ForegroundColor Cyan
        Write-Host "  7. Container Security Checks" -ForegroundColor Cyan
        Write-Host "  8. Web Security Checks" -ForegroundColor Cyan
        Write-Host "  9. Return to Main Menu" -ForegroundColor Gray
        Write-Host ""
        
        $choice = Read-Host "Enter your choice (1-9)"
        
        switch ($choice) {
            "1" { Run-NetworkChecks }
            "2" { Run-SystemChecks }
            "3" { Run-ComplianceChecks }
            "4" { Write-Host "Application checks coming soon..." -ForegroundColor Yellow; Pause }
            "5" { Write-Host "Database checks coming soon..." -ForegroundColor Yellow; Pause }
            "6" { Write-Host "Cloud checks coming soon..." -ForegroundColor Yellow; Pause }
            "7" { Write-Host "Container checks coming soon..." -ForegroundColor Yellow; Pause }
            "8" { Write-Host "Web checks coming soon..." -ForegroundColor Yellow; Pause }
            "9" { return }
            default {
                Write-Host "Invalid choice. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

function Run-NetworkChecks {
    Clear-Host
    Write-Host "`n" + "="*60 -ForegroundColor Cyan
    Write-Host "NETWORK SECURITY CHECKS" -ForegroundColor Yellow
    Write-Host "="*60 -ForegroundColor Cyan
    Write-Host ""
    
    $target = Read-Host "Enter target to scan (default: localhost)"
    if (-not $target) { $target = "localhost" }
    
    Write-Host "`nStarting network security checks for: $target" -ForegroundColor Green
    
    $networkModule = [NetworkSecurityModule]::new()
    $results = $networkModule.PerformChecks($target)
    
    # Display results
    Write-Host "`n" + "-"*60 -ForegroundColor Gray
    Write-Host "NETWORK SECURITY RESULTS" -ForegroundColor White
    Write-Host "-"*60 -ForegroundColor Gray
    
    foreach ($check in $results.Checks) {
        Write-Host "`n$($check.Name):" -ForegroundColor Cyan
        
        if ($check.Details -is [array]) {
            foreach ($detail in $check.Details) {
                Write-Host "  • Port $($detail.Port) ($($detail.Service)): $($detail.Status) - Risk: $($detail.Risk)" -ForegroundColor Gray
            }
        }
        
        if ($check.Details.Issues -and $check.Details.Issues.Count -gt 0) {
            Write-Host "  Issues Found:" -ForegroundColor Yellow
            foreach ($issue in $check.Details.Issues) {
                Write-Host "    - $issue" -ForegroundColor Red
            }
        }
    }
    
    Write-Host "`nOverall Network Risk Score: $($results.RiskScore)%" -ForegroundColor White
    
    Pause
}

function Run-SystemChecks {
    Clear-Host
    Write-Host "`n" + "="*60 -ForegroundColor Cyan
    Write-Host "SYSTEM SECURITY CHECKS" -ForegroundColor Yellow
    Write-Host "="*60 -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Starting system security checks..." -ForegroundColor Green
    
    $systemModule = [SystemSecurityModule]::new()
    $results = $systemModule.PerformChecks()
    
    # Display results
    Write-Host "`n" + "-"*60 -ForegroundColor Gray
    Write-Host "SYSTEM SECURITY RESULTS" -ForegroundColor White
    Write-Host "-"*60 -ForegroundColor Gray
    
    foreach ($check in $results.Checks) {
        Write-Host "`n$($check.Name):" -ForegroundColor Cyan
        
        if ($check.Details.Issues -and $check.Details.Issues.Count -gt 0) {
            Write-Host "  Issues Found ($($check.Details.Issues.Count)):" -ForegroundColor Yellow
            foreach ($issue in $check.Details.Issues | Select-Object -First 5) {
                Write-Host "    - $issue" -ForegroundColor Red
            }
        } else {
            Write-Host "  No issues found" -ForegroundColor Green
        }
        
        if ($check.Details.Recommendations -and $check.Details.Recommendations.Count -gt 0) {
            Write-Host "  Recommendations:" -ForegroundColor Blue
            foreach ($rec in $check.Details.Recommendations | Select-Object -First 3) {
                Write-Host "    • $rec" -ForegroundColor Gray
            }
        }
    }
    
    Write-Host "`nOverall System Risk Score: $($results.RiskScore)%" -ForegroundColor White
    
    Pause
}

function Run-ComplianceChecks {
    Clear-Host
    Write-Host "`n" + "="*60 -ForegroundColor Cyan
    Write-Host "COMPLIANCE CHECKS" -ForegroundColor Yellow
    Write-Host "="*60 -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Starting compliance checks..." -ForegroundColor Green
    
    $complianceModule = [ComplianceModule]::new()
    $results = $complianceModule.PerformChecks()
    
    # Display results
    Write-Host "`n" + "-"*60 -ForegroundColor Gray
    Write-Host "COMPLIANCE RESULTS" -ForegroundColor White
    Write-Host "-"*60 -ForegroundColor Gray
    
    Write-Host "`nOverall Compliance: $($results.OverallCompliance)%" -ForegroundColor Cyan
    
    foreach ($standard in $results.Standards) {
        Write-Host "`n$($standard.Standard): $($standard.Compliance)%" -ForegroundColor White
        
        if ($standard.Findings.Count -gt 0) {
            Write-Host "  Findings:" -ForegroundColor Yellow
            foreach ($finding in $standard.Findings | Select-Object -First 3) {
                Write-Host "    - $finding" -ForegroundColor Red
            }
        }
        
        if ($standard.Recommendations.Count -gt 0) {
            Write-Host "  Recommendations:" -ForegroundColor Blue
            foreach ($rec in $standard.Recommendations | Select-Object -First 3) {
                Write-Host "    • $rec" -ForegroundColor Gray
            }
        }
    }
    
    Pause
}

function View-PreviousReports {
    Clear-Host
    Write-Host "`n" + "="*60 -ForegroundColor Cyan
    Write-Host "PREVIOUS REPORTS" -ForegroundColor Yellow
    Write-Host "="*60 -ForegroundColor Cyan
    Write-Host ""
    
    $reports = Get-ChildItem -Path $Config.ReportPath -Filter "*.html" | Sort-Object LastWriteTime -Descending
    
    if ($reports.Count -eq 0) {
        Write-Host "No reports found." -ForegroundColor Yellow
        return
    }
    
    Write-Host "Recent Reports:" -ForegroundColor White
    Write-Host ""
    
    $index = 1
    foreach ($report in $reports | Select-Object -First 10) {
        $sizeKB = [math]::Round($report.Length / 1KB, 2)
        Write-Host "  $index. $($report.Name)" -ForegroundColor Gray
        Write-Host "     Created: $($report.LastWriteTime) | Size: ${sizeKB} KB" -ForegroundColor DarkGray
        $index++
    }
    
    Write-Host ""
    Write-Host "Options:" -ForegroundColor White
    Write-Host "  1-10: Open report in browser" -ForegroundColor Cyan
    Write-Host "  C: Clean old reports (keep last $($Config.MaxReportHistory))" -ForegroundColor Yellow
    Write-Host "  R: Return to menu" -ForegroundColor Gray
    Write-Host ""
    
    $choice = Read-Host "Enter your choice"
    
    if ($choice -match '^\d+$' -and [int]$choice -le $reports.Count -and [int]$choice -gt 0) {
        $selectedReport = $reports[[int]$choice - 1]
        Write-Host "Opening: $($selectedReport.FullName)" -ForegroundColor Green
        Start-Process $selectedReport.FullName
    }
    elseif ($choice -eq "C") {
        # Clean old reports
        $keepCount = $Config.MaxReportHistory
        $oldReports = $reports | Select-Object -Skip $keepCount
        
        if ($oldReports.Count -gt 0) {
            Write-Host "`nRemoving $($oldReports.Count) old reports..." -ForegroundColor Yellow
            foreach ($report in $oldReports) {
                Remove-Item $report.FullName -Force
                Write-Host "  Removed: $($report.Name)" -ForegroundColor Gray
            }
            Write-Host "Cleanup complete." -ForegroundColor Green
        } else {
            Write-Host "No old reports to clean." -ForegroundColor Yellow
        }
        Start-Sleep -Seconds 2
    }
}

function Show-ConfigurationMenu {
    while ($true) {
        Clear-Host
        Write-Host "`n" + "="*60 -ForegroundColor Cyan
        Write-Host "CONFIGURATION MANAGEMENT" -ForegroundColor Yellow
        Write-Host "="*60 -ForegroundColor Cyan
        Write-Host ""
        
        Write-Host "Configuration Options:" -ForegroundColor White
        Write-Host ""
        Write-Host "  1. View Current Configuration" -ForegroundColor Cyan
        Write-Host "  2. Edit Configuration" -ForegroundColor Cyan
        Write-Host "  3. Reset to Defaults" -ForegroundColor Yellow
        Write-Host "  4. Backup Configuration" -ForegroundColor Green
        Write-Host "  5. Restore Configuration" -ForegroundColor Green
        Write-Host "  6. Test Configuration" -ForegroundColor Blue
        Write-Host "  7. Return to Main Menu" -ForegroundColor Gray
        Write-Host ""
        
        $choice = Read-Host "Enter your choice (1-7)"
        
        switch ($choice) {
            "1" { 
                View-Configuration 
                Pause
            }
            "2" { 
                Edit-Configuration 
            }
            "3" { 
                Reset-Configuration 
                Pause
            }
            "4" { 
                Backup-Configuration 
                Pause
            }
            "5" { 
                Restore-Configuration 
                Pause
            }
            "6" { 
                Test-Configuration 
                Pause
            }
            "7" { return }
            default {
                Write-Host "Invalid choice. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

function View-Configuration {
    Write-Host "`nCurrent Configuration:" -ForegroundColor White
    Write-Host "="*40 -ForegroundColor Gray
    
    # Display main configuration
    $configGroups = @(
        @{ Name = "General Settings"; Items = $Config.General },
        @{ Name = "Scanning Settings"; Items = $Config.Scanning },
        @{ Name = "Reporting Settings"; Items = $Config.Reporting },
        @{ Name = "Notification Settings"; Items = $Config.Notifications },
        @{ Name = "Check Settings"; Items = $Config.Checks }
    )
    
    foreach ($group in $configGroups) {
        Write-Host "`n$($group.Name):" -ForegroundColor Cyan
        if ($group.Items) {
            foreach ($item in $group.Items.GetEnumerator()) {
                Write-Host "  $($item.Key): $($item.Value)" -ForegroundColor Gray
            }
        }
    }
    
    Write-Host "`n" + "="*40 -ForegroundColor Gray
}

function Show-SystemInfo {
    Clear-Host
    Write-Host "`n" + "="*60 -ForegroundColor Cyan
    Write-Host "SYSTEM INFORMATION" -ForegroundColor Yellow
    Write-Host "="*60 -ForegroundColor Cyan
    Write-Host ""
    
    # Get system information
    $os = Get-CimInstance Win32_OperatingSystem
    $computer = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $cpu = Get-CimInstance Win32_Processor
    $memory = Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum
    
    Write-Host "Operating System:" -ForegroundColor White
    Write-Host "  Name: $($os.Caption)" -ForegroundColor Gray
    Write-Host "  Version: $($os.Version)" -ForegroundColor Gray
    Write-Host "  Architecture: $($os.OSArchitecture)" -ForegroundColor Gray
    Write-Host "  Build: $($os.BuildNumber)" -ForegroundColor Gray
    
    Write-Host "`nComputer Information:" -ForegroundColor White
    Write-Host "  Name: $($computer.Name)" -ForegroundColor Gray
    Write-Host "  Manufacturer: $($computer.Manufacturer)" -ForegroundColor Gray
    Write-Host "  Model: $($computer.Model)" -ForegroundColor Gray
    Write-Host "  Domain: $($computer.Domain)" -ForegroundColor Gray
    
    Write-Host "`nBIOS Information:" -ForegroundColor White
    Write-Host "  Manufacturer: $($bios.Manufacturer)" -ForegroundColor Gray
    Write-Host "  Version: $($bios.SMBIOSBIOSVersion)" -ForegroundColor Gray
    Write-Host "  Serial: $($bios.SerialNumber)" -ForegroundColor Gray
    
    Write-Host "`nProcessor Information:" -ForegroundColor White
    Write-Host "  Name: $($cpu.Name)" -ForegroundColor Gray
    Write-Host "  Cores: $($cpu.NumberOfCores)" -ForegroundColor Gray
    Write-Host "  Threads: $($cpu.NumberOfLogicalProcessors)" -ForegroundColor Gray
    Write-Host "  Max Speed: $($cpu.MaxClockSpeed) MHz" -ForegroundColor Gray
    
    Write-Host "`nMemory Information:" -ForegroundColor White
    Write-Host "  Total RAM: $([math]::Round($memory.Sum / 1GB, 2)) GB" -ForegroundColor Gray
    Write-Host "  Free RAM: $([math]::Round($os.FreePhysicalMemory / 1MB, 2)) GB" -ForegroundColor Gray
    
    Write-Host "`nSecurity Tool Information:" -ForegroundColor White
    Write-Host "  Tool Name: $ScriptName" -ForegroundColor Gray
    Write-Host "  Version: $ScriptVersion" -ForegroundColor Gray
    Write-Host "  Author: $Author" -ForegroundColor Gray
    Write-Host "  Last Updated: $LastUpdated" -ForegroundColor Gray
    Write-Host "  Report Path: $($Config.ReportPath)" -ForegroundColor Gray
    Write-Host "  Log Path: $($Config.LogPath)" -ForegroundColor Gray
    
    Write-Host "`n" + "="*60 -ForegroundColor Cyan
}

function Show-Help {
    Clear-Host
    Write-Host "`n" + "="*60 -ForegroundColor Cyan
    Write-Host "HELP & DOCUMENTATION" -ForegroundColor Yellow
    Write-Host "="*60 -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Overview:" -ForegroundColor White
    Write-Host "  This tool provides comprehensive security assessment capabilities" -ForegroundColor Gray
    Write-Host "  for networks, systems, applications, and compliance requirements." -ForegroundColor Gray
    
    Write-Host "`nFeatures:" -ForegroundColor White
    Write-Host "  1. Network Security Scanning" -ForegroundColor Cyan
    Write-Host "  2. System Security Assessment" -ForegroundColor Cyan
    Write-Host "  3. Compliance Verification" -ForegroundColor Cyan
    Write-Host "  4. Detailed Reporting" -ForegroundColor Cyan
    Write-Host "  5. Risk Scoring" -ForegroundColor Cyan
    
    Write-Host "`nUsage:" -ForegroundColor White
    Write-Host "  Main Menu Options:" -ForegroundColor Gray
    Write-Host "    1. Run Comprehensive Assessment - Full security check" -ForegroundColor DarkGray
    Write-Host "    2. Specific Checks - Run individual security checks" -ForegroundColor DarkGray
    Write-Host "    3. View Reports - Access previous assessment reports" -ForegroundColor DarkGray
    Write-Host "    4. Configuration - Customize tool settings" -ForegroundColor DarkGray
    Write-Host "    5. System Info - View system details" -ForegroundColor DarkGray
    Write-Host "    6. Help - This documentation" -ForegroundColor DarkGray
    Write-Host "    7. Exit - Close the application" -ForegroundColor DarkGray
    
    Write-Host "`nPrerequisites:" -ForegroundColor White
    Write-Host "  • Windows 10/11 or Windows Server 2016+" -ForegroundColor Gray
    Write-Host "  • PowerShell 5.1 or later" -ForegroundColor Gray
    Write-Host "  • Administrative privileges" -ForegroundColor Gray
    Write-Host "  • Network connectivity (for remote scans)" -ForegroundColor Gray
    
    Write-Host "`nOutput:" -ForegroundColor White
    Write-Host "  • HTML reports in: $($Config.ReportPath)" -ForegroundColor Gray
    Write-Host "  • Log files in: $($Config.LogPath)" -ForegroundColor Gray
    Write-Host "  • Configuration in: $($Config.ConfigPath)" -ForegroundColor Gray
    
    Write-Host "`nBest Practices:" -ForegroundColor White
    Write-Host "  1. Run comprehensive assessments weekly" -ForegroundColor Gray
    Write-Host "  2. Review reports promptly" -ForegroundColor Gray
    Write-Host "  3. Address critical findings immediately" -ForegroundColor Gray
    Write-Host "  4. Keep the tool updated" -ForegroundColor Gray
    Write-Host "  5. Backup configuration regularly" -ForegroundColor Gray
    
    Write-Host "`nSupport:" -ForegroundColor White
    Write-Host "  • Check logs for error details" -ForegroundColor Gray
    Write-Host "  • Review generated reports" -ForegroundColor Gray
    Write-Host "  • Contact: security-team@example.com" -ForegroundColor Gray
    
    Write-Host "`n" + "="*60 -ForegroundColor Cyan
}

# ============================================
# MAIN EXECUTION
# ============================================

function Main {
    <#
    .SYNOPSIS
    Main execution function
    #>
    
    # Clear screen and show banner
    Clear-Host
    Write-Host "`n" + "*"*70 -ForegroundColor Cyan
    Write-Host "*" -NoNewline -ForegroundColor Cyan
    Write-Host "        ADVANCED SECURITY ASSESSMENT TOOL v$ScriptVersion        " -NoNewline -ForegroundColor Yellow
    Write-Host "*" -ForegroundColor Cyan
    Write-Host "*" -NoNewline -ForegroundColor Cyan
    Write-Host "                     Enhanced Security Checking                    " -NoNewline -ForegroundColor White
    Write-Host "*" -ForegroundColor Cyan
    Write-Host "*"*70 -ForegroundColor Cyan
    Write-Host ""
    
    # Check for administrative privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "WARNING: This tool requires administrative privileges!" -ForegroundColor Red
        Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
        Write-Host ""
        Pause
        exit 1
    }
    
    # Initialize configuration
    Write-Host "Initializing..." -ForegroundColor White
    Write-Host ""
    
    try {
        Initialize-Configuration | Out-Null
        
        Write-Host "✓ Configuration loaded" -ForegroundColor Green
        Write-Host "✓ Directories verified" -ForegroundColor Green
        Write-Host "✓ Modules initialized" -ForegroundColor Green
        
        Start-Sleep -Seconds 1
        
        # Show main menu
        Show-EnhancedMenu
        
    } catch {
        Write-Host "`nInitialization failed: $_" -ForegroundColor Red
        Write-Host "`nPlease check:" -ForegroundColor Yellow
        Write-Host "  1. PowerShell version (requires 5.1+)" -ForegroundColor Gray
        Write-Host "  2. Administrative privileges" -ForegroundColor Gray
        Write-Host "  3. File system permissions" -ForegroundColor Gray
        Write-Host "  4. Disk space availability" -ForegroundColor Gray
        Write-Host ""
        Pause
        exit 1
    }
}

# ============================================
# SCRIPT ENTRY POINT
# ============================================

# Set error handling
$ErrorActionPreference = "Stop"

# Check if script is being run directly
if ($MyInvocation.InvocationName -ne '.') {
    try {
        Main
    } catch {
        Write-Host "`nFatal error occurred: $_" -ForegroundColor Red
        Write-Host "Stack trace:" -ForegroundColor DarkRed
        Write-Host $_.ScriptStackTrace -ForegroundColor Gray
        Write-Host ""
        Write-Host "Please check the log file for details:" -ForegroundColor Yellow
        Write-Host $LoggingConfig.LogFile -ForegroundColor Gray
        Write-Host ""
        Pause
        exit 1
    }
}

