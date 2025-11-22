# Enhanced Security Checks Module
# This module provides additional security check functions for specific applications and services

# Import required modules
Import-Module PSLogging
Import-Module security_logging

# Initialize logging
$logPath = "C:\SecurityTools\Logs\enhanced_security_checks_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
Initialize-Logging -LogPath $logPath

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

# Function to test SQL Server security
function Test-SQLServerSecurity {
    param (
        [string]$ServerName = $env:COMPUTERNAME,
        [string]$InstanceName = "MSSQLSERVER"
    )
    
    try {
        Write-Log -Message "Starting SQL Server security check for $ServerName\$InstanceName" -Level Info
        
        $results = @{
            SQLServerSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check SQL Server installation
        if (Get-Service -Name "MSSQL`$$InstanceName" -ErrorAction SilentlyContinue) {
            $results.SQLServerSettings.Installation = @{
                Version = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.$InstanceName\MSSQLServer\CurrentVersion" -ErrorAction SilentlyContinue).Version
                Services = @{
                    SQLServer = (Get-Service -Name "MSSQL`$$InstanceName").Status
                    SQLAgent = (Get-Service -Name "SQLAGENT`$$InstanceName").Status
                    SQLBrowser = (Get-Service -Name "SQLBrowser").Status
                }
            }
            
            # Check SQL Server security settings
            $results.SQLServerSettings.Security = @{
                AuthenticationMode = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.$InstanceName\MSSQLServer\LoginMode" -ErrorAction SilentlyContinue).LoginMode
                EncryptionEnabled = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.$InstanceName\MSSQLServer\SuperSocketNetLib" -ErrorAction SilentlyContinue).ForceEncryption
                AuditLevel = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.$InstanceName\MSSQLServer\AuditLevel" -ErrorAction SilentlyContinue).AuditLevel
            }
            
            # Check for security issues
            if ($results.SQLServerSettings.Security.AuthenticationMode -eq 1) {
                $results.SecurityIssues += "Windows Authentication only mode not enabled"
                $results.Recommendations += "Enable Windows Authentication only mode"
            }
            
            if (-not $results.SQLServerSettings.Security.EncryptionEnabled) {
                $results.SecurityIssues += "Encryption not enforced"
                $results.Recommendations += "Enable ForceEncryption in SQL Server configuration"
            }
        }
        
        Write-Log -Message "Completed SQL Server security check for $ServerName\$InstanceName" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test SQL Server security: $_" -Level Error
        return $null
    }
}

# Function to test Active Directory security
function Test-ActiveDirectorySecurity {
    param (
        [string]$DomainName = $env:USERDNSDOMAIN
    )
    
    try {
        Write-Log -Message "Starting Active Directory security check for $DomainName" -Level Info
        
        $results = @{
            ADSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check domain controller
        $dc = Get-ADDomainController -DomainName $DomainName -ErrorAction SilentlyContinue
        if ($dc) {
            $results.ADSettings.DomainController = @{
                Name = $dc.Name
                IPAddress = $dc.IPv4Address
                OSVersion = $dc.OperatingSystem
                Roles = $dc.OperationMasterRoles
            }
            
            # Check AD security settings
            $results.ADSettings.Security = @{
                PasswordPolicy = Get-ADDefaultDomainPasswordPolicy
                AccountLockoutPolicy = Get-ADAccountLockoutPolicy
                KerberosPolicy = Get-ADKerberosPolicy
                AuditPolicy = Get-ADAuditPolicy
            }
            
            # Check for security issues
            if ($results.ADSettings.Security.PasswordPolicy.MinPasswordLength -lt 12) {
                $results.SecurityIssues += "Password minimum length less than 12 characters"
                $results.Recommendations += "Increase minimum password length to 12 characters"
            }
            
            if (-not $results.ADSettings.Security.PasswordPolicy.ComplexityEnabled) {
                $results.SecurityIssues += "Password complexity not enabled"
                $results.Recommendations += "Enable password complexity requirements"
            }
            
            if ($results.ADSettings.Security.AccountLockoutPolicy.LockoutThreshold -eq 0) {
                $results.SecurityIssues += "Account lockout not enabled"
                $results.Recommendations += "Enable account lockout after failed attempts"
            }
        }
        
        Write-Log -Message "Completed Active Directory security check for $DomainName" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test Active Directory security: $_" -Level Error
        return $null
    }
}

# Function to test Windows Server security
function Test-WindowsServerSecurity {
    param (
        [string]$ServerName = $env:COMPUTERNAME
    )
    
    try {
        Write-Log -Message "Starting Windows Server security check for $ServerName" -Level Info
        
        $results = @{
            ServerSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check server information
        $results.ServerSettings.System = @{
            OSVersion = (Get-WmiObject Win32_OperatingSystem).Version
            LastBootTime = (Get-WmiObject Win32_OperatingSystem).LastBootUpTime
            InstallDate = (Get-WmiObject Win32_OperatingSystem).InstallDate
        }
        
        # Check security settings
        $results.ServerSettings.Security = @{
            FirewallStatus = (Get-NetFirewallProfile).Enabled
            WindowsDefender = (Get-MpComputerStatus).AntivirusEnabled
            WindowsUpdate = (Get-WindowsUpdateStatus).LastSuccessTime
            BitLocker = (Get-BitLockerVolume).EncryptionMethod
            UAC = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA
        }
        
        # Check for security issues
        if (-not $results.ServerSettings.Security.FirewallStatus) {
            $results.SecurityIssues += "Windows Firewall not enabled"
            $results.Recommendations += "Enable Windows Firewall"
        }
        
        if (-not $results.ServerSettings.Security.WindowsDefender) {
            $results.SecurityIssues += "Windows Defender not enabled"
            $results.Recommendations += "Enable Windows Defender"
        }
        
        if (-not $results.ServerSettings.Security.UAC) {
            $results.SecurityIssues += "User Account Control not enabled"
            $results.Recommendations += "Enable User Account Control"
        }
        
        Write-Log -Message "Completed Windows Server security check for $ServerName" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Failed to test Windows Server security: $_" -Level Error
        return $null
    }
}

# Export functions
Export-ModuleMember -Function Test-SharePointSecurity, Test-ExchangeSecurity, Test-CustomApplicationSecurity, Test-SQLServerSecurity, Test-ActiveDirectorySecurity, Test-WindowsServerSecurity 