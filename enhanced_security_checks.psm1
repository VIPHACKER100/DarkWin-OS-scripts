# Enhanced Security Checks Module

# Function to test SQL Server security
function Test-SQLServerSecurity {
    param (
        [string]$ServerName = $env:COMPUTERNAME
    )
    
    try {
        Write-Log -Message "Starting SQL Server security check" -Level Info
        
        $results = @{
            ServerSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check SQL Server instances
        $instances = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\*\Tools\ClientSetup" -ErrorAction SilentlyContinue
        foreach ($instance in $instances) {
            $instanceName = $instance.PSChildName
            $results.ServerSettings[$instanceName] = @{
                AuthenticationMode = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceName\MSSQLServer" -Name "LoginMode" -ErrorAction SilentlyContinue).LoginMode
                EncryptionEnabled = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceName\MSSQLServer" -Name "ForceEncryption" -ErrorAction SilentlyContinue).ForceEncryption
                AuditLevel = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceName\MSSQLServer" -Name "AuditLevel" -ErrorAction SilentlyContinue).AuditLevel
            }
        }
        
        # Check for security issues
        foreach ($instance in $results.ServerSettings.Keys) {
            $settings = $results.ServerSettings[$instance]
            
            if ($settings.AuthenticationMode -eq 1) {
                $results.SecurityIssues += "SQL Server instance $instance is using Windows Authentication only"
            }
            
            if (-not $settings.EncryptionEnabled) {
                $results.SecurityIssues += "SQL Server instance $instance has encryption disabled"
            }
            
            if ($settings.AuditLevel -lt 2) {
                $results.SecurityIssues += "SQL Server instance $instance has insufficient audit logging"
            }
        }
        
        # Generate recommendations
        if ($results.SecurityIssues.Count -gt 0) {
            $results.Recommendations += "Enable SQL Server encryption for all instances"
            $results.Recommendations += "Configure comprehensive audit logging"
            $results.Recommendations += "Review and update SQL Server service accounts"
            $results.Recommendations += "Implement least privilege access"
        }
        
        Write-Log -Message "Completed SQL Server security check" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Error during SQL Server security check: $_" -Level Error
        return $null
    }
}

# Function to test Active Directory security
function Test-ActiveDirectorySecurity {
    param (
        [string]$DomainName = $env:USERDNSDOMAIN
    )
    
    try {
        Write-Log -Message "Starting Active Directory security check" -Level Info
        
        $results = @{
            DomainSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check domain settings
        $results.DomainSettings = @{
            PasswordPolicy = Get-ADDefaultDomainPasswordPolicy
            AccountLockoutPolicy = Get-ADAccountLockoutPolicy
            DomainControllers = Get-ADDomainController -Filter *
        }
        
        # Check for security issues
        if ($results.DomainSettings.PasswordPolicy.MinPasswordLength -lt 12) {
            $results.SecurityIssues += "Password minimum length is less than 12 characters"
        }
        
        if (-not $results.DomainSettings.PasswordPolicy.ComplexityEnabled) {
            $results.SecurityIssues += "Password complexity is not enforced"
        }
        
        if ($results.DomainSettings.AccountLockoutPolicy.LockoutThreshold -eq 0) {
            $results.SecurityIssues += "Account lockout is not configured"
        }
        
        # Generate recommendations
        if ($results.SecurityIssues.Count -gt 0) {
            $results.Recommendations += "Increase minimum password length to 12 characters"
            $results.Recommendations += "Enable password complexity requirements"
            $results.Recommendations += "Configure account lockout policy"
            $results.Recommendations += "Review domain controller security"
        }
        
        Write-Log -Message "Completed Active Directory security check" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Error during Active Directory security check: $_" -Level Error
        return $null
    }
}

# Function to test Windows Server security
function Test-WindowsServerSecurity {
    param (
        [string]$ServerName = $env:COMPUTERNAME
    )
    
    try {
        Write-Log -Message "Starting Windows Server security check" -Level Info
        
        $results = @{
            ServerSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check server settings
        $results.ServerSettings = @{
            WindowsVersion = (Get-WmiObject Win32_OperatingSystem).Version
            LastUpdate = (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
            Services = Get-Service | Where-Object {$_.StartType -eq 'Automatic'}
            FirewallStatus = Get-NetFirewallProfile
        }
        
        # Check for security issues
        if ((Get-Date) - $results.ServerSettings.LastUpdate -gt (New-TimeSpan -Days 30)) {
            $results.SecurityIssues += "Server has not been updated in over 30 days"
        }
        
        if (-not $results.ServerSettings.FirewallStatus.Enabled) {
            $results.SecurityIssues += "Windows Firewall is not enabled"
        }
        
        $vulnerableServices = $results.ServerSettings.Services | Where-Object {
            $_.Name -in @('TelnetServer', 'FTP', 'SNMP', 'RemoteRegistry')
        }
        if ($vulnerableServices) {
            $results.SecurityIssues += "Vulnerable services are enabled: $($vulnerableServices.Name -join ', ')"
        }
        
        # Generate recommendations
        if ($results.SecurityIssues.Count -gt 0) {
            $results.Recommendations += "Install latest Windows updates"
            $results.Recommendations += "Enable and configure Windows Firewall"
            $results.Recommendations += "Disable unnecessary services"
            $results.Recommendations += "Implement security baselines"
        }
        
        Write-Log -Message "Completed Windows Server security check" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Error during Windows Server security check: $_" -Level Error
        return $null
    }
}

# Function to test IIS security
function Test-IISSecurity {
    param (
        [string]$ServerName = $env:COMPUTERNAME
    )
    
    try {
        Write-Log -Message "Starting IIS security check" -Level Info
        
        $results = @{
            IISSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check IIS version and features
        $results.IISSettings = @{
            Version = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -Name "VersionString" -ErrorAction SilentlyContinue).VersionString
            InstalledFeatures = Get-WindowsFeature -Name Web-* | Where-Object {$_.Installed}
            Sites = Get-Website
            AppPools = Get-IISAppPool
        }
        
        # Check for security issues
        foreach ($site in $results.IISSettings.Sites) {
            if (-not $site.Bindings.Protocol -contains "https") {
                $results.SecurityIssues += "Site $($site.Name) does not have HTTPS binding"
            }
            
            if ($site.Bindings.Protocol -contains "http") {
                $results.SecurityIssues += "Site $($site.Name) has HTTP binding enabled"
            }
        }
        
        # Check SSL/TLS settings
        $sslSettings = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -ErrorAction SilentlyContinue
        if (-not $sslSettings.Enabled) {
            $results.SecurityIssues += "TLS 1.2 is not enabled"
        }
        
        # Generate recommendations
        if ($results.SecurityIssues.Count -gt 0) {
            $results.Recommendations += "Enable HTTPS for all websites"
            $results.Recommendations += "Disable HTTP bindings"
            $results.Recommendations += "Enable TLS 1.2"
            $results.Recommendations += "Configure secure headers"
            $results.Recommendations += "Implement request filtering"
        }
        
        Write-Log -Message "Completed IIS security check" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Error during IIS security check: $_" -Level Error
        return $null
    }
}

# Function to test SharePoint security
function Test-SharePointSecurity {
    param (
        [string]$ServerName = $env:COMPUTERNAME
    )
    
    try {
        Write-Log -Message "Starting SharePoint security check" -Level Info
        
        $results = @{
            SharePointSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check SharePoint installation
        $results.SharePointSettings = @{
            Version = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\16.0" -Name "Version" -ErrorAction SilentlyContinue).Version
            Services = Get-Service -Name *SharePoint*
            WebApplications = Get-SPWebApplication -ErrorAction SilentlyContinue
        }
        
        # Check for security issues
        if ($results.SharePointSettings.WebApplications) {
            foreach ($webApp in $results.SharePointSettings.WebApplications) {
                if (-not $webApp.UseClaimsAuthentication) {
                    $results.SecurityIssues += "Web application $($webApp.Name) is not using claims authentication"
                }
                
                if (-not $webApp.AllowAnonymous) {
                    $results.SecurityIssues += "Web application $($webApp.Name) allows anonymous access"
                }
            }
        }
        
        # Generate recommendations
        if ($results.SecurityIssues.Count -gt 0) {
            $results.Recommendations += "Enable claims authentication"
            $results.Recommendations += "Disable anonymous access"
            $results.Recommendations += "Configure SSL for all web applications"
            $results.Recommendations += "Implement proper authentication"
        }
        
        Write-Log -Message "Completed SharePoint security check" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Error during SharePoint security check: $_" -Level Error
        return $null
    }
}

# Function to test Exchange security
function Test-ExchangeSecurity {
    param (
        [string]$ServerName = $env:COMPUTERNAME
    )
    
    try {
        Write-Log -Message "Starting Exchange security check" -Level Info
        
        $results = @{
            ExchangeSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check Exchange installation
        $results.ExchangeSettings = @{
            Version = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup" -Name "Version" -ErrorAction SilentlyContinue).Version
            Services = Get-Service -Name *Exchange*
            MailboxServers = Get-ExchangeServer | Where-Object {$_.IsMailboxServer}
        }
        
        # Check for security issues
        if ($results.ExchangeSettings.MailboxServers) {
            foreach ($server in $results.ExchangeSettings.MailboxServers) {
                if (-not $server.ExternalURL) {
                    $results.SecurityIssues += "Server $($server.Name) does not have external URL configured"
                }
                
                if (-not $server.InternalURL) {
                    $results.SecurityIssues += "Server $($server.Name) does not have internal URL configured"
                }
            }
        }
        
        # Generate recommendations
        if ($results.SecurityIssues.Count -gt 0) {
            $results.Recommendations += "Configure external and internal URLs"
            $results.Recommendations += "Enable SSL/TLS for all connections"
            $results.Recommendations += "Implement proper authentication"
            $results.Recommendations += "Configure anti-spam and anti-malware"
        }
        
        Write-Log -Message "Completed Exchange security check" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Error during Exchange security check: $_" -Level Error
        return $null
    }
}

# Function to test custom application security
function Test-CustomApplicationSecurity {
    param (
        [string]$AppPath,
        [string]$AppType = "Web"
    )
    
    try {
        Write-Log -Message "Starting custom application security check" -Level Info
        
        $results = @{
            AppSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check application settings
        $results.AppSettings = @{
            Path = $AppPath
            Type = $AppType
            ConfigFiles = Get-ChildItem -Path $AppPath -Filter "*.config" -Recurse
            LogFiles = Get-ChildItem -Path $AppPath -Filter "*.log" -Recurse
        }
        
        # Check for security issues
        foreach ($config in $results.AppSettings.ConfigFiles) {
            $content = Get-Content $config.FullName
            if ($content -match "password|connectionString|key") {
                $results.SecurityIssues += "Sensitive information found in $($config.Name)"
            }
        }
        
        # Generate recommendations
        if ($results.SecurityIssues.Count -gt 0) {
            $results.Recommendations += "Remove sensitive information from config files"
            $results.Recommendations += "Implement proper encryption"
            $results.Recommendations += "Use secure configuration management"
            $results.Recommendations += "Implement proper logging"
        }
        
        Write-Log -Message "Completed custom application security check" -Level Info
        return $results
    }
    catch {
        Write-Log -Message "Error during custom application security check: $_" -Level Error
        return $null
    }
}

# Function to test Docker security
function Test-DockerSecurity {
    param (
        [string]$ServerName = $env:COMPUTERNAME
    )
    
    try {
        Write-LogMessage -Message "Starting Docker security check on $ServerName" -Level Info
        
        $results = @{
            DockerSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check Docker installation
        $dockerInfo = docker info 2>&1
        if ($LASTEXITCODE -eq 0) {
            $results.DockerSettings.Installation = "Present"
            $results.DockerSettings.Version = (docker version --format '{{.Server.Version}}')
            
            # Check container security
            $containers = docker ps -a --format '{{.Names}}'
            foreach ($container in $containers) {
                $containerInfo = docker inspect $container
                if ($containerInfo.HostConfig.Privileged -eq $true) {
                    $results.SecurityIssues += "Container $container is running in privileged mode"
                    $results.Recommendations += "Consider running $container without privileged mode"
                }
            }
            
            # Check image security
            $images = docker images --format '{{.Repository}}:{{.Tag}}'
            foreach ($image in $images) {
                $imageInfo = docker inspect $image
                if (-not $imageInfo.RepoDigests) {
                    $results.SecurityIssues += "Image $image is not signed"
                    $results.Recommendations += "Use signed images for $image"
                }
            }
        } else {
            $results.DockerSettings.Installation = "Not Present"
            $results.Recommendations += "Consider installing Docker for container security"
        }
        
        Write-LogMessage -Message "Completed Docker security check on $ServerName" -Level Info
        return $results
    }
    catch {
        Write-LogMessage -Message "Error during Docker security check: $_" -Level Error
        throw
    }
}

# Function to test Kubernetes security
function Test-KubernetesSecurity {
    param (
        [string]$ServerName = $env:COMPUTERNAME
    )
    
    try {
        Write-LogMessage -Message "Starting Kubernetes security check on $ServerName" -Level Info
        
        $results = @{
            KubernetesSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check Kubernetes installation
        $kubectlVersion = kubectl version --client 2>&1
        if ($LASTEXITCODE -eq 0) {
            $results.KubernetesSettings.Installation = "Present"
            $results.KubernetesSettings.Version = $kubectlVersion
            
            # Check pod security
            $pods = kubectl get pods --all-namespaces -o json
            foreach ($pod in $pods.items) {
                if ($pod.spec.containers[0].securityContext.privileged -eq $true) {
                    $results.SecurityIssues += "Pod $($pod.metadata.name) is running in privileged mode"
                    $results.Recommendations += "Consider running $($pod.metadata.name) without privileged mode"
                }
                
                if ($pod.spec.hostNetwork -eq $true) {
                    $results.SecurityIssues += "Pod $($pod.metadata.name) is using host network"
                    $results.Recommendations += "Consider using pod network for $($pod.metadata.name)"
                }
            }
        } else {
            $results.KubernetesSettings.Installation = "Not Present"
            $results.Recommendations += "Consider installing Kubernetes for container orchestration security"
        }
        
        Write-LogMessage -Message "Completed Kubernetes security check on $ServerName" -Level Info
        return $results
    }
    catch {
        Write-LogMessage -Message "Error during Kubernetes security check: $_" -Level Error
        throw
    }
}

# Function to test Azure security
function Test-AzureSecurity {
    param (
        [string]$SubscriptionId
    )
    
    try {
        Write-LogMessage -Message "Starting Azure security check for subscription $SubscriptionId" -Level Info
        
        $results = @{
            AzureSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check Azure subscription
        $subscription = Get-AzSubscription -SubscriptionId $SubscriptionId
        if ($subscription) {
            $results.AzureSettings.Subscription = $subscription.Name
            
            # Check storage accounts
            $storageAccounts = Get-AzStorageAccount
            foreach ($account in $storageAccounts) {
                if (-not $account.EnableHttpsTrafficOnly) {
                    $results.SecurityIssues += "Storage account $($account.StorageAccountName) allows HTTP traffic"
                    $results.Recommendations += "Enable HTTPS-only traffic for $($account.StorageAccountName)"
                }
            }
            
            # Check virtual networks
            $vnets = Get-AzVirtualNetwork
            foreach ($vnet in $vnets) {
                if (-not $vnet.EnableDdosProtection) {
                    $results.SecurityIssues += "Virtual network $($vnet.Name) has DDoS protection disabled"
                    $results.Recommendations += "Enable DDoS protection for $($vnet.Name)"
                }
            }
        } else {
            $results.AzureSettings.Subscription = "Not Found"
            $results.Recommendations += "Verify Azure subscription access"
        }
        
        Write-LogMessage -Message "Completed Azure security check for subscription $SubscriptionId" -Level Info
        return $results
    }
    catch {
        Write-LogMessage -Message "Error during Azure security check: $_" -Level Error
        throw
    }
}

# Function to test AWS security
function Test-AWSSecurity {
    param (
        [string]$ProfileName
    )
    
    try {
        Write-LogMessage -Message "Starting AWS security check for profile $ProfileName" -Level Info
        
        $results = @{
            AWSSettings = @{}
            SecurityIssues = @()
            Recommendations = @()
        }
        
        # Check AWS profile
        $profile = Get-AWSCredential -ProfileName $ProfileName
        if ($profile) {
            $results.AWSSettings.Profile = $ProfileName
            
            # Check EC2 instances
            $instances = Get-EC2Instance
            foreach ($instance in $instances.Instances) {
                if (-not $instance.IamInstanceProfile) {
                    $results.SecurityIssues += "EC2 instance $($instance.InstanceId) has no IAM role"
                    $results.Recommendations += "Assign IAM role to $($instance.InstanceId)"
                }
            }
            
            # Check S3 buckets
            $buckets = Get-S3Bucket
            foreach ($bucket in $buckets) {
                $acl = Get-S3ACL -BucketName $bucket.BucketName
                if ($acl.Grants.Permission -contains "FULL_CONTROL") {
                    $results.SecurityIssues += "S3 bucket $($bucket.BucketName) has public access"
                    $results.Recommendations += "Restrict public access for $($bucket.BucketName)"
                }
            }
        } else {
            $results.AWSSettings.Profile = "Not Found"
            $results.Recommendations += "Verify AWS profile configuration"
        }
        
        Write-LogMessage -Message "Completed AWS security check for profile $ProfileName" -Level Info
        return $results
    }
    catch {
        Write-LogMessage -Message "Error during AWS security check: $_" -Level Error
        throw
    }
}

# Export functions
Export-ModuleMember -Function Test-SQLServerSecurity, Test-ActiveDirectorySecurity, Test-WindowsServerSecurity, `
    Test-IISSecurity, Test-SharePointSecurity, Test-ExchangeSecurity, Test-CustomApplicationSecurity, `
    Test-DockerSecurity, Test-KubernetesSecurity, Test-AzureSecurity, Test-AWSSecurity 