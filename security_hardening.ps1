# DarkWin Security Hardening Script
# Author: viphacker.100
# Description: Applies security hardening configurations

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$LogFile = "C:\Tools\Logs\hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param($Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    Write-Host $LogMessage
}

function Set-SystemHardening {
    Write-Log "Applying system hardening..."
    
    # Disable unnecessary services
    $ServicesToDisable = @(
        "DiagTrack",
        "dmwappushservice",
        "HomeGroupListener",
        "HomeGroupProvider",
        "WSearch",
        "RemoteRegistry",
        "PrintSpooler",
        "Fax",
        "XblAuthManager",
        "XblGameSave",
        "XboxNetApiSvc"
    )
    
    foreach ($Service in $ServicesToDisable) {
        Set-Service -Name $Service -StartupType Disabled
        Write-Log "Disabled service: $Service"
    }
    
    # Configure Windows Firewall
    Write-Log "Configuring Windows Firewall..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow
    
    # Add firewall rules for security tools
    $FirewallRules = @(
        @{
            Name = "Allow Wireshark"
            Program = "C:\Program Files\Wireshark\Wireshark.exe"
            Direction = "Inbound"
            Action = "Allow"
        },
        @{
            Name = "Allow Nmap"
            Program = "C:\Program Files\Nmap\nmap.exe"
            Direction = "Inbound"
            Action = "Allow"
        },
        @{
            Name = "Allow Metasploit"
            Program = "C:\metasploit-framework\msfconsole.exe"
            Direction = "Inbound"
            Action = "Allow"
        }
    )
    
    foreach ($Rule in $FirewallRules) {
        New-NetFirewallRule -DisplayName $Rule.Name -Program $Rule.Program -Direction $Rule.Direction -Action $Rule.Action
        Write-Log "Added firewall rule: $($Rule.Name)"
    }
}

function Set-SecurityPolicies {
    Write-Log "Applying security policies..."
    
    # Configure password policy
    net accounts /minpwlen:12
    net accounts /maxpwage:90
    net accounts /minpwage:1
    net accounts /lockoutthreshold:5
    net accounts /lockoutduration:30
    net accounts /lockoutwindow:30
    
    # Configure audit policy
    auditpol /set /category:* /success:enable /failure:enable
    
    # Configure UAC
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 3
}

function Set-NetworkHardening {
    Write-Log "Applying network hardening..."
    
    # Disable NetBIOS
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -Value 2
    
    # Disable LLMNR
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0
    
    # Disable SMBv1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -Value 0
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
}

function Set-PrivacySettings {
    Write-Log "Applying privacy settings..."
    
    # Disable telemetry
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
    
    # Disable location services
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny"
    
    # Disable Cortana
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0
    
    # Disable Windows Tips
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0
}

function Set-ApplicationHardening {
    Write-Log "Applying application hardening..."
    
    # Configure Java security
    $JavaConfig = @"
deployment.security.level=HIGH
deployment.security.sandbox.revoked=true
deployment.security.askgrantdialog.notinca=false
"@
    $JavaConfig | Out-File "C:\Program Files\Java\jre*\lib\security\java.security"
    
    # Configure Adobe Reader security
    $AdobeConfig = @"
[Security]
bEnableProtectedMode=1
bDisableJavaScript=1
"@
    $AdobeConfig | Out-File "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroApp.ini"
}

function Set-MonitoringTools {
    Write-Log "Setting up monitoring tools..."
    
    # Configure Windows Event Log
    wevtutil sl Security /ms:1024000
    wevtutil sl Application /ms:1024000
    wevtutil sl System /ms:1024000
    
    # Enable PowerShell logging
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
}

# Main execution
try {
    Write-Log "Starting security hardening..."
    
    Set-SystemHardening
    Set-SecurityPolicies
    Set-NetworkHardening
    Set-PrivacySettings
    Set-ApplicationHardening
    Set-MonitoringTools
    
    Write-Log "Security hardening completed successfully"
    Write-Log "Please restart your system to apply all changes"
} catch {
    Write-Log "ERROR: Hardening failed - $_"
    exit 1
} 