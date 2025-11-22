# DarkWin Setup Script

# Create logging functions
function Write-Log {
    param(
        [string]$Message,
        [string]$LogType = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$LogType] $Message"
    
    # Ensure log directory exists
    $logDir = "C:\SecurityTools\Logs"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    # Write to log file
    $logPath = "C:\SecurityTools\Logs\setup_$(Get-Date -Format 'yyyy-MM-dd').log"
    Add-Content -Path $logPath -Value $logMessage
    
    # Also write to console with appropriate color
    $color = switch ($LogType) {
        "Error" { "Red" }
        "Warning" { "Yellow" }
        "Info" { "Green" }
        default { "White" }
    }
    Write-Host $logMessage -ForegroundColor $color
}

# Initialize logging
Write-Log -Message "Starting DarkWin setup" -LogType "Info"

# Function to create directory structure
function Initialize-DirectoryStructure {
    Write-Log -Message "Creating directory structure" -LogType "Info"
    
    $directories = @(
        "C:\SecurityTools",
        "C:\SecurityTools\Tools",
        "C:\SecurityTools\Scripts",
        "C:\SecurityTools\Configs",
        "C:\SecurityTools\Logs",
        "C:\SecurityTools\Captures",
        "C:\SecurityTools\Reports",
        "C:\SecurityTools\Analysis",
        "C:\SecurityTools\Exploits",
        "C:\SecurityTools\Backups"
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Log -Message "Created directory: $dir" -LogType "Info"
        }
    }
}

# Function to install security tools
function Install-SecurityTools {
    Write-Log -Message "Installing security tools" -LogType "Info"
    
    # Network Tools
    $networkTools = @(
        @{
            Name = "Wireshark"
            URL = "https://2.na.dl.wireshark.org/win64/Wireshark-win64-4.2.3.exe"
            Args = "/S"
        },
        @{
            Name = "Nmap"
            URL = "https://nmap.org/dist/nmap-7.94-setup.exe"
            Args = "/S"
        },
        @{
            Name = "Metasploit"
            URL = "https://windows.metasploit.com/metasploitframework-latest.msi"
            Args = "/quiet"
        },
        @{
            Name = "Burp Suite"
            URL = "https://portswigger.net/burp/releases/download?product=community&version=2024.1.1"
            Args = "/S"
        }
    )
    
    # System Tools
    $systemTools = @(
        @{
            Name = "Process Hacker"
            URL = "https://github.com/processhacker/processhacker/releases/download/v2.39/processhacker-2.39-setup.exe"
            Args = "/S"
        },
        @{
            Name = "Autoruns"
            URL = "https://download.sysinternals.com/files/Autoruns.zip"
            Args = ""
        },
        @{
            Name = "Sysinternals Suite"
            URL = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
            Args = ""
        }
    )
    
    # Forensic Tools
    $forensicTools = @(
        @{
            Name = "Autopsy"
            URL = "https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.21.3/autopsy-4.21.3_64bit.msi"
            Args = "/quiet"
        },
        @{
            Name = "Volatility"
            URL = "https://github.com/volatilityfoundation/volatility3/archive/refs/tags/2.6.1.zip"
            Args = ""
        },
        @{
            Name = "FTK Imager"
            URL = "https://ad-pdf.s3.amazonaws.com/FTKImager_4.7.1.0_x64.msi"
            Args = "/quiet"
        }
    )
    
    # Install tools
    $allTools = $networkTools + $systemTools + $forensicTools
    
    foreach ($tool in $allTools) {
        Write-Log -Message "Installing $($tool.Name)" -LogType "Info"
        
        $installer = "$env:TEMP\$($tool.Name)_installer.exe"
        try {
            Invoke-WebRequest -Uri $tool.URL -OutFile $installer -UseBasicParsing
            
            if ($tool.Args) {
                Start-Process -FilePath $installer -ArgumentList $tool.Args -Wait
            } else {
                Expand-Archive -Path $installer -DestinationPath "C:\SecurityTools\Tools\$($tool.Name)" -Force
            }
            
            Remove-Item $installer -Force
            Write-Log -Message "Installed $($tool.Name)" -LogType "Info"
        } catch {
            Write-Log -Message "Failed to install $($tool.Name): $_" -LogType "Error"
            if (Test-Path $installer) {
                Remove-Item $installer -Force
            }
        }
    }
}

# Function to configure Windows Defender
function Set-WindowsDefenderConfig {
    Write-Log -Message "Configuring Windows Defender" -LogType "Info"
    
    # Enable real-time protection
    Set-MpPreference -DisableRealtimeMonitoring $false
    Write-Log -Message "Enabled real-time protection" -LogType "Info"
    
    # Enable cloud protection
    Set-MpPreference -MAPSReporting Advanced
    Write-Log -Message "Enabled cloud protection" -LogType "Info"
    
    # Enable tamper protection
    Set-MpPreference -DisableTamperProtection $false
    Write-Log -Message "Enabled tamper protection" -LogType "Info"
    
    # Add exclusions
    $exclusions = @(
        "C:\SecurityTools",
        "C:\Program Files\SecurityTools"
    )
    
    foreach ($path in $exclusions) {
        Add-MpPreference -ExclusionPath $path
        Write-Log -Message "Added exclusion: $path" -LogType "Info"
    }
}

# Function to configure firewall
function Set-FirewallConfig {
    Write-Log -Message "Configuring firewall" -LogType "Info"
    
    # Enable firewall
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Write-Log -Message "Enabled firewall" -LogType "Info"
    
    # Set default profile
    Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    Write-Log -Message "Set default profile" -LogType "Info"
    
    # Allow ICMP
    New-NetFirewallRule -DisplayName "Allow ICMP" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow
    Write-Log -Message "Allowed ICMP" -LogType "Info"
    
    # Block remote management
    Set-NetFirewallRule -DisplayName "Remote Management" -Enabled False
    Write-Log -Message "Blocked remote management" -LogType "Info"
}

# Function to set up theme
function Set-Theme {
    Write-Log -Message "Setting up theme" -LogType "Info"
    
    # Set wallpaper
    $wallpaperPath = "C:\SecurityTools\Configs\cyberpunk_wallpaper.png"
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name WallPaper -Value $wallpaperPath
    Write-Log -Message "Set wallpaper" -LogType "Info"
    
    # Set color scheme
    $theme = @{
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" = @{
            "SystemUsesLightTheme" = 0
            "AppsUseLightTheme" = 0
        }
        "HKCU:\Control Panel\Colors" = @{
            "Background" = "0 0 0"
            "Window" = "0 0 0"
            "WindowText" = "255 255 255"
        }
    }
    
    foreach ($key in $theme.Keys) {
        foreach ($value in $theme[$key].Keys) {
            Set-ItemProperty -Path $key -Name $value -Value $theme[$key][$value]
        }
    }
    Write-Log -Message "Set color scheme" -LogType "Info"
}

# Function to set up auto-login
function Set-AutoLogin {
    Write-Log -Message "Setting up auto-login" -LogType "Info"
    
    $username = "darkwin"
    $password = "DarkWin@2024"
    
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $regPath -Name "AutoAdminLogon" -Value 1
    Set-ItemProperty -Path $regPath -Name "DefaultUsername" -Value $username
    Set-ItemProperty -Path $regPath -Name "DefaultPassword" -Value $password
    Write-Log -Message "Set auto-login" -LogType "Info"
}

# Function to check installation status
function Test-ToolInstallation {
    param(
        [string]$ToolName,
        [string]$InstallPath
    )
    
    $status = @{
        Name = $ToolName
        Installed = $false
        Path = $null
        Version = $null
    }
    
    # Check common installation paths
    $possiblePaths = @(
        "C:\Program Files\$ToolName",
        "C:\Program Files (x86)\$ToolName",
        "C:\SecurityTools\Tools\$ToolName",
        "C:\Program Files\Wireshark",
        "C:\Program Files\Nmap",
        "C:\Program Files\Metasploit",
        "C:\Program Files\Burp Suite",
        "C:\Program Files\Process Hacker",
        "C:\Program Files\Autopsy",
        "C:\Program Files\AccessData\FTK Imager"
    )
    
    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            $status.Installed = $true
            $status.Path = $path
            
            # Try to get version information
            try {
                if (Test-Path "$path\*.exe") {
                    $exe = Get-ChildItem "$path\*.exe" | Select-Object -First 1
                    $version = (Get-Item $exe.FullName).VersionInfo.FileVersion
                    $status.Version = $version
                }
            } catch {
                $status.Version = "Unknown"
            }
            break
        }
    }
    
    return $status
}

# Function to generate installation report
function Get-InstallationReport {
    $tools = @(
        "Wireshark",
        "Nmap",
        "Metasploit",
        "Burp Suite",
        "Process Hacker",
        "Autoruns",
        "Sysinternals Suite",
        "Autopsy",
        "Volatility",
        "FTK Imager"
    )
    
    Write-Log -Message "Generating installation report..." -LogType "Info"
    Write-Host "`n=== Installation Report ===" -ForegroundColor Cyan
    
    $report = @()
    foreach ($tool in $tools) {
        $status = Test-ToolInstallation -ToolName $tool
        $report += $status
        
        $color = if ($status.Installed) { "Green" } else { "Red" }
        $statusText = if ($status.Installed) { "Installed" } else { "Not Found" }
        $versionText = if ($status.Version) { " (v$($status.Version))" } else { "" }
        
        Write-Host "$($tool): $statusText$versionText" -ForegroundColor $color
        if ($status.Path) {
            Write-Host "  Location: $($status.Path)" -ForegroundColor Gray
        }
    }
    
    # Save report to file
    $reportPath = "C:\SecurityTools\Reports\installation_report_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
    $report | Format-Table -AutoSize | Out-File $reportPath
    
    Write-Log -Message "Installation report saved to: $reportPath" -LogType "Info"
    Write-Host "`nReport saved to: $reportPath" -ForegroundColor Cyan
    Write-Host "=== End of Report ===`n" -ForegroundColor Cyan
    
    return $report
}

# Main execution
try {
    Initialize-DirectoryStructure
    Install-SecurityTools
    Set-WindowsDefenderConfig
    Set-FirewallConfig
    Set-Theme
    Set-AutoLogin
    
    # Generate installation report
    $report = Get-InstallationReport
    
    # Check if all tools were installed successfully
    $failedTools = $report | Where-Object { -not $_.Installed }
    if ($failedTools) {
        Write-Log -Message "Some tools failed to install: $($failedTools.Name -join ', ')" -LogType "Warning"
    }
    
    Write-Log -Message "DarkWin setup completed" -LogType "Info"
} catch {
    Write-Log -Message "Error during setup: $_" -LogType "Error"
} 