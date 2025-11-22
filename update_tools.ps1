# DarkWin Tools Update Script
# Author: viphacker.100
# Description: Updates and maintains security tools

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$LogFile = "C:\Tools\Logs\update_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param($Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    Write-Host $LogMessage
}

function Update-Chocolatey {
    Write-Log "Updating Chocolatey packages..."
    choco upgrade all -y
    Write-Log "Chocolatey packages updated successfully"
}

function Update-PythonPackages {
    Write-Log "Updating Python packages..."
    pip install --upgrade pip
    pip install --upgrade scapy requests paramiko python-nmap impacket
    Write-Log "Python packages updated successfully"
}

function Update-GitRepos {
    Write-Log "Updating Git repositories..."
    $Repos = @(
        "C:\Tools\PEASS",
        "C:\Tools\PowerSploit",
        "C:\Tools\Modules\Metasploit"
    )
    
    foreach ($Repo in $Repos) {
        if (Test-Path $Repo) {
            Set-Location $Repo
            git pull
            Write-Log "Updated repository: $Repo"
        }
    }
}

function Update-Metasploit {
    Write-Log "Updating Metasploit Framework..."
    $MSFPath = "C:\metasploit-framework"
    if (Test-Path $MSFPath) {
        Set-Location $MSFPath
        .\msfupdate.bat
        Write-Log "Metasploit Framework updated successfully"
    }
}

function Update-Wordlists {
    Write-Log "Updating wordlists..."
    $WordlistPath = "C:\Tools\Wordlists"
    if (Test-Path $WordlistPath) {
        # Update SecLists
        if (Test-Path "$WordlistPath\SecLists") {
            Set-Location "$WordlistPath\SecLists"
            git pull
        } else {
            git clone https://github.com/danielmiessler/SecLists.git "$WordlistPath\SecLists"
        }
        Write-Log "Wordlists updated successfully"
    }
}

function Backup-Configs {
    Write-Log "Backing up configurations..."
    $BackupPath = "C:\Tools\Backups\$(Get-Date -Format 'yyyyMMdd')"
    New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    
    $Configs = @(
        "C:\Tools\Configs",
        "C:\Windows\System32\drivers\etc\hosts",
        "$env:USERPROFILE\.msf4"
    )
    
    foreach ($Config in $Configs) {
        if (Test-Path $Config) {
            Copy-Item -Path $Config -Destination $BackupPath -Recurse -Force
        }
    }
    Write-Log "Configurations backed up successfully"
}

function Test-Tools {
    Write-Log "Testing installed tools..."
    $Tools = @(
        @{Name="Nmap"; Path="nmap.exe"},
        @{Name="Wireshark"; Path="Wireshark.exe"},
        @{Name="Metasploit"; Path="msfconsole.bat"},
        @{Name="Burp Suite"; Path="burpsuite_community.bat"}
    )
    
    foreach ($Tool in $Tools) {
        try {
            $Result = Get-Command $Tool.Path -ErrorAction Stop
            Write-Log "$($Tool.Name) is working correctly"
        } catch {
            Write-Log "WARNING: $($Tool.Name) may not be working correctly"
        }
    }
}

# Main execution
try {
    Write-Log "Starting DarkWin tools update..."
    
    # Create necessary directories
    $Directories = @(
        "C:\Tools\Logs",
        "C:\Tools\Backups",
        "C:\Tools\Wordlists"
    )
    
    foreach ($Dir in $Directories) {
        if (-not (Test-Path $Dir)) {
            New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        }
    }
    
    # Run update functions
    Update-Chocolatey
    Update-PythonPackages
    Update-GitRepos
    Update-Metasploit
    Update-Wordlists
    Backup-Configs
    Test-Tools
    
    Write-Log "DarkWin tools update completed successfully"
} catch {
    Write-Log "ERROR: Update failed - $_"
    exit 1
} 