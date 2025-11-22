# DarkWin Additional Tools Installer
# Author: viphacker.100
# Description: Installs additional security tools for DarkWin OS

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$LogFile = "C:\Tools\Logs\additional_tools_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param($Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    Write-Host $LogMessage
}

function Install-ChocolateyPackage {
    param(
        [string]$PackageName,
        [string]$Version = "latest"
    )
    Write-Log "Installing $PackageName..."
    choco install $PackageName --version $Version -y
    Write-Log "$PackageName installed successfully"
}

function Install-PythonPackage {
    param(
        [string]$PackageName,
        [string]$Version = "latest"
    )
    Write-Log "Installing Python package: $PackageName..."
    pip install "$PackageName==$Version"
    Write-Log "Python package $PackageName installed successfully"
}

function Install-GitRepo {
    param(
        [string]$RepoUrl,
        [string]$Destination
    )
    Write-Log "Cloning repository: $RepoUrl"
    if (-not (Test-Path $Destination)) {
        git clone $RepoUrl $Destination
        Write-Log "Repository cloned successfully"
    } else {
        Set-Location $Destination
        git pull
        Write-Log "Repository updated successfully"
    }
}

# Main installation
try {
    Write-Log "Starting installation of additional security tools..."
    
    # Create necessary directories
    $Directories = @(
        "C:\Tools\Additional",
        "C:\Tools\Wordlists",
        "C:\Tools\Payloads",
        "C:\Tools\Reports"
    )
    
    foreach ($Dir in $Directories) {
        if (-not (Test-Path $Dir)) {
            New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        }
    }
    
    # Install additional Chocolatey packages
    $ChocolateyPackages = @(
        @{Name="hashcat"; Version="latest"},
        @{Name="john"; Version="latest"},
        @{Name="sqlmap"; Version="latest"},
        @{Name="nikto"; Version="latest"},
        @{Name="dirb"; Version="latest"},
        @{Name="gobuster"; Version="latest"},
        @{Name="ffuf"; Version="latest"},
        @{Name="masscan"; Version="latest"},
        @{Name="netcat"; Version="latest"},
        @{Name="putty"; Version="latest"},
        @{Name="winscp"; Version="latest"},
        @{Name="notepadplusplus"; Version="latest"},
        @{Name="7zip"; Version="latest"},
        @{Name="adb"; Version="latest"},
        @{Name="postman"; Version="latest"},
        @{Name="fiddler"; Version="latest"},
        @{Name="proxifier"; Version="latest"},
        @{Name="tor-browser"; Version="latest"},
        @{Name="keepass"; Version="latest"},
        @{Name="veracrypt"; Version="latest"}
    )
    
    foreach ($Package in $ChocolateyPackages) {
        Install-ChocolateyPackage -PackageName $Package.Name -Version $Package.Version
    }
    
    # Install additional Python packages
    $PythonPackages = @(
        @{Name="pwntools"; Version="latest"},
        @{Name="impacket"; Version="latest"},
        @{Name="mitmproxy"; Version="latest"},
        @{Name="dnspython"; Version="latest"},
        @{Name="netfilterqueue"; Version="latest"},
        @{Name="pycryptodome"; Version="latest"},
        @{Name="pywin32"; Version="latest"},
        @{Name="psutil"; Version="latest"},
        @{Name="colorama"; Version="latest"},
        @{Name="termcolor"; Version="latest"},
        @{Name="tqdm"; Version="latest"},
        @{Name="pyinstaller"; Version="latest"},
        @{Name="virtualenv"; Version="latest"},
        @{Name="pytest"; Version="latest"},
        @{Name="black"; Version="latest"},
        @{Name="pylint"; Version="latest"},
        @{Name="mypy"; Version="latest"},
        @{Name="bandit"; Version="latest"},
        @{Name="safety"; Version="latest"},
        @{Name="pip-audit"; Version="latest"}
    )
    
    foreach ($Package in $PythonPackages) {
        Install-PythonPackage -PackageName $Package.Name -Version $Package.Version
    }
    
    # Clone additional Git repositories
    $GitRepos = @(
        @{
            Url = "https://github.com/danielmiessler/SecLists.git"
            Path = "C:\Tools\Wordlists\SecLists"
        },
        @{
            Url = "https://github.com/SecureAuthCorp/impacket.git"
            Path = "C:\Tools\Additional\impacket"
        },
        @{
            Url = "https://github.com/BloodHoundAD/BloodHound.git"
            Path = "C:\Tools\Additional\BloodHound"
        },
        @{
            Url = "https://github.com/gentilkiwi/mimikatz.git"
            Path = "C:\Tools\Additional\mimikatz"
        },
        @{
            Url = "https://github.com/byt3bl33d3r/CrackMapExec.git"
            Path = "C:\Tools\Additional\CrackMapExec"
        }
    )
    
    foreach ($Repo in $GitRepos) {
        Install-GitRepo -RepoUrl $Repo.Url -Destination $Repo.Path
    }
    
    # Configure tool-specific settings
    Write-Log "Configuring tool settings..."
    
    # Configure Hashcat
    $HashcatConfig = @"
--opencl-device-types=1,2
--workload-profile=4
--kernel-accel=1
--kernel-loops=1
"@
    $HashcatConfig | Out-File "C:\Tools\Configs\hashcat.conf"
    
    # Configure John the Ripper
    $JohnConfig = @"
[Options]
#Wordlist = $/Tools/Wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
#Rules = $/Tools/Wordlists/SecLists/Rules/dive.rule
"@
    $JohnConfig | Out-File "C:\Tools\Configs\john.conf"
    
    Write-Log "Additional tools installation completed successfully"
} catch {
    Write-Log "ERROR: Installation failed - $_"
    exit 1
} 