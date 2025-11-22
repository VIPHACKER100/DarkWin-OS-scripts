@echo off
echo [*] Starting DarkWin post-installation setup...

:: Create necessary directories
mkdir "C:\Tools" 2>nul
mkdir "C:\Tools\Scripts" 2>nul
mkdir "C:\Tools\Configs" 2>nul
mkdir "C:\Tools\Logs" 2>nul

:: Install Chocolatey package manager
echo [*] Installing Chocolatey...
powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"

:: Install essential tools via Chocolatey
echo [*] Installing security tools...
choco install -y nmap
choco install -y wireshark
choco install -y python3
choco install -y git
choco install -y cmder
choco install -y burp-suite-free-edition
choco install -y metasploit-framework

:: Install Python packages
echo [*] Installing Python packages...
pip install scapy requests paramiko python-nmap

:: Clone security tools from GitHub
echo [*] Cloning security tools...
git clone https://github.com/carlospolop/PEASS-ng.git "C:\Tools\PEASS"
git clone https://github.com/PowerShellMafia/PowerSploit.git "C:\Tools\PowerSploit"

:: Configure system settings
echo [*] Configuring system settings...
powershell -Command "Set-ExecutionPolicy Unrestricted -Force"
powershell -Command "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Hidden' -Value 1"
powershell -Command "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Value 0"

:: Set up environment variables
echo [*] Setting up environment variables...
setx PATH "%PATH%;C:\Tools;C:\Tools\Scripts" /M
setx METASPLOIT_DATABASE "true" /M

:: Create desktop shortcuts
echo [*] Creating desktop shortcuts...
powershell -Command "$WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut([Environment]::GetFolderPath('Desktop') + '\Metasploit.lnk'); $Shortcut.TargetPath = 'C:\metasploit-framework\msfconsole.bat'; $Shortcut.Save()"
powershell -Command "$WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut([Environment]::GetFolderPath('Desktop') + '\Burp Suite.lnk'); $Shortcut.TargetPath = 'C:\Program Files\BurpSuiteCommunity\burpsuite_community.bat'; $Shortcut.Save()"

:: Apply custom theme and wallpaper
echo [*] Applying custom theme...
powershell -Command "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -Value 0"
powershell -Command "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'SystemUsesLightTheme' -Value 0"

echo [*] DarkWin setup completed successfully!
echo [*] Please restart your system to apply all changes. 