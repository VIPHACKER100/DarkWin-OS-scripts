# Nessus Automation Script

# Import required modules
Import-Module PSLogging
Import-Module PSNessus

# Initialize logging
$logPath = "C:\SecurityTools\Logs\nessus_automation_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
Start-Log -LogPath $logPath -LogLevel Info

# Function to connect to Nessus
function Connect-NessusServer {
    param (
        [string]$Server = "https://localhost:8834",
        [string]$ApiKey = "",
        [string]$Username = "",
        [string]$Password = ""
    )
    
    Write-Log -Message "Connecting to Nessus server: $Server" -Level Info
    Write-Host "Connecting to Nessus server..." -ForegroundColor Green
    
    try {
        if ($ApiKey) {
            Connect-Nessus -Server $Server -ApiKey $ApiKey
        } else {
            Connect-Nessus -Server $Server -Username $Username -Password $Password
        }
        Write-Log -Message "Successfully connected to Nessus server" -Level Info
    } catch {
        Write-Log -Message "Failed to connect to Nessus server: $_" -Level Error
        throw "Failed to connect to Nessus server: $_"
    }
}

# Function to start basic scan
function Start-BasicScan {
    param (
        [string]$Target,
        [string]$ScanName,
        [string]$PolicyId = "1"  # Basic Network Scan
    )
    
    Write-Log -Message "Starting basic scan of $Target" -Level Info
    Write-Host "Starting basic scan..." -ForegroundColor Green
    
    try {
        $scan = New-NessusScan -Name $ScanName -Targets $Target -PolicyId $PolicyId
        Start-NessusScan -ScanId $scan.id
        Write-Log -Message "Basic scan started with ID: $($scan.id)" -Level Info
        return $scan.id
    } catch {
        Write-Log -Message "Failed to start basic scan: $_" -Level Error
        throw "Failed to start basic scan: $_"
    }
}

# Function to start advanced scan
function Start-AdvancedScan {
    param (
        [string]$Target,
        [string]$ScanName,
        [string]$PolicyId = "2"  # Advanced Scan
    )
    
    Write-Log -Message "Starting advanced scan of $Target" -Level Info
    Write-Host "Starting advanced scan..." -ForegroundColor Green
    
    try {
        $scan = New-NessusScan -Name $ScanName -Targets $Target -PolicyId $PolicyId
        Start-NessusScan -ScanId $scan.id
        Write-Log -Message "Advanced scan started with ID: $($scan.id)" -Level Info
        return $scan.id
    } catch {
        Write-Log -Message "Failed to start advanced scan: $_" -Level Error
        throw "Failed to start advanced scan: $_"
    }
}

# Function to start compliance scan
function Start-ComplianceScan {
    param (
        [string]$Target,
        [string]$ScanName,
        [string]$PolicyId = "3"  # Compliance Scan
    )
    
    Write-Log -Message "Starting compliance scan of $Target" -Level Info
    Write-Host "Starting compliance scan..." -ForegroundColor Green
    
    try {
        $scan = New-NessusScan -Name $ScanName -Targets $Target -PolicyId $PolicyId
        Start-NessusScan -ScanId $scan.id
        Write-Log -Message "Compliance scan started with ID: $($scan.id)" -Level Info
        return $scan.id
    } catch {
        Write-Log -Message "Failed to start compliance scan: $_" -Level Error
        throw "Failed to start compliance scan: $_"
    }
}

# Function to get scan status
function Get-ScanStatus {
    param (
        [string]$ScanId
    )
    
    Write-Log -Message "Getting status for scan ID: $ScanId" -Level Info
    
    try {
        $status = Get-NessusScan -ScanId $ScanId
        Write-Log -Message "Scan status: $($status.status)" -Level Info
        return $status
    } catch {
        Write-Log -Message "Failed to get scan status: $_" -Level Error
        throw "Failed to get scan status: $_"
    }
}

# Function to generate report
function New-NessusReport {
    param (
        [string]$ScanId,
        [string]$Format = "html",
        [string]$OutputFile
    )
    
    Write-Log -Message "Generating $Format report for scan ID: $ScanId" -Level Info
    Write-Host "Generating report..." -ForegroundColor Green
    
    try {
        $report = Export-NessusScan -ScanId $ScanId -Format $Format
        $report | Out-File -FilePath $OutputFile
        Write-Log -Message "Report generated: $OutputFile" -Level Info
        return $OutputFile
    } catch {
        Write-Log -Message "Failed to generate report: $_" -Level Error
        throw "Failed to generate report: $_"
    }
}

# Function to list scan policies
function Get-ScanPolicies {
    Write-Log -Message "Getting available scan policies" -Level Info
    Write-Host "Getting scan policies..." -ForegroundColor Green
    
    try {
        $policies = Get-NessusPolicy
        Write-Log -Message "Found $($policies.Count) policies" -Level Info
        return $policies
    } catch {
        Write-Log -Message "Failed to get scan policies: $_" -Level Error
        throw "Failed to get scan policies: $_"
    }
}

# Main menu
function Show-Menu {
    Write-Host "`nNessus Automation Menu" -ForegroundColor Cyan
    Write-Host "1. Connect to Nessus Server"
    Write-Host "2. Start Basic Scan"
    Write-Host "3. Start Advanced Scan"
    Write-Host "4. Start Compliance Scan"
    Write-Host "5. Get Scan Status"
    Write-Host "6. Generate Report"
    Write-Host "7. List Scan Policies"
    Write-Host "8. Exit"
}

# Main execution
try {
    Write-Log -Message "Starting Nessus automation" -Level Info
    
    do {
        Show-Menu
        $choice = Read-Host "`nSelect an option"
        
        switch ($choice) {
            "1" {
                $server = Read-Host "Enter Nessus server URL (default: https://localhost:8834)"
                $apiKey = Read-Host "Enter API key (leave blank to use username/password)"
                if ($apiKey) {
                    Connect-NessusServer -Server $server -ApiKey $apiKey
                } else {
                    $username = Read-Host "Enter username"
                    $password = Read-Host "Enter password" -AsSecureString
                    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
                    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                    Connect-NessusServer -Server $server -Username $username -Password $plainPassword
                }
            }
            "2" {
                $target = Read-Host "Enter target"
                $scanName = Read-Host "Enter scan name"
                $scanId = Start-BasicScan -Target $target -ScanName $scanName
                Write-Host "Scan started with ID: $scanId" -ForegroundColor Green
            }
            "3" {
                $target = Read-Host "Enter target"
                $scanName = Read-Host "Enter scan name"
                $scanId = Start-AdvancedScan -Target $target -ScanName $scanName
                Write-Host "Scan started with ID: $scanId" -ForegroundColor Green
            }
            "4" {
                $target = Read-Host "Enter target"
                $scanName = Read-Host "Enter scan name"
                $scanId = Start-ComplianceScan -Target $target -ScanName $scanName
                Write-Host "Scan started with ID: $scanId" -ForegroundColor Green
            }
            "5" {
                $scanId = Read-Host "Enter scan ID"
                $status = Get-ScanStatus -ScanId $scanId
                Write-Host "Scan status: $($status.status)" -ForegroundColor Green
            }
            "6" {
                $scanId = Read-Host "Enter scan ID"
                $format = Read-Host "Enter report format (html/pdf/csv)"
                $outputFile = "C:\SecurityTools\Reports\nessus_scan_${scanId}_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').$format"
                New-NessusReport -ScanId $scanId -Format $format -OutputFile $outputFile
                Write-Host "Report generated: $outputFile" -ForegroundColor Green
            }
            "7" {
                $policies = Get-ScanPolicies
                foreach ($policy in $policies) {
                    Write-Host "ID: $($policy.id) - Name: $($policy.name)" -ForegroundColor Green
                }
            }
            "8" {
                Write-Log -Message "Exiting Nessus automation" -Level Info
                Write-Host "Exiting..." -ForegroundColor Yellow
                exit
            }
            default {
                Write-Host "Invalid option. Please try again." -ForegroundColor Red
            }
        }
    } while ($true)
} catch {
    Write-Log -Message "Error during Nessus automation: $_" -Level Error
    Write-Host "Error: $_" -ForegroundColor Red
} 