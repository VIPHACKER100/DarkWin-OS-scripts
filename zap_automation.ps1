# OWASP ZAP Automation Script

# Import required modules
Import-Module PSLogging

# Initialize logging
$logPath = "C:\SecurityTools\Logs\zap_automation_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
Start-Log -LogPath $logPath -LogLevel Info

# Function to start OWASP ZAP
function Start-ZAP {
    param (
        [string]$ConfigFile = "C:\SecurityTools\Configs\zap_config.json"
    )
    
    Write-Log -Message "Starting OWASP ZAP with config: $ConfigFile" -Level Info
    Write-Host "Starting OWASP ZAP..." -ForegroundColor Green
    
    # Start OWASP ZAP with configuration
    Start-Process "C:\Program Files\OWASP\Zed Attack Proxy\zap.bat" -ArgumentList "-config $ConfigFile"
    
    Write-Log -Message "OWASP ZAP started" -Level Info
}

# Function to start quick scan
function Start-QuickScan {
    param (
        [string]$Target,
        [string]$OutputFile
    )
    
    Write-Log -Message "Starting quick scan of $Target" -Level Info
    Write-Host "Starting quick scan..." -ForegroundColor Green
    
    # Create OWASP ZAP session file
    $sessionFile = "C:\SecurityTools\Projects\zap_quick_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').session"
    
    # Start OWASP ZAP with quick scan
    Start-Process "C:\Program Files\OWASP\Zed Attack Proxy\zap-cli.bat" -ArgumentList @(
        "quick-scan",
        "--self-contained",
        "--start-options",
        "-config api.disablekey=true",
        "-config api.addrs.addr.name=.*",
        "-config api.addrs.addr.regex=true",
        "-config api.key=12345",
        "-config database.newsession=3",
        "-config database.sessionpath=$sessionFile",
        $Target
    )
    
    Write-Log -Message "Quick scan started. Session saved to $sessionFile" -Level Info
    return $sessionFile
}

# Function to start full scan
function Start-FullScan {
    param (
        [string]$Target,
        [string]$OutputFile
    )
    
    Write-Log -Message "Starting full scan of $Target" -Level Info
    Write-Host "Starting full scan..." -ForegroundColor Green
    
    # Create OWASP ZAP session file
    $sessionFile = "C:\SecurityTools\Projects\zap_full_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').session"
    
    # Start OWASP ZAP with full scan
    Start-Process "C:\Program Files\OWASP\Zed Attack Proxy\zap-cli.bat" -ArgumentList @(
        "full-scan",
        "--self-contained",
        "--start-options",
        "-config api.disablekey=true",
        "-config api.addrs.addr.name=.*",
        "-config api.addrs.addr.regex=true",
        "-config api.key=12345",
        "-config database.newsession=3",
        "-config database.sessionpath=$sessionFile",
        $Target
    )
    
    Write-Log -Message "Full scan started. Session saved to $sessionFile" -Level Info
    return $sessionFile
}

# Function to start API scan
function Start-APIScan {
    param (
        [string]$Target,
        [string]$OutputFile
    )
    
    Write-Log -Message "Starting API scan of $Target" -Level Info
    Write-Host "Starting API scan..." -ForegroundColor Green
    
    # Create OWASP ZAP session file
    $sessionFile = "C:\SecurityTools\Projects\zap_api_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').session"
    
    # Start OWASP ZAP with API scan
    Start-Process "C:\Program Files\OWASP\Zed Attack Proxy\zap-cli.bat" -ArgumentList @(
        "api-scan",
        "--self-contained",
        "--start-options",
        "-config api.disablekey=true",
        "-config api.addrs.addr.name=.*",
        "-config api.addrs.addr.regex=true",
        "-config api.key=12345",
        "-config database.newsession=3",
        "-config database.sessionpath=$sessionFile",
        $Target
    )
    
    Write-Log -Message "API scan started. Session saved to $sessionFile" -Level Info
    return $sessionFile
}

# Function to generate report
function New-ZAPReport {
    param (
        [string]$SessionFile,
        [string]$OutputFile
    )
    
    Write-Log -Message "Generating report from $SessionFile" -Level Info
    Write-Host "Generating report..." -ForegroundColor Green
    
    # Start OWASP ZAP with report generation
    Start-Process "C:\Program Files\OWASP\Zed Attack Proxy\zap-cli.bat" -ArgumentList @(
        "report",
        "-o",
        $OutputFile,
        "-f",
        "html",
        "-s",
        $SessionFile
    )
    
    Write-Log -Message "Report generated: $OutputFile" -Level Info
    return $OutputFile
}

# Function to configure proxy
function Set-ZAPProxy {
    param (
        [string]$Interface = "127.0.0.1",
        [int]$Port = 8080
    )
    
    Write-Log -Message "Configuring OWASP ZAP proxy on ${Interface}:${Port}" -Level Info
    Write-Host "Configuring proxy..." -ForegroundColor Green
    
    # Update OWASP ZAP configuration
    $configFile = "C:\SecurityTools\Configs\zap_config.json"
    $config = Get-Content $configFile | ConvertFrom-Json
    
    $config.proxy.address = $Interface
    $config.proxy.port = $Port
    
    $config | ConvertTo-Json -Depth 10 | Set-Content $configFile
    
    Write-Log -Message "Proxy configured" -Level Info
}

# Main menu
function Show-Menu {
    Write-Host "`nOWASP ZAP Automation Menu" -ForegroundColor Cyan
    Write-Host "1. Start OWASP ZAP"
    Write-Host "2. Start Quick Scan"
    Write-Host "3. Start Full Scan"
    Write-Host "4. Start API Scan"
    Write-Host "5. Generate Report"
    Write-Host "6. Configure Proxy"
    Write-Host "7. Exit"
}

# Main execution
try {
    Write-Log -Message "Starting OWASP ZAP automation" -Level Info
    
    do {
        Show-Menu
        $choice = Read-Host "`nSelect an option"
        
        switch ($choice) {
            "1" {
                Start-ZAP
            }
            "2" {
                $target = Read-Host "Enter target URL"
                $outputFile = "C:\SecurityTools\Reports\zap_quick_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"
                $sessionFile = Start-QuickScan -Target $target -OutputFile $outputFile
                New-ZAPReport -SessionFile $sessionFile -OutputFile $outputFile
            }
            "3" {
                $target = Read-Host "Enter target URL"
                $outputFile = "C:\SecurityTools\Reports\zap_full_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"
                $sessionFile = Start-FullScan -Target $target -OutputFile $outputFile
                New-ZAPReport -SessionFile $sessionFile -OutputFile $outputFile
            }
            "4" {
                $target = Read-Host "Enter target URL"
                $outputFile = "C:\SecurityTools\Reports\zap_api_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"
                $sessionFile = Start-APIScan -Target $target -OutputFile $outputFile
                New-ZAPReport -SessionFile $sessionFile -OutputFile $outputFile
            }
            "5" {
                $sessionFile = Read-Host "Enter session file path"
                $outputFile = "C:\SecurityTools\Reports\zap_report_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"
                New-ZAPReport -SessionFile $sessionFile -OutputFile $outputFile
            }
            "6" {
                $interface = Read-Host "Enter interface (default: 127.0.0.1)"
                $port = Read-Host "Enter port (default: 8080)"
                Set-ZAPProxy -Interface $interface -Port $port
            }
            "7" {
                Write-Log -Message "Exiting OWASP ZAP automation" -Level Info
                Write-Host "Exiting..." -ForegroundColor Yellow
                exit
            }
            default {
                Write-Host "Invalid option. Please try again." -ForegroundColor Red
            }
        }
    } while ($true)
} catch {
    Write-Log -Message "Error during OWASP ZAP automation: $_" -Level Error
    Write-Host "Error: $_" -ForegroundColor Red
} 