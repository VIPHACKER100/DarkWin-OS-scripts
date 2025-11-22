# Burp Suite Automation Script

# Import required modules
Import-Module PSLogging

# Initialize logging
$logPath = "C:\SecurityTools\Logs\burp_automation_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
Start-Log -LogPath $logPath -LogLevel Info

# Function to start Burp Suite
function Start-BurpSuite {
    param (
        [string]$ConfigFile = "C:\SecurityTools\Configs\burp_config.json"
    )
    
    Write-Log -Message "Starting Burp Suite with config: $ConfigFile" -Level Info
    Write-Host "Starting Burp Suite..." -ForegroundColor Green
    
    # Start Burp Suite with configuration
    Start-Process "C:\Program Files\Burp Suite\burpsuite.exe" -ArgumentList "--config-file=$ConfigFile"
    
    Write-Log -Message "Burp Suite started" -Level Info
}

# Function to start passive scan
function Start-PassiveScan {
    param (
        [string]$Target,
        [string]$OutputFile
    )
    
    Write-Log -Message "Starting passive scan of $Target" -Level Info
    Write-Host "Starting passive scan..." -ForegroundColor Green
    
    # Create Burp Suite project file
    $projectFile = "C:\SecurityTools\Projects\burp_passive_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').burp"
    
    # Start Burp Suite with passive scan
    Start-Process "C:\Program Files\Burp Suite\burpsuite.exe" -ArgumentList @(
        "--config-file=C:\SecurityTools\Configs\burp_config.json",
        "--project-file=$projectFile",
        "--unpause-spider-and-scanner",
        "--target=$Target"
    )
    
    Write-Log -Message "Passive scan started. Project saved to $projectFile" -Level Info
    return $projectFile
}

# Function to start active scan
function Start-ActiveScan {
    param (
        [string]$Target,
        [string]$OutputFile
    )
    
    Write-Log -Message "Starting active scan of $Target" -Level Info
    Write-Host "Starting active scan..." -ForegroundColor Green
    
    # Create Burp Suite project file
    $projectFile = "C:\SecurityTools\Projects\burp_active_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').burp"
    
    # Start Burp Suite with active scan
    Start-Process "C:\Program Files\Burp Suite\burpsuite.exe" -ArgumentList @(
        "--config-file=C:\SecurityTools\Configs\burp_config.json",
        "--project-file=$projectFile",
        "--unpause-spider-and-scanner",
        "--target=$Target",
        "--scan-mode=active"
    )
    
    Write-Log -Message "Active scan started. Project saved to $projectFile" -Level Info
    return $projectFile
}

# Function to start crawl
function Start-Crawl {
    param (
        [string]$Target,
        [string]$OutputFile
    )
    
    Write-Log -Message "Starting crawl of $Target" -Level Info
    Write-Host "Starting crawl..." -ForegroundColor Green
    
    # Create Burp Suite project file
    $projectFile = "C:\SecurityTools\Projects\burp_crawl_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').burp"
    
    # Start Burp Suite with crawl
    Start-Process "C:\Program Files\Burp Suite\burpsuite.exe" -ArgumentList @(
        "--config-file=C:\SecurityTools\Configs\burp_config.json",
        "--project-file=$projectFile",
        "--unpause-spider-and-scanner",
        "--target=$Target",
        "--crawl-mode=active"
    )
    
    Write-Log -Message "Crawl started. Project saved to $projectFile" -Level Info
    return $projectFile
}

# Function to generate report
function New-BurpReport {
    param (
        [string]$ProjectFile,
        [string]$OutputFile
    )
    
    Write-Log -Message "Generating report from $ProjectFile" -Level Info
    Write-Host "Generating report..." -ForegroundColor Green
    
    # Start Burp Suite with report generation
    Start-Process "C:\Program Files\Burp Suite\burpsuite.exe" -ArgumentList @(
        "--config-file=C:\SecurityTools\Configs\burp_config.json",
        "--project-file=$ProjectFile",
        "--generate-report=$OutputFile"
    )
    
    Write-Log -Message "Report generated: $OutputFile" -Level Info
    return $OutputFile
}

# Function to configure proxy
function Set-BurpProxy {
    param (
        [string]$Interface = "127.0.0.1",
        [int]$Port = 8080
    )
    
    Write-Log -Message "Configuring Burp Suite proxy on ${Interface}:${Port}" -Level Info
    Write-Host "Configuring proxy..." -ForegroundColor Green
    
    # Update Burp Suite configuration
    $configFile = "C:\SecurityTools\Configs\burp_config.json"
    $config = Get-Content $configFile | ConvertFrom-Json
    
    $config.proxy.listeners[0].bind_address = $Interface
    $config.proxy.listeners[0].bind_port = $Port
    
    $config | ConvertTo-Json -Depth 10 | Set-Content $configFile
    
    Write-Log -Message "Proxy configured" -Level Info
}

# Main menu
function Show-Menu {
    Write-Host "`nBurp Suite Automation Menu" -ForegroundColor Cyan
    Write-Host "1. Start Burp Suite"
    Write-Host "2. Start Passive Scan"
    Write-Host "3. Start Active Scan"
    Write-Host "4. Start Crawl"
    Write-Host "5. Generate Report"
    Write-Host "6. Configure Proxy"
    Write-Host "7. Exit"
}

# Main execution
try {
    Write-Log -Message "Starting Burp Suite automation" -Level Info
    
    do {
        Show-Menu
        $choice = Read-Host "`nSelect an option"
        
        switch ($choice) {
            "1" {
                Start-BurpSuite
            }
            "2" {
                $target = Read-Host "Enter target URL"
                $outputFile = "C:\SecurityTools\Reports\burp_passive_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"
                $projectFile = Start-PassiveScan -Target $target -OutputFile $outputFile
                New-BurpReport -ProjectFile $projectFile -OutputFile $outputFile
            }
            "3" {
                $target = Read-Host "Enter target URL"
                $outputFile = "C:\SecurityTools\Reports\burp_active_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"
                $projectFile = Start-ActiveScan -Target $target -OutputFile $outputFile
                New-BurpReport -ProjectFile $projectFile -OutputFile $outputFile
            }
            "4" {
                $target = Read-Host "Enter target URL"
                $outputFile = "C:\SecurityTools\Reports\burp_crawl_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"
                $projectFile = Start-Crawl -Target $target -OutputFile $outputFile
                New-BurpReport -ProjectFile $projectFile -OutputFile $outputFile
            }
            "5" {
                $projectFile = Read-Host "Enter project file path"
                $outputFile = "C:\SecurityTools\Reports\burp_report_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"
                New-BurpReport -ProjectFile $projectFile -OutputFile $outputFile
            }
            "6" {
                $interface = Read-Host "Enter interface (default: 127.0.0.1)"
                $port = Read-Host "Enter port (default: 8080)"
                Set-BurpProxy -Interface $interface -Port $port
            }
            "7" {
                Write-Log -Message "Exiting Burp Suite automation" -Level Info
                Write-Host "Exiting..." -ForegroundColor Yellow
                exit
            }
            default {
                Write-Host "Invalid option. Please try again." -ForegroundColor Red
            }
        }
    } while ($true)
} catch {
    Write-Log -Message "Error during Burp Suite automation: $_" -Level Error
    Write-Host "Error: $_" -ForegroundColor Red
} 