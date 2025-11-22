# OpenVAS Automation Script

# Import required modules
Import-Module PSLogging
Import-Module security_logging

# Initialize logging
$logPath = Initialize-SecurityLogging -ToolName "OpenVAS" -LogLevel "Info"

# Function to connect to OpenVAS
function Connect-OpenVAS {
    param (
        [string]$Server = "https://localhost:9392",
        [string]$Username = "",
        [string]$Password = "",
        [string]$ApiKey = ""
    )
    
    Write-SecurityEvent -Message "Connecting to OpenVAS server: $Server" `
        -Level "Info" `
        -ToolName "OpenVAS" `
        -EventType "Connection" `
        -Severity "Low"
    
    Write-Host "Connecting to OpenVAS server..." -ForegroundColor Green
    
    try {
        # Set up OpenVAS connection
        $headers = @{
            "Content-Type" = "application/json"
        }
        
        if ($ApiKey) {
            $headers["X-API-Key"] = $ApiKey
        } else {
            # Get authentication token
            $authBody = @{
                username = $Username
                password = $Password
            } | ConvertTo-Json
            
            $response = Invoke-RestMethod -Uri "$Server/api/v1/auth" `
                -Method Post `
                -Headers $headers `
                -Body $authBody `
                -SkipCertificateCheck
            
            $headers["X-Auth-Token"] = $response.token
        }
        
        # Test connection
        $response = Invoke-RestMethod -Uri "$Server/api/v1/system/version" `
            -Method Get `
            -Headers $headers `
            -SkipCertificateCheck
        
        Write-SecurityEvent -Message "Successfully connected to OpenVAS server" `
            -Level "Info" `
            -ToolName "OpenVAS" `
            -EventType "Connection" `
            -Severity "Low" `
            -Details @{
                Version = $response.version
            }
        
        return $headers
    } catch {
        Write-SecurityEvent -Message "Failed to connect to OpenVAS server: $_" `
            -Level "Error" `
            -ToolName "OpenVAS" `
            -EventType "Connection" `
            -Severity "High"
        throw "Failed to connect to OpenVAS server: $_"
    }
}

# Function to start full scan
function Start-FullScan {
    param (
        [hashtable]$Headers,
        [string]$Target,
        [string]$ScanName,
        [string]$ConfigId = "daba56c8-73ec-11df-a475-002264764cea"  # Full and fast
    )
    
    Write-SecurityEvent -Message "Starting full scan of $Target" `
        -Level "Info" `
        -ToolName "OpenVAS" `
        -EventType "Scan" `
        -Severity "Medium" `
        -Details @{
            Target = $Target
            ScanName = $ScanName
            ConfigId = $ConfigId
        }
    
    Write-Host "Starting full scan..." -ForegroundColor Green
    
    try {
        # Create scan task
        $taskBody = @{
            name = $ScanName
            targets = @($Target)
            config_id = $ConfigId
            scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"  # Default scanner
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$Server/api/v1/tasks" `
            -Method Post `
            -Headers $Headers `
            -Body $taskBody `
            -SkipCertificateCheck
        
        # Start the scan
        $response = Invoke-RestMethod -Uri "$Server/api/v1/tasks/$($response.id)/start" `
            -Method Post `
            -Headers $Headers `
            -SkipCertificateCheck
        
        Write-SecurityEvent -Message "Full scan started with ID: $($response.id)" `
            -Level "Info" `
            -ToolName "OpenVAS" `
            -EventType "Scan" `
            -Severity "Medium" `
            -Details @{
                ScanId = $response.id
            }
        
        return $response.id
    } catch {
        Write-SecurityEvent -Message "Failed to start full scan: $_" `
            -Level "Error" `
            -ToolName "OpenVAS" `
            -EventType "Scan" `
            -Severity "High"
        throw "Failed to start full scan: $_"
    }
}

# Function to start compliance scan
function Start-ComplianceScan {
    param (
        [hashtable]$Headers,
        [string]$Target,
        [string]$ScanName,
        [string]$ConfigId = "698f691e-7489-11df-9d8c-002264764cea"  # Compliance
    )
    
    Write-SecurityEvent -Message "Starting compliance scan of $Target" `
        -Level "Info" `
        -ToolName "OpenVAS" `
        -EventType "Scan" `
        -Severity "Medium" `
        -Details @{
            Target = $Target
            ScanName = $ScanName
            ConfigId = $ConfigId
        }
    
    Write-Host "Starting compliance scan..." -ForegroundColor Green
    
    try {
        # Create scan task
        $taskBody = @{
            name = $ScanName
            targets = @($Target)
            config_id = $ConfigId
            scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"  # Default scanner
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$Server/api/v1/tasks" `
            -Method Post `
            -Headers $Headers `
            -Body $taskBody `
            -SkipCertificateCheck
        
        # Start the scan
        $response = Invoke-RestMethod -Uri "$Server/api/v1/tasks/$($response.id)/start" `
            -Method Post `
            -Headers $Headers `
            -SkipCertificateCheck
        
        Write-SecurityEvent -Message "Compliance scan started with ID: $($response.id)" `
            -Level "Info" `
            -ToolName "OpenVAS" `
            -EventType "Scan" `
            -Severity "Medium" `
            -Details @{
                ScanId = $response.id
            }
        
        return $response.id
    } catch {
        Write-SecurityEvent -Message "Failed to start compliance scan: $_" `
            -Level "Error" `
            -ToolName "OpenVAS" `
            -EventType "Scan" `
            -Severity "High"
        throw "Failed to start compliance scan: $_"
    }
}

# Function to get scan status
function Get-ScanStatus {
    param (
        [hashtable]$Headers,
        [string]$ScanId
    )
    
    Write-SecurityEvent -Message "Getting status for scan ID: $ScanId" `
        -Level "Info" `
        -ToolName "OpenVAS" `
        -EventType "Status" `
        -Severity "Low"
    
    try {
        $response = Invoke-RestMethod -Uri "$Server/api/v1/tasks/$ScanId" `
            -Method Get `
            -Headers $Headers `
            -SkipCertificateCheck
        
        Write-SecurityEvent -Message "Scan status: $($response.status)" `
            -Level "Info" `
            -ToolName "OpenVAS" `
            -EventType "Status" `
            -Severity "Low" `
            -Details @{
                Status = $response.status
                Progress = $response.progress
            }
        
        return $response
    } catch {
        Write-SecurityEvent -Message "Failed to get scan status: $_" `
            -Level "Error" `
            -ToolName "OpenVAS" `
            -EventType "Status" `
            -Severity "Medium"
        throw "Failed to get scan status: $_"
    }
}

# Function to generate report
function New-OpenVASReport {
    param (
        [hashtable]$Headers,
        [string]$ScanId,
        [string]$Format = "html",
        [string]$OutputFile
    )
    
    Write-SecurityEvent -Message "Generating $Format report for scan ID: $ScanId" `
        -Level "Info" `
        -ToolName "OpenVAS" `
        -EventType "Report" `
        -Severity "Low"
    
    Write-Host "Generating report..." -ForegroundColor Green
    
    try {
        # Get report format ID
        $formatId = switch ($Format) {
            "html" { "a994b278-1f62-11e1-96ac-406186ea4fc5" }
            "pdf" { "c402cc3e-b531-11e1-9163-406186ea4fc5" }
            "xml" { "a994b278-1f62-11e1-96ac-406186ea4fc5" }
            default { "a994b278-1f62-11e1-96ac-406186ea4fc5" }
        }
        
        # Generate report
        $reportBody = @{
            task_id = $ScanId
            format_id = $formatId
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$Server/api/v1/reports" `
            -Method Post `
            -Headers $Headers `
            -Body $reportBody `
            -SkipCertificateCheck
        
        # Download report
        $report = Invoke-RestMethod -Uri "$Server/api/v1/reports/$($response.id)" `
            -Method Get `
            -Headers $Headers `
            -SkipCertificateCheck
        
        $report | Out-File -FilePath $OutputFile
        
        Write-SecurityEvent -Message "Report generated: $OutputFile" `
            -Level "Info" `
            -ToolName "OpenVAS" `
            -EventType "Report" `
            -Severity "Low" `
            -Details @{
                ReportId = $response.id
                Format = $Format
                OutputFile = $OutputFile
            }
        
        return $OutputFile
    } catch {
        Write-SecurityEvent -Message "Failed to generate report: $_" `
            -Level "Error" `
            -ToolName "OpenVAS" `
            -EventType "Report" `
            -Severity "Medium"
        throw "Failed to generate report: $_"
    }
}

# Function to list scan configs
function Get-ScanConfigs {
    param (
        [hashtable]$Headers
    )
    
    Write-SecurityEvent -Message "Getting available scan configurations" `
        -Level "Info" `
        -ToolName "OpenVAS" `
        -EventType "Config" `
        -Severity "Low"
    
    Write-Host "Getting scan configurations..." -ForegroundColor Green
    
    try {
        $response = Invoke-RestMethod -Uri "$Server/api/v1/configs" `
            -Method Get `
            -Headers $Headers `
            -SkipCertificateCheck
        
        Write-SecurityEvent -Message "Found $($response.configs.Count) configurations" `
            -Level "Info" `
            -ToolName "OpenVAS" `
            -EventType "Config" `
            -Severity "Low"
        
        return $response.configs
    } catch {
        Write-SecurityEvent -Message "Failed to get scan configurations: $_" `
            -Level "Error" `
            -ToolName "OpenVAS" `
            -EventType "Config" `
            -Severity "Medium"
        throw "Failed to get scan configurations: $_"
    }
}

# Main menu
function Show-Menu {
    Write-Host "`nOpenVAS Automation Menu" -ForegroundColor Cyan
    Write-Host "1. Connect to OpenVAS Server"
    Write-Host "2. Start Full Scan"
    Write-Host "3. Start Compliance Scan"
    Write-Host "4. Get Scan Status"
    Write-Host "5. Generate Report"
    Write-Host "6. List Scan Configs"
    Write-Host "7. Exit"
}

# Main execution
try {
    Write-SecurityEvent -Message "Starting OpenVAS automation" `
        -Level "Info" `
        -ToolName "OpenVAS" `
        -EventType "Startup" `
        -Severity "Low"
    
    $headers = $null
    
    do {
        Show-Menu
        $choice = Read-Host "`nSelect an option"
        
        switch ($choice) {
            "1" {
                $server = Read-Host "Enter OpenVAS server URL (default: https://localhost:9392)"
                $apiKey = Read-Host "Enter API key (leave blank to use username/password)"
                if ($apiKey) {
                    $headers = Connect-OpenVAS -Server $server -ApiKey $apiKey
                } else {
                    $username = Read-Host "Enter username"
                    $password = Read-Host "Enter password" -AsSecureString
                    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
                    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                    $headers = Connect-OpenVAS -Server $server -Username $username -Password $plainPassword
                }
            }
            "2" {
                if (-not $headers) {
                    Write-Host "Please connect to OpenVAS server first." -ForegroundColor Red
                    continue
                }
                $target = Read-Host "Enter target"
                $scanName = Read-Host "Enter scan name"
                $scanId = Start-FullScan -Headers $headers -Target $target -ScanName $scanName
                Write-Host "Scan started with ID: $scanId" -ForegroundColor Green
            }
            "3" {
                if (-not $headers) {
                    Write-Host "Please connect to OpenVAS server first." -ForegroundColor Red
                    continue
                }
                $target = Read-Host "Enter target"
                $scanName = Read-Host "Enter scan name"
                $scanId = Start-ComplianceScan -Headers $headers -Target $target -ScanName $scanName
                Write-Host "Scan started with ID: $scanId" -ForegroundColor Green
            }
            "4" {
                if (-not $headers) {
                    Write-Host "Please connect to OpenVAS server first." -ForegroundColor Red
                    continue
                }
                $scanId = Read-Host "Enter scan ID"
                $status = Get-ScanStatus -Headers $headers -ScanId $scanId
                Write-Host "Scan status: $($status.status)" -ForegroundColor Green
            }
            "5" {
                if (-not $headers) {
                    Write-Host "Please connect to OpenVAS server first." -ForegroundColor Red
                    continue
                }
                $scanId = Read-Host "Enter scan ID"
                $format = Read-Host "Enter report format (html/pdf/xml)"
                $outputFile = "C:\SecurityTools\Reports\openvas_scan_${scanId}_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').$format"
                New-OpenVASReport -Headers $headers -ScanId $scanId -Format $format -OutputFile $outputFile
                Write-Host "Report generated: $outputFile" -ForegroundColor Green
            }
            "6" {
                if (-not $headers) {
                    Write-Host "Please connect to OpenVAS server first." -ForegroundColor Red
                    continue
                }
                $configs = Get-ScanConfigs -Headers $headers
                foreach ($config in $configs) {
                    Write-Host "ID: $($config.id) - Name: $($config.name)" -ForegroundColor Green
                }
            }
            "7" {
                Write-SecurityEvent -Message "Exiting OpenVAS automation" `
                    -Level "Info" `
                    -ToolName "OpenVAS" `
                    -EventType "Shutdown" `
                    -Severity "Low"
                Write-Host "Exiting..." -ForegroundColor Yellow
                exit
            }
            default {
                Write-Host "Invalid option. Please try again." -ForegroundColor Red
            }
        }
    } while ($true)
} catch {
    Write-SecurityEvent -Message "Error during OpenVAS automation: $_" `
        -Level "Error" `
        -ToolName "OpenVAS" `
        -EventType "Error" `
        -Severity "High"
    Write-Host "Error: $_" -ForegroundColor Red
} 