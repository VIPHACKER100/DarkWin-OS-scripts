# Security Logging Module

# Import required modules
Import-Module PSLogging

# Initialize logging configuration
$script:LogConfig = @{
    BasePath = "C:\SecurityTools\Logs"
    LogLevels = @{
        Debug = 0
        Info = 1
        Warning = 2
        Error = 3
        Critical = 4
    }
    CurrentLevel = 1  # Default to Info level
    MaxLogSize = 10MB
    MaxLogAge = 30    # days
    LogFormat = "{timestamp} [{level}] {message} {details}"
}

# Function to initialize logging
function Initialize-SecurityLogging {
    param (
        [string]$ToolName,
        [string]$LogLevel = "Info"
    )
    
    # Create log directory if it doesn't exist
    if (-not (Test-Path $LogConfig.BasePath)) {
        New-Item -ItemType Directory -Path $LogConfig.BasePath -Force | Out-Null
    }
    
    # Set current log level
    $LogConfig.CurrentLevel = $LogConfig.LogLevels[$LogLevel]
    
    # Create tool-specific log file
    $logPath = Join-Path $LogConfig.BasePath "${ToolName}_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
    Start-Log -LogPath $logPath -LogLevel $LogLevel
    
    Write-Log -Message "Initialized logging for $ToolName" -Level Info
    return $logPath
}

# Function to write security event
function Write-SecurityEvent {
    param (
        [string]$Message,
        [string]$Level = "Info",
        [hashtable]$Details = @{},
        [string]$ToolName,
        [string]$EventType,
        [string]$Severity
    )
    
    # Check if log level is enabled
    if ($LogConfig.LogLevels[$Level] -lt $LogConfig.CurrentLevel) {
        return
    }
    
    # Format event details
    $eventDetails = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Level = $Level
        Message = $Message
        ToolName = $ToolName
        EventType = $EventType
        Severity = $Severity
    }
    
    # Add custom details
    foreach ($key in $Details.Keys) {
        $eventDetails[$key] = $Details[$key]
    }
    
    # Format log message
    $logMessage = $LogConfig.LogFormat -replace "{timestamp}", $eventDetails.Timestamp `
        -replace "{level}", $eventDetails.Level `
        -replace "{message}", $eventDetails.Message `
        -replace "{details}", ($eventDetails | ConvertTo-Json -Compress)
    
    # Write to log
    Write-Log -Message $logMessage -Level $Level
    
    # Write to Windows Event Log for critical events
    if ($Level -eq "Critical") {
        Write-EventLog -LogName "Security" -Source "SecurityTools" -EventId 1000 -EntryType Error -Message $logMessage
    }
}

# Function to rotate logs
function Start-LogRotation {
    param (
        [string]$LogPath
    )
    
    # Get log file info
    $logFile = Get-Item $LogPath
    $logAge = (Get-Date) - $logFile.CreationTime
    
    # Check log size
    if ($logFile.Length -gt $LogConfig.MaxLogSize) {
        # Archive current log
        $archivePath = $LogPath -replace "\.log$", "_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
        Move-Item -Path $LogPath -Destination $archivePath
        
        # Start new log
        Start-Log -LogPath $LogPath -LogLevel "Info"
        Write-Log -Message "Rotated log file due to size limit" -Level Info
    }
    
    # Check log age
    if ($logAge.TotalDays -gt $LogConfig.MaxLogAge) {
        # Archive old log
        $archivePath = $LogPath -replace "\.log$", "_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
        Move-Item -Path $LogPath -Destination $archivePath
        
        # Start new log
        Start-Log -LogPath $LogPath -LogLevel "Info"
        Write-Log -Message "Rotated log file due to age limit" -Level Info
    }
}

# Function to get log statistics
function Get-LogStatistics {
    param (
        [string]$LogPath
    )
    
    $stats = @{
        TotalEvents = 0
        EventsByLevel = @{}
        EventsByTool = @{}
        EventsByType = @{}
        CriticalEvents = 0
        Errors = 0
        Warnings = 0
    }
    
    # Read log file
    Get-Content $LogPath | ForEach-Object {
        if ($_ -match '\[(.*?)\]') {
            $level = $matches[1]
            $stats.TotalEvents++
            $stats.EventsByLevel[$level]++
            
            if ($_ -match '"ToolName":"(.*?)"') {
                $tool = $matches[1]
                $stats.EventsByTool[$tool]++
            }
            
            if ($_ -match '"EventType":"(.*?)"') {
                $type = $matches[1]
                $stats.EventsByType[$type]++
            }
            
            switch ($level) {
                "Critical" { $stats.CriticalEvents++ }
                "Error" { $stats.Errors++ }
                "Warning" { $stats.Warnings++ }
            }
        }
    }
    
    return $stats
}

# Function to search logs
function Search-SecurityLogs {
    param (
        [string]$LogPath,
        [string]$SearchTerm,
        [string]$Level,
        [string]$ToolName,
        [string]$EventType,
        [datetime]$StartTime,
        [datetime]$EndTime
    )
    
    $results = @()
    
    # Read log file
    Get-Content $LogPath | ForEach-Object {
        $line = $_
        $match = $true
        
        # Apply filters
        if ($SearchTerm -and $line -notmatch $SearchTerm) { $match = $false }
        if ($Level -and $line -notmatch "\[$Level\]") { $match = $false }
        if ($ToolName -and $line -notmatch "`"ToolName`":`"$ToolName`"") { $match = $false }
        if ($EventType -and $line -notmatch "`"EventType`":`"$EventType`"") { $match = $false }
        
        if ($StartTime -or $EndTime) {
            if ($line -match '(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})') {
                $eventTime = [datetime]::ParseExact($matches[1], "yyyy-MM-dd HH:mm:ss", $null)
                if ($StartTime -and $eventTime -lt $StartTime) { $match = $false }
                if ($EndTime -and $eventTime -gt $EndTime) { $match = $false }
            }
        }
        
        if ($match) {
            $results += $line
        }
    }
    
    return $results
}

# Export functions
Export-ModuleMember -Function @(
    'Initialize-SecurityLogging',
    'Write-SecurityEvent',
    'Start-LogRotation',
    'Get-LogStatistics',
    'Search-SecurityLogs'
) 