# SearchFunctions.ps1
# Contains functions for searching different Windows event logs

# Function to search Security log
function Search-SecurityLog {
    param (
        [DateTime]$StartTime
    )
    
    try {
        # Get list of security event IDs to search for
        $securityEventIDs = $global:EventData.Keys | Where-Object { 
            ($global:EventData[$_].Category -like "*Security*" -or 
             $global:EventData[$_].Category -like "*Account*" -or 
             $global:EventData[$_].Category -like "*Logon*" -or 
             $global:EventData[$_].Category -like "*Policy*") 
        }
        
        Write-Progress -Activity "Searching Security Log" -Status "Starting search..." -PercentComplete 0
        
        # Get events from Security log
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            StartTime = $StartTime
            ID = $securityEventIDs
        } -ErrorAction SilentlyContinue
        
        $totalEvents = $events.Count
        $processedEvents = 0
        
        foreach ($event in $events) {
            $processedEvents++
            $percentComplete = [math]::Min(100, [math]::Round(($processedEvents / $totalEvents) * 100))
            Write-Progress -Activity "Searching Security Log" -Status "Processing event $processedEvents of $totalEvents" -PercentComplete $percentComplete
            
            # Create result object
            $result = [PSCustomObject]@{
                Timestamp = $event.TimeCreated
                EventID = $event.Id
                Source = $event.ProviderName
                Description = $global:EventData[$event.Id].Description
                Category = $global:EventData[$event.Id].Category
                Subcategory = $global:EventData[$event.Id].Subcategory
                Threats = $global:EventData[$event.Id].Threats
                FalsePositives = $global:EventData[$event.Id].FalsePositives
                Severity = $global:EventData[$event.Id].Severity
                Message = $event.Message
                Computer = $event.MachineName
                UserID = $event.UserId
            }
            
            # Add to results array
            $global:Results += $result
        }
        
        Write-Progress -Activity "Searching Security Log" -Completed
        
        # Report count
        if ($events.Count -gt 0) {
            Write-Host "  Found $($events.Count) security events of interest." -ForegroundColor Yellow
        } else {
            Write-Host "  No security events of interest found." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  Error searching Security log: $_" -ForegroundColor Red
    }
}

# Function to search System log
function Search-SystemLog {
    param (
        [DateTime]$StartTime
    )
    
    try {
        # Get list of system event IDs to search for
        $systemEventIDs = $global:EventData.Keys | Where-Object { 
            $global:EventData[$_].Category -like "*System*" 
        }
        
        Write-Progress -Activity "Searching System Log" -Status "Starting search..." -PercentComplete 0
        
        # Get events from System log
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            StartTime = $StartTime
            ID = $systemEventIDs
        } -ErrorAction SilentlyContinue
        
        $totalEvents = $events.Count
        $processedEvents = 0
        
        foreach ($event in $events) {
            $processedEvents++
            $percentComplete = [math]::Min(100, [math]::Round(($processedEvents / $totalEvents) * 100))
            Write-Progress -Activity "Searching System Log" -Status "Processing event $processedEvents of $totalEvents" -PercentComplete $percentComplete
            
            # Create result object
            $result = [PSCustomObject]@{
                Timestamp = $event.TimeCreated
                EventID = $event.Id
                Source = $event.ProviderName
                Description = $global:EventData[$event.Id].Description
                Category = $global:EventData[$event.Id].Category
                Subcategory = $global:EventData[$event.Id].Subcategory
                Threats = $global:EventData[$event.Id].Threats
                FalsePositives = $global:EventData[$event.Id].FalsePositives
                Severity = $global:EventData[$event.Id].Severity
                Message = $event.Message
                Computer = $event.MachineName
                UserID = $event.UserId
            }
            
            # Add to results array
            $global:Results += $result
        }
        
        Write-Progress -Activity "Searching System Log" -Completed
        
        # Report count
        if ($events.Count -gt 0) {
            Write-Host "  Found $($events.Count) system events of interest." -ForegroundColor Yellow
        } else {
            Write-Host "  No system events of interest found." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  Error searching System log: $_" -ForegroundColor Red
    }
}

# Function to search Application log
function Search-ApplicationLog {
    param (
        [DateTime]$StartTime
    )
    
    try {
        # Get list of application event IDs to search for
        $appEventIDs = $global:EventData.Keys | Where-Object { 
            $global:EventData[$_].Category -like "*Application*" 
        }
        
        Write-Progress -Activity "Searching Application Log" -Status "Starting search..." -PercentComplete 0
        
        # Get events from Application log
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            StartTime = $StartTime
            ID = $appEventIDs
        } -ErrorAction SilentlyContinue
        
        $totalEvents = $events.Count
        $processedEvents = 0
        
        foreach ($event in $events) {
            $processedEvents++
            $percentComplete = [math]::Min(100, [math]::Round(($processedEvents / $totalEvents) * 100))
            Write-Progress -Activity "Searching Application Log" -Status "Processing event $processedEvents of $totalEvents" -PercentComplete $percentComplete
            
            # Create result object
            $result = [PSCustomObject]@{
                Timestamp = $event.TimeCreated
                EventID = $event.Id
                Source = $event.ProviderName
                Description = $global:EventData[$event.Id].Description
                Category = $global:EventData[$event.Id].Category
                Subcategory = $global:EventData[$event.Id].Subcategory
                Threats = $global:EventData[$event.Id].Threats
                FalsePositives = $global:EventData[$event.Id].FalsePositives
                Severity = $global:EventData[$event.Id].Severity
                Message = $event.Message
                Computer = $event.MachineName
                UserID = $event.UserId
            }
            
            # Add to results array
            $global:Results += $result
        }
        
        Write-Progress -Activity "Searching Application Log" -Completed
        
        # Report count
        if ($events.Count -gt 0) {
            Write-Host "  Found $($events.Count) application events of interest." -ForegroundColor Yellow
        } else {
            Write-Host "  No application events of interest found." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  Error searching Application log: $_" -ForegroundColor Red
    }
}

# Function to search PowerShell log
function Search-PowerShellLog {
    param (
        [DateTime]$StartTime
    )
    
    try {
        # Get list of PowerShell event IDs to search for
        $psEventIDs = $global:EventData.Keys | Where-Object { 
            $global:EventData[$_].Category -like "*PowerShell*" 
        }
        
        Write-Progress -Activity "Searching PowerShell Log" -Status "Starting search..." -PercentComplete 0
        
        # Get events from PowerShell logs
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-PowerShell/Operational'
            StartTime = $StartTime
            ID = $psEventIDs
        } -ErrorAction SilentlyContinue
        
        $totalEvents = $events.Count
        $processedEvents = 0
        
        foreach ($event in $events) {
            $processedEvents++
            $percentComplete = [math]::Min(100, [math]::Round(($processedEvents / $totalEvents) * 100))
            Write-Progress -Activity "Searching PowerShell Log" -Status "Processing event $processedEvents of $totalEvents" -PercentComplete $percentComplete
            
            # Create result object
            $result = [PSCustomObject]@{
                Timestamp = $event.TimeCreated
                EventID = $event.Id
                Source = $event.ProviderName
                Description = $global:EventData[$event.Id].Description
                Category = $global:EventData[$event.Id].Category
                Subcategory = $global:EventData[$event.Id].Subcategory
                Threats = $global:EventData[$event.Id].Threats
                FalsePositives = $global:EventData[$event.Id].FalsePositives
                Severity = $global:EventData[$event.Id].Severity
                Message = $event.Message
                Computer = $event.MachineName
                UserID = $event.UserId
            }
            
            # Add to results array
            $global:Results += $result
        }
        
        Write-Progress -Activity "Searching PowerShell Log" -Completed
        
        # Report count
        if ($events.Count -gt 0) {
            Write-Host "  Found $($events.Count) PowerShell events of interest." -ForegroundColor Yellow
        } else {
            Write-Host "  No PowerShell events of interest found." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  Error searching PowerShell log: $_" -ForegroundColor Red
    }
}