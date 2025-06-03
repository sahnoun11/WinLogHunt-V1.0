# UIFunctions.ps1
# Contains functions for user interface elements

# Function to display options menu
function Show-OptionsMenu {
    $continue = $true
    
    while ($continue) {
        Write-Host ""
        Write-Host "=== WinLogHunt Options ===" -ForegroundColor Cyan
        Write-Host "1. Start log investigation (last 24 hours)" -ForegroundColor White
        Write-Host "2. Start log investigation (custom time range)" -ForegroundColor White
        Write-Host "3. Export event data to CSV" -ForegroundColor White
        Write-Host "4. Show event database information" -ForegroundColor White
        Write-Host "5. Exit" -ForegroundColor White
        Write-Host ""
        
        $choice = Read-Host "Enter your choice (1-5)"
        
        switch ($choice) {
            "1" {
                Start-LogInvestigation
            }
            "2" {
                $hours = Read-Host "Enter number of hours to look back"
                if ($hours -match "^\d+$") {
                    Start-LogInvestigation -HoursBack ([int]$hours)
                } else {
                    Write-Host "Invalid input. Please enter a number." -ForegroundColor Red
                }
            }
            "3" {
                $exportPath = Read-Host "Enter export path (default: Desktop\WinLogHunt_Results.csv)"
                if ([string]::IsNullOrWhiteSpace($exportPath)) {
                    $exportPath = "$env:USERPROFILE\Desktop\WinLogHunt_Results.csv"
                }
                Start-LogInvestigation -ExportResults -ExportPath $exportPath
            }
            "4" {
                Show-EventDatabase
            }
            "5" {
                $continue = $false
                Write-Host "Exiting WinLogHunt. Thank you for using this tool!" -ForegroundColor Cyan
            }
            default {
                Write-Host "Invalid choice. Please enter a number between 1 and 5." -ForegroundColor Red
            }
        }
    }
}

# Function to show event database information
function Show-EventDatabase {
    $totalEvents = $global:EventData.Count
    
    Write-Host ""
    Write-Host "=== Event Database Information ===" -ForegroundColor Cyan
    Write-Host "Total events in database: $totalEvents" -ForegroundColor White
    
    # Group events by category
    $categories = $global:EventData.Values | Group-Object -Property Category | Sort-Object Count -Descending
    
    Write-Host ""
    Write-Host "Events by Category:" -ForegroundColor Yellow
    foreach ($category in $categories) {
        if (-not [string]::IsNullOrWhiteSpace($category.Name)) {
            Write-Host "  $($category.Name): $($category.Count) events" -ForegroundColor White
        }
    }
    
    # Group by severity
    $severities = $global:EventData.Values | Group-Object -Property Severity | Sort-Object Name
    
    Write-Host ""
    Write-Host "Events by Severity:" -ForegroundColor Yellow
    foreach ($severity in $severities) {
        $color = Get-SeverityColor -Severity $severity.Name
        Write-Host "  $($severity.Name): $($severity.Count) events" -ForegroundColor $color
    }
    
    Write-Host ""
    Write-Host "Press Enter to return to the main menu..." -ForegroundColor Cyan
    Read-Host | Out-Null
}

# Function to show a progress animation
function Show-ProgressAnimation {
    param (
        [string]$Activity,
        [int]$DurationSeconds = 3
    )
    
    $chars = '|', '/', '-', '\'
    $startTime = Get-Date
    $endTime = $startTime.AddSeconds($DurationSeconds)
    
    $i = 0
    while ((Get-Date) -lt $endTime) {
        Write-Host "`r$Activity $($chars[$i % $chars.Length])" -NoNewline
        Start-Sleep -Milliseconds 250
        $i++
    }
    
    Write-Host "`r$Activity Complete!     " 
}