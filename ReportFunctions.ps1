# ReportFunctions.ps1
# Contains functions for reporting and displaying results

# Function to display investigation results
function Show-InvestigationResults {
    Write-Host ""
    Write-Host "===== INVESTIGATION RESULTS =====" -ForegroundColor Cyan
    
    if ($global:Results.Count -eq 0) {
        Write-Host ""
        Write-Host "No events of interest were found. You appear to be safe!" -ForegroundColor Green
        Write-Host ""
        return
    }
    
    # Sort results by severity and timestamp
    $sortedResults = $global:Results | Sort-Object Severity, Timestamp -Descending
    
    # Display summary by severity
    $highSeverity = ($sortedResults | Where-Object { $_.Severity -eq "High" }).Count
    $mediumSeverity = ($sortedResults | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowSeverity = ($sortedResults | Where-Object { $_.Severity -eq "Low" }).Count
    
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor White
    Write-Host "--------" -ForegroundColor White
    Write-Host "Total Events Found: $($sortedResults.Count)" -ForegroundColor White
    Write-Host "High Severity: $highSeverity" -ForegroundColor Red
    Write-Host "Medium Severity: $mediumSeverity" -ForegroundColor Yellow
    Write-Host "Low Severity: $lowSeverity" -ForegroundColor Green
    Write-Host ""
    
    # Group results by category
    $categoryGroups = $sortedResults | Group-Object Category
    
    Write-Host "Events by Category:" -ForegroundColor White
    Write-Host "-----------------" -ForegroundColor White
    foreach ($group in $categoryGroups) {
        Write-Host "$($group.Name): $($group.Count) events" -ForegroundColor Cyan
    }
    Write-Host ""
    
    # Display detailed results
    Write-Host "Detailed Findings:" -ForegroundColor White
    Write-Host "-----------------" -ForegroundColor White
    
    foreach ($result in $sortedResults) {
        $severityColor = Get-SeverityColor -Severity $result.Severity
        
        Write-Host ""
        Write-Host "Event ID $($result.EventID): $($result.Description)" -ForegroundColor $severityColor
        Write-Host "Timestamp: $($result.Timestamp)" -ForegroundColor White
        Write-Host "Source: $($result.Source)" -ForegroundColor White
        Write-Host "Category: $($result.Category)" -ForegroundColor White
        Write-Host "Subcategory: $($result.Subcategory)" -ForegroundColor White
        Write-Host "Severity: $($result.Severity)" -ForegroundColor $severityColor
        Write-Host "Potential Threats: $($result.Threats)" -ForegroundColor Yellow
        Write-Host "Possible False Positives: $($result.FalsePositives)" -ForegroundColor Cyan
        Write-Host "Computer: $($result.Computer)" -ForegroundColor White
        
        # Truncate message if too long
        if ($result.Message.Length -gt 300) {
            $truncatedMessage = $result.Message.Substring(0, 300) + "..."
            Write-Host "Message (truncated): $truncatedMessage" -ForegroundColor Gray
        } else {
            Write-Host "Message: $($result.Message)" -ForegroundColor Gray
        }
        
        Write-Host "-----------------" -ForegroundColor DarkGray
    }
    
    Write-Host ""
    Write-Host "===== END OF RESULTS =====" -ForegroundColor Cyan
    Write-Host ""
}

# Function to create a summary report
function Get-InvestigationSummary {
    if ($global:Results.Count -eq 0) {
        return "No events of interest were found. System appears to be safe."
    }
    
    # Sort results by severity and timestamp
    $sortedResults = $global:Results | Sort-Object Severity, Timestamp -Descending
    
    # Count by severity
    $highSeverity = ($sortedResults | Where-Object { $_.Severity -eq "High" }).Count
    $mediumSeverity = ($sortedResults | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowSeverity = ($sortedResults | Where-Object { $_.Severity -eq "Low" }).Count
    
    # Create summary text
    $summary = "Investigation Summary:`n"
    $summary += "-------------------`n"
    $summary += "Total Events Found: $($sortedResults.Count)`n"
    $summary += "High Severity: $highSeverity`n"
    $summary += "Medium Severity: $mediumSeverity`n"
    $summary += "Low Severity: $lowSeverity`n`n"
    
    # Add top high severity events if any
    if ($highSeverity -gt 0) {
        $summary += "Top High Severity Events:`n"
        $topHigh = $sortedResults | Where-Object { $_.Severity -eq "High" } | Select-Object -First 3
        
        foreach ($event in $topHigh) {
            $summary += "- Event ID $($event.EventID): $($event.Description) at $($event.Timestamp)`n"
        }
        $summary += "`n"
    }
    
    # Add recommendation based on findings
    if ($highSeverity -gt 0) {
        $summary += "RECOMMENDATION: Immediate investigation required due to high severity events.`n"
    } elseif ($mediumSeverity -gt 0) {
        $summary += "RECOMMENDATION: Further investigation recommended for medium severity events.`n"
    } else {
        $summary += "RECOMMENDATION: System appears generally safe with only low severity events.`n"
    }
    
    return $summary
}