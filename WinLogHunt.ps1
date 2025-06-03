# WinLogHunt.ps1
# Windows Event Log Investigation Tool
# Created by: Sahnoun_Oussama (Script template)
# Enhanced by: [Your Name]

# Import required modules
. "$PSScriptRoot\EventData.ps1"
. "$PSScriptRoot\SearchFunctions.ps1"
. "$PSScriptRoot\ReportFunctions.ps1"
. "$PSScriptRoot\UIFunctions.ps1"

# Signature Banner
function Show-LogInvestigatorBanner {
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "   WinLogHunt - Endpoint Log Investigation Tool" -ForegroundColor Yellow
    Write-Host "  Created for Blue Teams and Incident Responders" -ForegroundColor Yellow
    Write-Host "  Created By Sahnoun_Oussama" -ForegroundColor Yellow
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "We will begin by analyzing key Windows event logs." -ForegroundColor Green
    Write-Host ""
}

# Show Log Location Info
function Show-LogFilePaths {
    Write-Host " Windows stores its event logs in several key locations:" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "Log Type           Path" -ForegroundColor White
    Write-Host "---------          ----"
    Write-Host "Application        %SystemRoot%\System32\Winevt\Logs\Application.evtx"
    Write-Host "Security           %SystemRoot%\System32\Winevt\Logs\Security.evtx"
    Write-Host "System             %SystemRoot%\System32\Winevt\Logs\System.evtx"
    Write-Host "Setup              %SystemRoot%\System32\Winevt\Logs\Setup.evtx"
    Write-Host "Forwarded Events   %SystemRoot%\System32\Winevt\Logs\ForwardedEvents.evtx"
    Write-Host ""
    Write-Host ""
}

function Start-LogInvestigation {
    param (
        [int]$HoursBack = 24,
        [switch]$ExportResults,
        [string]$ExportPath = "$env:USERPROFILE\Desktop\WinLogHunt_Results.csv"
    )

    Write-Host "Starting Windows Event Log investigation for the past $HoursBack hours..." -ForegroundColor Cyan
    
    # Initialize results container
    $global:Results = @()
    
    # Set time range for event search
    $startTime = (Get-Date).AddHours(-$HoursBack)
    
    # Search Security Log
    Write-Host "Searching Security logs..." -ForegroundColor Yellow
    Search-SecurityLog -StartTime $startTime
    
    # Search System Log
    Write-Host "Searching System logs..." -ForegroundColor Yellow
    Search-SystemLog -StartTime $startTime
    
    # Search Application Log
    Write-Host "Searching Application logs..." -ForegroundColor Yellow
    Search-ApplicationLog -StartTime $startTime
    
    # Search PowerShell Logs
    Write-Host "Searching PowerShell logs..." -ForegroundColor Yellow
    Search-PowerShellLog -StartTime $startTime
    
    # Generate and display report
    Show-InvestigationResults
    
    # Export results if requested
    if ($ExportResults -and $global:Results.Count -gt 0) {
        $global:Results | Export-Csv -Path $ExportPath -NoTypeInformation
        Write-Host "Results exported to: $ExportPath" -ForegroundColor Green
    }
}

# Entry Point
Show-LogInvestigatorBanner
Show-LogFilePaths

# Provide options menu
Show-OptionsMenu