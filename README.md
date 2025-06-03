# WinLogHunt - Endpoint Log Investigation Tool

WinLogHunt is a PowerShell-based tool designed for Blue Teams and Incident Responders to quickly analyze Windows event logs for suspicious activities.

## Features

- Comprehensive analysis of Windows event logs (Security, System, Application, PowerShell)
- Detection of suspicious events based on a database of 100+ known security-relevant event IDs
- Detailed reporting with severity-based color coding
- Context-aware event interpretation showing potential threats and false positive scenarios
- Export capabilities for findings
- User-friendly interface with progress indicators

## Usage

1. Run the main script:
```powershell
>>powershell -ExecutionPolicy Bypass -File .\WinLogHunt.ps1
```
<p align="center">
    <img width="50%" src="https://i.imgur.com/VzEgtDz.png"> 
</p>

2. Choose from the options menu:
   - Start log investigation (default 24 hours)
   - Customize time range for investigation
   - Export results to CSV
   - View event database information

## Requirements

- Windows operating system
- PowerShell 5.1 or later
- Administrative privileges (to access certain event logs)

## Files

- **WinLogHunt.ps1**: Main script file
- **EventData.ps1**: Contains the database of event IDs and their security context
- **SearchFunctions.ps1**: Functions for searching various Windows event logs
- **ReportFunctions.ps1**: Functions for generating and displaying results
- **UIFunctions.ps1**: User interface components
- **EventData-Additional.ps1**: Additional event data that can be imported if needed

## Created By

Original template by Sahnoun_Oussama, enhanced with additional functionality.
