# EventData.ps1
# Contains data about Windows Event IDs, their descriptions, and security implications

# Create a hashtable to store event information
$global:EventData = @{}

# Populate the hashtable with event information
function Initialize-EventData {
    # Security Events
    # Format: EventID = @{Description, Category, Subcategory, Monitoring, Threats, FalsePositives}
    
    # Log Management Events
    $global:EventData.Add(1100, @{
        Description = "The event logging service has shut down"
        Category = "----"
        Subcategory = "Service shutdown"
        Monitoring = "Monitor for unexpected service shutdowns"
        Threats = "Log tampering, Anti-forensics"
        FalsePositives = "System shutdown, Maintenance"
        Severity = "High"
    })
    
    $global:EventData.Add(1102, @{
        Description = "The audit log was cleared"
        Category = "-----"
        Subcategory = "Log clear"
        Monitoring = "Alert on all audit log clears"
        Threats = "Evidence destruction, Attack cleanup"
        FalsePositives = "Routine log maintenance"
        Severity = "High"
    })
    
    # System Events
    $global:EventData.Add(4611, @{
        Description = "A trusted logon process has been registered with the Local Security Authority"
        Category = "System"
        Subcategory = "Security System Extension"
        Monitoring = "Monitor for new logon processes"
        Threats = "Credential theft, Authentication bypass"
        FalsePositives = "Software installation"
        Severity = "Medium"
    })
    
    $global:EventData.Add(4616, @{
        Description = "The system time was changed"
        Category = "System"
        Subcategory = "Security State Change"
        Monitoring = "Track time changes outside NTP"
        Threats = "Log manipulation, Time-based attacks"
        FalsePositives = "Time zone changes, NTP updates"
        Severity = "Medium"
    })
    
    $global:EventData.Add(4618, @{
        Description = "A monitored security event pattern has occurred"
        Category = "System"
        Subcategory = "System Integrity"
        Monitoring = "Immediate investigation of patterns"
        Threats = "Policy violations, Attack patterns"
        FalsePositives = "Legitimate pattern matches"
        Severity = "High"
    })
    
    # Logon Events
    $global:EventData.Add(4624, @{
        Description = "An account was successfully logged on"
        Category = "Logon/Logoff"
        Subcategory = "Logon"
        Monitoring = "Monitor for unusual patterns"
        Threats = "Unauthorized access, Lateral movement"
        FalsePositives = "Normal user activity"
        Severity = "Low"
    })
    
    $global:EventData.Add(4625, @{
        Description = "An account failed to log on"
        Category = "Logon/Logoff"
        Subcategory = "Logon"
        Monitoring = "Alert on multiple failures"
        Threats = "Brute force attacks, Password spraying"
        FalsePositives = "Forgotten passwords"
        Severity = "Medium"
    })
    
    $global:EventData.Add(4634, @{
        Description = "An account was logged off"
        Category = "Logon/Logoff"
        Subcategory = "Logon"
        Monitoring = "Baseline normal patterns"
        Threats = "Session hijacking detection"
        FalsePositives = "Normal user logoffs"
        Severity = "Low"
    })
    
    # Add more events here...
    # I'm including a selection of the most important events, but you can add all events from the table
    
    # PowerShell Events
    $global:EventData.Add(4103, @{
        Description = "Microsoft-Windows-PowerShell"
        Category = "Microsoft-Windows-PowerShell"
        Subcategory = "Pipeline Execution"
        Monitoring = "Monitor for unusual pipeline executions"
        Threats = "Malicious script execution"
        FalsePositives = "Administrative scripting"
        Severity = "Medium"
    })
    
    $global:EventData.Add(4104, @{
        Description = "Scriptblock executed."
        Category = "Microsoft-Windows-PowerShell"
        Subcategory = "Execute a Remote Command"
        Monitoring = "Monitor for unauthorized script executions"
        Threats = "Malicious script execution"
        FalsePositives = "Administrative tasks"
        Severity = "High"
    })
    
    $global:EventData.Add(40961, @{
        Description = "PowerShell Console Starting."
        Category = "Microsoft-Windows-PowerShell"
        Subcategory = "PowerShell Console Startup"
        Monitoring = "Monitor for unexpected PowerShell console starts"
        Threats = "Unauthorized access"
        FalsePositives = "Administrative tasks"
        Severity = "Low"
    })
    
    $global:EventData.Add(40962, @{
        Description = "PowerShell Console Started."
        Category = "Microsoft-Windows-PowerShell"
        Subcategory = "PowerShell Console Startup"
        Monitoring = "Monitor for frequent PowerShell starts"
        Threats = "Potential malicious activity"
        FalsePositives = "Administrative tasks"
        Severity = "Low"
    })
    
    # Continue adding more events as needed from the provided list
}

# Function to get event severity color
function Get-SeverityColor {
    param (
        [string]$Severity
    )
    
    switch ($Severity) {
        "High" { return "Red" }
        "Medium" { return "Yellow" }
        "Low" { return "Green" }
        default { return "White" }
    }
}

# Initialize the event data
Initialize-EventData