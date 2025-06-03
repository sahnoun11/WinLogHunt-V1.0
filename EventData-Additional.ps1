# EventData-Additional.ps1
# Contains additional event data that can be imported if needed

# This file contains additional event IDs that can be added to the main EventData.ps1 file
# To use this data, you can run: . "$PSScriptRoot\EventData-Additional.ps1"

function Add-AdditionalEventData {
    # Account Management Events
    $global:EventData.Add(4720, @{
        Description = "A user account was created."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for unauthorized account creation"
        Threats = "Privilege escalation, Backdoor accounts"
        FalsePositives = "Normal administrative tasks"
        Severity = "Medium"
    })
    
    $global:EventData.Add(4722, @{
        Description = "A user account was enabled."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for re-enabling of disabled accounts"
        Threats = "Privilege escalation"
        FalsePositives = "Administrative activity"
        Severity = "Medium"
    })
    
    $global:EventData.Add(4723, @{
        Description = "An attempt was made to change an account's password."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for unauthorized password change attempts"
        Threats = "Account compromise"
        FalsePositives = "Normal user activity"
        Severity = "Medium"
    })
    
    $global:EventData.Add(4724, @{
        Description = "An attempt was made to reset an account's password."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for unauthorized password reset attempts"
        Threats = "Account compromise"
        FalsePositives = "Normal user activity"
        Severity = "Medium"
    })
    
    $global:EventData.Add(4725, @{
        Description = "A user account was disabled."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for unexpected account disabling"
        Threats = "Privilege abuse"
        FalsePositives = "Normal administrative tasks"
        Severity = "Medium"
    })
    
    $global:EventData.Add(4726, @{
        Description = "A user account was deleted."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for unauthorized account deletions"
        Threats = "Privilege abuse"
        FalsePositives = "Normal administrative tasks"
        Severity = "Medium"
    })
    
    # Add more events as needed
    
    # Kerberos Events
    $global:EventData.Add(4768, @{
        Description = "A Kerberos authentication ticket (TGT) was requested."
        Category = "Account Logon"
        Subcategory = "Kerberos Authentication Service"
        Monitoring = "Monitor for unusual TGT requests"
        Threats = "Brute force attacks"
        FalsePositives = "Normal authentication operations"
        Severity = "Low"
    })
    
    $global:EventData.Add(4769, @{
        Description = "A Kerberos service ticket was requested."
        Category = "Account Logon"
        Subcategory = "Kerberos Service Ticket Operations"
        Monitoring = "Monitor for unusual service ticket requests"
        Threats = "Lateral movement"
        FalsePositives = "Legitimate service access"
        Severity = "Medium"
    })
    
    $global:EventData.Add(4771, @{
        Description = "Kerberos pre-authentication failed."
        Category = "Account Logon"
        Subcategory = "Kerberos Authentication Service"
        Monitoring = "Monitor for frequent pre-authentication failures"
        Threats = "Brute force attacks"
        FalsePositives = "User error"
        Severity = "Medium"
    })
    
    # Plug and Play Events
    $global:EventData.Add(6416, @{
        Description = "A new external device was recognized by the system."
        Category = "Process Tracking"
        Subcategory = "Plug and Play"
        Monitoring = "Monitor for unauthorized devices"
        Threats = "Unauthorized data transfer"
        FalsePositives = "Planned device usage"
        Severity = "Medium"
    })
    
    $global:EventData.Add(6419, @{
        Description = "A request was made to disable a device."
        Category = "Process Tracking"
        Subcategory = "Plug and Play"
        Monitoring = "Monitor for unexpected device disable requests"
        Threats = "Device tampering"
        FalsePositives = "Administrative tasks"
        Severity = "Low"
    })
    
    Write-Host "Added $(($global:EventData.Count) - $initialCount) additional event IDs to the database." -ForegroundColor Green
}

# Call the function to add the additional data if needed
# To use this, uncomment the line below
# Add-AdditionalEventData