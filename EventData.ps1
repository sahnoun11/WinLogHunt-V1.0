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
    $global:EventData.Add(4697, @{
        Description = "A service was installed in the system"
        Category = "System"
        Subcategory = "Security System Extension"
        Monitoring = "Alert on new services"
        Threats = "Persistence, Backdoor installation"
        FalsePositives = "Legitimate service installation"
        Severity = "High"
    })
    $global:EventData.Add(5038, @{
        Description = "Code integrity determined that the image hash of a file is not valid."
        Category = "System"
        Subcategory = "System Integrity"
        Monitoring = "Monitor for invalid file hashes"
        Threats = "Malware infection"
        FalsePositives = "File corruption"
        Severity = "High"
    })
    $global:EventData.Add(5146, @{
        Description = "The Windows Filtering Platform has blocked a packet."
        Category = "System"
        Subcategory = "Other System Events"
        Monitoring = "Monitor for unexpected packet blocks"
        Threats = "Malicious traffic"
        FalsePositives = "Network misconfiguration"
        Severity = "High"
    })
    $global:EventData.Add(6281, @{
        Description = "Code Integrity determined that the page hashes of an image file are not valid."
        Category = "System"
        Subcategory = "System Integrity"
        Monitoring = "Monitor for invalid page hashes"
        Threats = "Malware injection"
        FalsePositives = "File corruption"
        Severity = "High"
    })
    $global:EventData.Add(6410, @{
        Description = "Code integrity determined that a file does not meet the security requirements to load into a process."
        Category = "System"
        Subcategory = "System Integrity"
        Monitoring = "Monitor for file loading failures"
        Threats = "Malware injection"
        FalsePositives = "File corruption"
        Severity = "High"
    })
    # Object Access Events
    $global:EventData.Add(4657, @{
        Description = "A registry value was modified"
        Category = "Object Access"
        Subcategory = "Registry"
        Monitoring = "Monitor critical keys"
        Threats = "Persistence, Configuration changes"
        FalsePositives = "Software updates"
        Severity = "Medium"
    })
    $global:EventData.Add(4670, @{
        Description = "Permissions on an object were changed"
        Category = "Object Access"
        Subcategory = "File System,Registry"
        Monitoring = "Track sensitive object changes"
        Threats = "Privilege escalation, Access control changes"
        FalsePositives = "Legitimate permission updates"
        Severity = "High"
    })
    $global:EventData.Add(4698, @{
        Description = "A scheduled task was created"
        Category = "Object Access"
        Subcategory = "Other Object Access Events"
        Monitoring = "Monitor new task creation"
        Threats = "Persistence, Scheduled execution"
        FalsePositives = "Legitimate task scheduling"
        Severity = "Medium"
    })
    $global:EventData.Add(4699, @{
        Description = "A scheduled task was deleted."
        Category = "Object Access"
        Subcategory = "Other Object Access Events"
        Monitoring = "Monitor for unexpected task deletions"
        Threats = "Persistence removal"
        FalsePositives = "Administrative tasks"
        Severity = "Low"
    })
    $global:EventData.Add(4700, @{
        Description = "A scheduled task was enabled."
        Category = "Object Access"
        Subcategory = "Other Object Access Events"
        Monitoring = "Monitor for unauthorized task enabling"
        Threats = "Task misuse"
        FalsePositives = "Administrative tasks"
        Severity = "Medium"
    })
    $global:EventData.Add(4702, @{
        Description = "A scheduled task was updated."
        Category = "Object Access"
        Subcategory = "Other Object Access Events"
        Monitoring = "Monitor for unauthorized task updates"
        Threats = "Persistence mechanisms"
        FalsePositives = "Administrative tasks"
        Severity = "Medium"
    })
    $global:EventData.Add(4882, @{
        Description = "The security permissions for Certificate Services changed."
        Category = "Object Access"
        Subcategory = "Certification Services"
        Monitoring = "Monitor for unexpected certificate permissions changes"
        Threats = "Certificate misuse"
        FalsePositives = "Administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(4885, @{
        Description = "The audit filter for Certificate Services changed."
        Category = "Object Access"
        Subcategory = "Certification Services"
        Monitoring = "Monitor for unauthorized audit filter changes"
        Threats = "Policy tampering"
        FalsePositives = "Planned updates"
        Severity = "High"
    })
    $global:EventData.Add(4890, @{
        Description = "The certificate manager settings for Certificate Services changed."
        Category = "Object Access"
        Subcategory = "Certification Services"
        Monitoring = "Monitor for unauthorized manager settings changes"
        Threats = "Configuration tampering"
        FalsePositives = "Administrative tasks"
        Severity = "Medium"
    })
    $global:EventData.Add(5142, @{
        Description = "Network share object added."
        Category = "Object Access"
        Subcategory = "File Share"
        Monitoring = "Monitor for unauthorized network shares"
        Threats = "Unauthorized data sharing"
        FalsePositives = "Administrative tasks"
        Severity = "Medium"
    })
    $global:EventData.Add(5143, @{
        Description = "Network share object changed."
        Category = "Object Access"
        Subcategory = "File Share"
        Monitoring = "Monitor for changes to critical network shares"
        Threats = "Data leakage"
        FalsePositives = "Policy updates"
        Severity = "High"
    })
    $global:EventData.Add(5144, @{
        Description = "Network share object deleted."
        Category = "Object Access"
        Subcategory = "File Share"
        Monitoring = "Monitor for deleted network shares"
        Threats = "Unauthorized data removal"
        FalsePositives = "Maintenance tasks"
        Severity = "Medium"
    })
    $global:EventData.Add(5158, @{
        Description = "The Windows Filtering Platform has permitted a bind to a local port."
        Category = "Object Access"
        Subcategory = "Filtering Platform Connection"
        Monitoring = "Monitor for unusual port bindings"
        Threats = "Unauthorized services"
        FalsePositives = "Legitimate application usage"
        Severity = "High"
    })
    $global:EventData.Add(5140, @{
        Description = "(NOISY!) Network share object accessed."
        Category = "Object Access"
        Subcategory = "File Share"
        Monitoring = "Monitor for abnormal network share access"
        Threats = "Data exfiltration"
        FalsePositives = "Normal file sharing"
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
    $global:EventData.Add(4647, @{
        Description = "User initiated logoff"
        Category = "Logon/Logoff"
        Subcategory = "Logon"
        Monitoring = "Compare with 4634 events"
        Threats = "Forced logoffs, Session termination"
        FalsePositives = "Normal user logoffs"
        Severity = "Low"
    })
    $global:EventData.Add(4648, @{
        Description = "A logon was attempted using explicit credentials"
        Category = "Logon/Logoff"
        Subcategory = "Logon"
        Monitoring = "Alert on unexpected usage"
        Threats = "Pass-the-hash, Credential abuse"
        FalsePositives = "RunAs operations"
        Severity = "High"
    })     
    $global:EventData.Add(4672, @{
        Description = "Special privileges assigned to new logon"
        Category = "Logon/Logoff"
        Subcategory = "Special Logon"
        Monitoring = "Alert on privilege assignments"
        Threats = "Privilege escalation, Admin abuse"
        FalsePositives = "Admin logons"
        Severity = "High"
    })
    $global:EventData.Add(4778, @{
        Description = "A session was reconnected to a Window Station."
        Category = "Logon/Logoff"
        Subcategory = "Other Logon/Logoff Events"
        Monitoring = "Monitor for unexpected session reconnections"
        Threats = "Session hijacking"
        FalsePositives = "Normal user activity"
        Severity = "Low"
    })
    $global:EventData.Add(4779, @{
        Description = "A session was disconnected from a Window Station."
        Category = "Logon/Logoff"
        Subcategory = "Other Logon/Logoff Events"
        Monitoring = "Monitor for unexpected session disconnections"
        Threats = "Session hijacking"
        FalsePositives = "Normal user activity"
        Severity = "Low"
    })
    $global:EventData.Add(4800, @{
        Description = "The workstation was locked."
        Category = "Logon/Logoff"
        Subcategory = "Other Logon/Logoff Events"
        Monitoring = "Monitor for unusual workstation lock activities"
        Threats = "Suspicious user behavior"
        FalsePositives = "Normal user activity"
        Severity = "Low"
    })
    $global:EventData.Add(4801, @{
        Description = "The workstation was locked."
        Category = "Logon/Logoff"
        Subcategory = "Other Logon/Logoff Events"
        Monitoring = "Monitor for unusual workstation lock activities"
        Threats = "Suspicious user behavior"
        FalsePositives = "Normal user activity"
        Severity = "Low"
    })
    $global:EventData.Add(4964, @{
        Description = "Special groups assigned to a new logon."
        Category = "Logon/Logoff"
        Subcategory = "Special Logon"
        Monitoring = "Monitor for unexpected special group assignments"
        Threats = "Privilege escalation"
        FalsePositives = "Administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(5378, @{
        Description = "The requested credentials delegation was disallowed by policy."
        Category = "Logon/Logoff"
        Subcategory = "Other Logon/Logoff Events"
        Monitoring = "Monitor for repeated delegation disallowances"
        Threats = "Policy misconfiguration"
        FalsePositives = "Normal policy behavior"
        Severity = "Medium "
    })
    $global:EventData.Add(6273, @{
        Description = "Network Policy Server denied access to a user."
        Category = "Logon/Logoff"
        Subcategory = "Network Policy Server"
        Monitoring = "Monitor for repeated access denials"
        Threats = "Unauthorized access attempts"
        FalsePositives = "Incorrect credentials"
        Severity = "Medium "
    })
    $global:EventData.Add(6276, @{
        Description = "Network Policy Server quarantined a user."
        Category = "Logon/Logoff"
        Subcategory = "Network Policy Server"
        Monitoring = "Monitor for quarantined user accounts"
        Threats = "Compromised accounts"
        FalsePositives = "Policy enforcement"
        Severity = "Medium"
    })
    $global:EventData.Add(6280, @{
        Description = "Network Policy Server unlocked the user account."
        Category = "Logon/Logoff"
        Subcategory = "Network Policy Server"
        Monitoring = "Monitor for unexpected account unlocks"
        Threats = "Policy circumvention"
        FalsePositives = "Administrative tasks"
        Severity = "Medium"
    })
    $global:EventData.Add(4649, @{
        Description = "A replay attack was detected."
        Category = "Logon/Logoff"
        Subcategory = "Other Logon/Logoff Events"
        Monitoring = "Monitor for repeated identical requests"
        Threats = "Credential reuse"
        FalsePositives = "Network misconfiguration"
        Severity = "High "
    })
    $global:EventData.Add(4776, @{
        Description = "The domain controller attempted to validate the credentials for an account."
        Category = "Account Logon"
        Subcategory = "Credential Validation"
        Monitoring = "Monitor for failed credential validations"
        Threats = "Brute force attacks"
        FalsePositives = "Normal user activity"
        Severity = "High "
    })
    $global:EventData.Add(4803, @{
        Description = "The screen saver was dismissed."
        Category = "AOther Logon/Logoff Events"
        Subcategory = "Screen Saver"
        Monitoring = "Monitor for unusual activity after screen saver dismissal"
        Threats = "Unauthorized access"
        FalsePositives = "Normal user activity"
        Severity = "High "
    })
    $global:EventData.Add(4768, @{
        Description = "A Kerberos authentication ticket (TGT) was requested."
        Category = "Account Logon"
        Subcategory = "Kerberos Authentication Service"
        Monitoring = "Monitor for unusual TGT requests"
        Threats = "Brute force attacks"
        FalsePositives = "Normal authentication operations"
        Severity = "High "
    })
    $global:EventData.Add(4769, @{
        Description = "A Kerberos service ticket was requested."
        Category = "Account Logon"
        Subcategory = "Kerberos Service Ticket Operations"
        Monitoring = "Monitor for unusual service ticket requests"
        Threats = "Lateral movement"
        FalsePositives = "Legitimate service access"
        Severity = "High "
    })
    $global:EventData.Add(4770, @{
        Description = "A Kerberos service ticket was renewed."
        Category = "Account Logon"
        Subcategory = "Kerberos Service Ticket Operations"
        Monitoring = "Monitor for repeated ticket renewals"
        Threats = "Session hijacking"
        FalsePositives = "Normal ticket renewal processes"
        Severity = "High "
    })
    $global:EventData.Add(4771, @{
        Description = "Kerberos pre-authentication failed."
        Category = "Account Logon"
        Subcategory = "Kerberos Authentication Service"
        Monitoring = "Monitor for frequent pre-authentication failures"
        Threats = "Brute force attacks"
        FalsePositives = "User error"
        Severity = "High "
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

    # Process Tracking Events
    $global:EventData.Add(4688, @{
        Description = "A new process has been created"
        Category = "Process Tracking"
        Subcategory = "Process Creation"
        Monitoring = "Monitor suspicious processes"
        Threats = "Malware execution, Living off the land"
        FalsePositives = "Normal process creation"
        Severity = "High"
    })
    $global:EventData.Add(4689, @{
        Description = "A process has exited"
        Category = "Process Tracking"
        Subcategory = "Process Termination"
        Monitoring = "Compare with 4688 events"
        Threats = "Crash analysis, Process termination"
        FalsePositives = "Normal process exits"
        Severity = "Low"
    })
    $global:EventData.Add(4692, @{
        Description = "Backup of data protection master key was attempted"
        Category = "Process Tracking"
        Subcategory = "DPAPI Activity"
        Monitoring = "Alert on all attempts"
        Threats = "Key theft, Unauthorized backup"
        FalsePositives = "Authorized key backup"
        Severity = "High"
    })
    $global:EventData.Add(4693, @{
        Description = "Recovery of data protection master key was attempted"
        Category = "Process Tracking"
        Subcategory = "DPAPI Activity"
        Monitoring = "Alert on all attempts"
        Threats = "Key compromise, Unauthorized recovery"
        FalsePositives = "Authorized key recovery"
        Severity = "High"
    })
    $global:EventData.Add(4695, @{
        Description = "Unprotection of auditable protected data was attempted"
        Category = "Process Tracking"
        Subcategory = "DPAPI Activity"
        Monitoring = "Alert on all attempts"
        Threats = "Data exposure, Protection removal"
        FalsePositives = "Authorized data access"
        Severity = "Medium"
    })
    $global:EventData.Add(4816, @{
        Description = "RPC detected an integrity violation while decrypting an incoming message."
        Category = "Process Tracking"
        Subcategory = "RPC Events"
        Monitoring = "Monitor for RPC integrity violations"
        Threats = "Protocol tampering"
        FalsePositives = "Network issues"
        Severity = "Medium"
    })
    $global:EventData.Add(6416, @{
        Description = "A new external device was recognized by the system."
        Category = "Process Tracking"
        Subcategory = "Plug and Play"
        Monitoring = "Monitor for unauthorized devices"
        Threats = "Unauthorized data transfer"
        FalsePositives = "NPlanned device usage"
        Severity = "Medium"
    })
    $global:EventData.Add(6419, @{
        Description = "A request was made to disable a device."
        Category = "Process Tracking"
        Subcategory = "Plug and Play"
        Monitoring = "Monitor for unexpected device disable requests"
        Threats = "Device tampering"
        FalsePositives = "Administrative tasks"
        Severity = "Medium"
    })
    $global:EventData.Add(6420, @{
        Description = "A device was disabled."
        Category = "Process Tracking"
        Subcategory = "Plug and Play"
        Monitoring = "Monitor for unexpected device disable actions"
        Threats = "Device tampering"
        FalsePositives = "Administrative tasks"
        Severity = "Medium"
    })
    $global:EventData.Add(6421, @{
        Description = "A request was made to enable a device."
        Category = "Process Tracking"
        Subcategory = "Plug and Play"
        Monitoring = "Monitor for unexpected device enable requests"
        Threats = "Device tampering"
        FalsePositives = "Administrative tasks"
        Severity = "Medium"
    })
    $global:EventData.Add(6422, @{
        Description = "A device was enabled."
        Category = "Process Tracking"
        Subcategory = "Plug and Play"
        Monitoring = "Monitor for unexpected device enable actions"
        Threats = "Device tampering"
        FalsePositives = "Administrative tasks"
        Severity = "Medium"
    })
    $global:EventData.Add(6423, @{
        Description = "The installation of this device is forbidden by system policy."
        Category = "Process Tracking"
        Subcategory = "Plug and Play"
        Monitoring = "Monitor for device installation policy violations"
        Threats = "Unauthorized device installation"
        FalsePositives = "Policy enforcement"
        Severity = "High"
    })
    $global:EventData.Add(6424, @{
        Description = "The installation of this device was allowed after having previously been forbidden by policy."
        Category = "Process Tracking"
        Subcategory = "Plug and Play"
        Monitoring = "Monitor for device installation policy changes"
        Threats = "Unauthorized device installation"
        FalsePositives = "Policy updates"
        Severity = "High"
    })

    # Directory_Services Events
    $global:EventData.Add(5136, @{
        Description = "A directory service object was modified."
        Category = "Directory Services"
        Subcategory = "Directory Service Changes"
        Monitoring = "Monitor for unauthorized directory modifications"
        Threats = "Data tampering"
        FalsePositives = "Administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(5137, @{
        Description = "A directory service object was created."
        Category = "Directory Services"
        Subcategory = "Directory Service Changes"
        Monitoring = "Monitor for unauthorized directory creations"
        Threats = "Unauthorized accounts"
        FalsePositives = "Administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(5138, @{
        Description = "A directory service object was undeleted."
        Category = "Directory Services"
        Subcategory = "Directory Service Changes"
        Monitoring = "Monitor for unexpected directory undeletions"
        Threats = "Data tampering"
        FalsePositives = "Planned updates"
        Severity = "High"
    })
    $global:EventData.Add(5139, @{
        Description = "A directory service object was moved."
        Category = "Directory Services"
        Subcategory = "Directory Service Changes"
        Monitoring = "Monitor for unexpected directory undeletions"
        Threats = "Data tampering"
        FalsePositives = "Administrative tasks"
        Severity = "High"
    })
    # Account Management Events
    $global:EventData.Add(4720, @{
        Description = "A user account was created."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for unauthorized account creation"
        Threats = "Privilege escalation, Backdoor accounts"
        FalsePositives = "Normal administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(4722, @{
        Description = "A user account was enabled."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for re-enabling of disabled accounts"
        Threats = "Privilege escalation"
        FalsePositives = "Administrative activity"
        Severity = "High"
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
        Severity = "High"
    })
    $global:EventData.Add(4731, @{
        Description = "A security-enabled local group was created."
        Category = "Account Management"
        Subcategory = "Security Group Management"
        Monitoring = "Monitor for unauthorized group creation"
        Threats = "Privilege escalation"
        FalsePositives = "Normal administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(4732, @{
        Description = "A member was added to a security-enabled local group."
        Category = "Account Management"
        Subcategory = "Security Group Management"
        Monitoring = "Monitor for unauthorized group membership additions"
        Threats = "Privilege escalation"
        FalsePositives = "Normal administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(4733, @{
        Description = "A member was removed from a security-enabled local group."
        Category = "Account Management"
        Subcategory = "Security Group Management"
        Monitoring = "Monitor for unauthorized group membership removals"
        Threats = "Privilege abuse"
        FalsePositives = "Normal administrative tasks"
        Severity = "Medium"
    })
    $global:EventData.Add(4734, @{
        Description = "A security-enabled local group was deleted."
        Category = "Account Management"
        Subcategory = "Security Group Management"
        Monitoring = "Monitor for unauthorized group deletions"
        Threats = "Privilege abuse"
        FalsePositives = "Normal administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(4735, @{
        Description = "A security-enabled local group was changed."
        Category = "Account Management"
        Subcategory = "Security Group Management"
        Monitoring = "Monitor for unexpected group modifications"
        Threats = "Privilege escalation"
        FalsePositives = "Normal administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(4738, @{
        Description = "A user account was changed."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for unexpected account changes"
        Threats = "Account takeover"
        FalsePositives = "Normal administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(4739, @{
        Description = "Domain Policy was changed."
        Category = "Account Management"
        Subcategory = "Other Account Management Events"
        Monitoring = "Monitor for unauthorized domain policy changes"
        Threats = "Policy tampering"
        FalsePositives = "Planned updates"
        Severity = "Critical"
    })
    $global:EventData.Add(4740, @{
        Description = "A user account was locked out."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for frequent lockouts"
        Threats = "Brute force attacks"
        FalsePositives = "User error"
        Severity = "Medium"
    })
    $global:EventData.Add(4767, @{
        Description = "A user account was unlocked."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for unexpected account unlocks"
        Threats = "Privilege abuse"
        FalsePositives = "Administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(4780, @{
        Description = "The ACL was set on accounts which are members of administrators groups."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for unauthorized ACL changes"
        Threats = "Privilege escalation"
        FalsePositives = "Administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(4781, @{
        Description = "The name of an account was changed."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for unexpected account name changes"
        Threats = "Account impersonation"
        FalsePositives = "Administrative tasks"
        Severity = "Medium"
    })
    $global:EventData.Add(4782, @{
        Description = "The password hash of an account was accessed."
        Category = "Account Management"
        Subcategory = "Other Account Management Events"
        Monitoring = "Monitor for unauthorized password hash access"
        Threats = "Credential theft"
        FalsePositives = "Administrative tasks"
        Severity = "Critical"
    })
    $global:EventData.Add(4793, @{
        Description = "The Password Policy Checking API was called."
        Category = "Account Management"
        Subcategory = "Other Account Management Events"
        Monitoring = "Monitor for frequent password policy API calls"
        Threats = "Policy tampering"
        FalsePositives = "Planned operations"
        Severity = "Medium"
    })
    $global:EventData.Add(4798, @{
        Description = "A user's local group membership was enumerated."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for frequent group membership enumerations"
        Threats = "Reconnaissance"
        FalsePositives = "Normal administrative tasks"
        Severity = "Medium"
    })
    $global:EventData.Add(5376, @{
        Description = "Credential Manager credentials were backed up."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for unexpected credential backups"
        Threats = "Credential theft"
        FalsePositives = "Planned maintenance"
        Severity = "High"
    })
    $global:EventData.Add(5377, @{
        Description = "Credential Manager credentials were restored from a backup."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for unexpected credential restores"
        Threats = "Credential tampering"
        FalsePositives = "Planned maintenance"
        Severity = "High"
    })
    $global:EventData.Add(4727, @{
        Description = "A security-enabled global group was created."
        Category = "Account Management"
        Subcategory = "Security Group Management"
        Monitoring = "Monitor for unauthorized group creation"
        Threats = "Privilege escalation"
        FalsePositives = "Administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(4728, @{
        Description = "A member was added to a security-enabled global group."
        Category = "Account Management"
        Subcategory = "Security Group Management"
        Monitoring = "Monitor for unauthorized group member additions"
        Threats = "Privilege escalation"
        FalsePositives = "Planned changes"
        Severity = "High"
    })
    $global:EventData.Add(4729, @{
        Description = "A member was removed from a security-enabled global group."
        Category = "Account Management"
        Subcategory = "Security Group Management"
        Monitoring = "Monitor for unauthorized group member removals"
        Threats = "Privilege abuse"
        FalsePositives = "Planned changes"
        Severity = "Medium"
    })
    $global:EventData.Add(4730, @{
        Description = "A security-enabled global group was deleted."
        Category = "Account Management"
        Subcategory = "Security Group Management"
        Monitoring = "Monitor for unauthorized group deletions"
        Threats = "Privilege abuse"
        FalsePositives = "Planned changes"
        Severity = "Medium"
    })
    $global:EventData.Add(4737, @{
        Description = "A security-enabled global group was changed."
        Category = "Account Management"
        Subcategory = "Security Group Management"
        Monitoring = "Monitor for unexpected group modifications"
        Threats = "Privilege escalation"
        FalsePositives = "Planned changes"
        Severity = "High"
    })
    $global:EventData.Add(4741, @{
        Description = "A computer account was created."
        Category = "Account Management"
        Subcategory = "Computer Account Management"
        Monitoring = "Monitor for unauthorized computer account creation"
        Threats = "Backdoor accounts"
        FalsePositives = "Planned changes"
        Severity = "High"
    })
    $global:EventData.Add(4742, @{
        Description = "A computer account was changed."
        Category = "Account Management"
        Subcategory = "Computer Account Management"
        Monitoring = "Monitor for unauthorized computer account changes"
        Threats = "Privilege escalation"
        FalsePositives = "Planned updates"
        Severity = "Medium"
    })
    $global:EventData.Add(4743, @{
        Description = "A computer account was deleted."
        Category = "Account Management"
        Subcategory = "Computer Account Management"
        Monitoring = "Monitor for unauthorized computer account deletions"
        Threats = "Backdoor removal"
        FalsePositives = "Planned updates"
        Severity = "Medium"
    })
    $global:EventData.Add(4754, @{
        Description = "A security-enabled universal group was created."
        Category = "Account Management"
        Subcategory = "Security Group Management"
        Monitoring = "Monitor for unauthorized universal group creation"
        Threats = "Privilege escalation"
        FalsePositives = "Administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(4755, @{
        Description = "A security-enabled universal group was changed."
        Category = "Account Management"
        Subcategory = "Security Group Management"
        Monitoring = "Monitor for unauthorized universal group changes"
        Threats = "Privilege escalation"
        FalsePositives = "Administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(4756, @{
        Description = "A member was added to a security-enabled universal group."
        Category = "Account Management"
        Subcategory = "Security Group Management"
        Monitoring = "Monitor for unauthorized additions to universal groups"
        Threats = "Privilege escalation"
        FalsePositives = "Administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(4757, @{
        Description = "A member was removed from a security-enabled universal group."
        Category = "Account Management"
        Subcategory = "Security Group Management"
        Monitoring = "Monitor for unauthorized removals from universal groups"
        Threats = "Privilege abuse"
        FalsePositives = "Administrative tasks"
        Severity = "Medium"
    })
    $global:EventData.Add(4764, @{
        Description = "A group’s type was changed."
        Category = "Account Management"
        Subcategory = "Security Group Management"
        Monitoring = "Monitor for unexpected group type changes"
        Threats = "Privilege escalation"
        FalsePositives = "Administrative tasks"
        Severity = "Medium"
    })
    $global:EventData.Add(4765, @{
        Description = "SID History was added to an account."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for unauthorized SID History additions"
        Threats = "Account tampering"
        FalsePositives = "Planned updates"
        Severity = "High"
    })
    $global:EventData.Add(4766, @{
        Description = "An attempt to add SID History to an account failed."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for failed attempts to add SID History"
        Threats = "Privilege escalation attempts"
        FalsePositives = "Misconfiguration"
        Severity = "Medium"
    })
    $global:EventData.Add(4794, @{
        Description = "An attempt was made to set the Directory Services Restore Mode administrator password."
        Category = "Account Management"
        Subcategory = "User Account Management"
        Monitoring = "Monitor for unauthorized password resets"
        Threats = "Account compromise"
        FalsePositives = "Planned updates"
        Severity = "High"
    })
    $global:EventData.Add(4799, @{
        Description = "A security-enabled local group membership was enumerated."
        Category = "Account Management"
        Subcategory = "Security Group Management"
        Monitoring = "Monitor for frequent group membership enumerations"
        Threats = "Reconnaissance"
        FalsePositives = "Administrative tasks"
        Severity = "Medium"
    })
    # Policy Change Events
    $global:EventData.Add(4703, @{
        Description = "A user right was adjusted."
        Category = "Policy Change"
        Subcategory = "Authorization Policy Change"
        Monitoring = "Monitor for suspicious privilege changes"
        Threats = "Privilege escalation"
        FalsePositives = "Normal administrative activity"
        Severity = "Medium"
    })
    $global:EventData.Add(4704, @{
        Description = "A user right was assigned."
        Category = "Policy Change"
        Subcategory = "Audit Policy Change"
        Monitoring = "Monitor for unusual privilege assignments"
        Threats = "Privilege escalation"
        FalsePositives = "Administrative activity"
        Severity = "Medium"
    })
    $global:EventData.Add(4715, @{
        Description = "The audit policy (SACL) on an object was changed."
        Category = "Policy Change"
        Subcategory = "Modification"
        Monitoring = "Monitor for unauthorized audit policy changes"
        Threats = "Audit log tampering"
        FalsePositives = "Policy updates"
        Severity = "High"
    })
    $global:EventData.Add(4717, @{
        Description = "System security access was granted to an account."
        Category = "Policy Change"
        Subcategory = "Authentication Policy Change"
        Monitoring = "Monitor for unauthorized access grants"
        Threats = "Privilege escalation"
        FalsePositives = "Administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(4718, @{
        Description = "System security access was removed from an account."
        Category = "Policy Change"
        Subcategory = "Authentication Policy Change"
        Monitoring = "Monitor for unauthorized access removal"
        Threats = "Privilege abuse"
        FalsePositives = "Administrative tasks"
        Severity = "Medium"
    })
    $global:EventData.Add(4719, @{
        Description = "System audit policy was changed."
        Category = "Policy Change"
        Subcategory = "Audit Policy Change"
        Monitoring = "Monitor for unauthorized audit policy changes"
        Threats = "Audit log tampering"
        FalsePositives = "Policy updates"
        Severity = "High"
    })
    $global:EventData.Add(4817, @{
        Description = "Auditing settings on object were changed."
        Category = "Policy Change"
        Subcategory = "Audit Policy Change"
        Monitoring = "Monitor for unauthorized auditing changes"
        Threats = "Policy tampering"
        FalsePositives = "Planned updates"
        Severity = "High"
    })
    $global:EventData.Add(4906, @{
        Description = "The CrashOnAuditFail value has changed."
        Category = "Policy Change"
        Subcategory = "Audit Policy Change"
        Monitoring = "Monitor for changes to the CrashOnAuditFail setting"
        Threats = "Audit bypass"
        FalsePositives = "Planned updates"
        Severity = "High"
    })
    $global:EventData.Add(4907, @{
        Description = "Auditing settings on object changed."
        Category = "Policy Change"
        Subcategory = "Audit Policy Change"
        Monitoring = "Monitor for unauthorized auditing changes"
        Threats = "Policy tampering"
        FalsePositives = "Planned updates"
        Severity = "High"
    })
    $global:EventData.Add(4908, @{
        Description = "Special Groups Logon table modified."
        Category = "Policy Change"
        Subcategory = "Audit Policy Change"
        Monitoring = "Monitor for changes to Special Groups Logon"
        Threats = "Privilege escalation"
        FalsePositives = "Administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(4912, @{
        Description = "Per-User Audit Policy changed."
        Category = "Policy Change"
        Subcategory = "Audit Policy Change"
        Monitoring = "Monitor for unusual per-user policy applications"
        Threats = "Policy tampering"
        FalsePositives = "Planned operations"
        Severity = "Medium"
    })
    $global:EventData.Add(6145, @{
        Description = "One or more errors occurred while processing security policy in the group policy objects."
        Category = "Policy Change"
        Subcategory = "Other Policy Change Events"
        Monitoring = "Monitor for GPO processing errors"
        Threats = "Policy corruption"
        FalsePositives = "Network issues"
        Severity = "Medium"
    })
    $global:EventData.Add(4706, @{
        Description = "A new trust was created to a domain."
        Category = "Policy Change"
        Subcategory = "Authentication Policy Change"
        Monitoring = "Monitor for unauthorized trust creation"
        Threats = "Domain compromise"
        FalsePositives = "Planned domain updates"
        Severity = "High"
    })
    $global:EventData.Add(4707, @{
        Description = "A trust to a domain was removed."
        Category = "Policy Change"
        Subcategory = "Authentication Policy Change"
        Monitoring = "Monitor for unauthorized trust removal"
        Threats = "Domain isolation"
        FalsePositives = "Planned domain updates"
        Severity = "High"
    })
    $global:EventData.Add(4713, @{
        Description = "Kerberos policy was changed."
        Category = "Policy Change"
        Subcategory = "Authentication Policy Change"
        Monitoring = "Monitor for unexpected Kerberos policy changes"
        Threats = "Authentication bypass"
        FalsePositives = "Planned updates"
        Severity = "High"
    })
    $global:EventData.Add(4716, @{
        Description = "Trusted domain information was modified."
        Category = "Policy Change"
        Subcategory = "Authentication Policy Change"
        Monitoring = "Monitor for unexpected changes to trusted domain information"
        Threats = "Domain tampering"
        FalsePositives = "Administrative tasks"
        Severity = "High"
    })
    $global:EventData.Add(4865, @{
        Description = "A trusted forest information entry was added."
        Category = "Policy Change"
        Subcategory = "Authentication Policy Change"
        Monitoring = "Monitor for unexpected forest additions"
        Threats = "Privilege escalation"
        FalsePositives = "Planned updates"
        Severity = "High"
    })
    $global:EventData.Add(4866, @{
        Description = "A trusted forest information entry was removed."
        Category = "Policy Change"
        Subcategory = "Authentication Policy Change"
        Monitoring = "Monitor for unauthorized forest entry removals"
        Threats = "Domain isolation"
        FalsePositives = "Planned updates"
        Severity = "High"
    })
    $global:EventData.Add(4867, @{
        Description = "A trusted forest information entry was added."
        Category = "Policy Change"
        Subcategory = "Authentication Policy Change"
        Monitoring = "Monitor for unexpected forest additions"
        Threats = "Privilege escalation"
        FalsePositives = "Planned updates"
        Severity = "High"
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
