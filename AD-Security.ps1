<#

  THIS SCRIPT IS NOT READY FOR PRODUCTION, IT IS STILL BEING TESTED AND DEVELOPED. RUN AT YOUR OWN RISK

  Changes made to the domain controllers:
  Stops and DISABLES the Print Spooler service on all domain controllers
  Enables AD Recycle Bin (If not already enabled)
  Removes all members from Schema Admins and Enterprise Admins
  Prevents all domain admins from being delegated in the domain
  Enables PowerShell logging on all domain controllers
  Changes primary group for all users to "Domain Users"
  Disables NTLMV1 and only allows NTLMV2 by registry and tells you where to make changes in your group policy
  Protects all Orginizational Units from accidential deletion

  Recommendations:
  Which advanced audit policies is missing and where you change them
  How many users have a password that never expires, and makes a list of all the accounts
  Recommendations to Domain Admins and Administrators
  Checking your password policy and gives CIS18 recommendations
  Checking how many users was recently locked in Active Directory caused by bad passwords
  

#>
# Standard Variables: 
$LogPath = "$Home\Desktop\ADAssesment"
$LogFile = "$Home\Desktop\ADAssesment\1-Logfile.txt"
If ($LogPath)
{
Remove-Item $Logpath -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
}
MKDIR $LogPath -ErrorAction SilentlyContinue | Out-Null

# Stop and disable Print Spooler on all domain controllers
$DomainName = (Get-ADDomain).DNSRoot
$DC = Get-ADDomainController -filter * | Select Hostname
Foreach ($D in $DC)
{
Invoke-Command $D.HostName {
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
}
    }
Echo "INFORMATION: Print spoolers stopped and disabled" | Out-File $LogFile -Append

# Enable AD Recycle Bin if not already present
If (-Not (Get-ADOptionalFeature -Filter {Name -like "Recycle*"}).EnabledScopes)
{
$BinDestination = Get-ADOptionalFeature "Recycle Bin Feature" | Select DistinguishedName
Enable-ADOptionalFeature $BinDestination.DistinguishedName -Scope ForestOrConfigurationSet -Target $DomainName -Confirm:$false -ErrorAction SilentlyContinue
Echo "INFORMATION: AD Recycle bin enabled" | Out-File $LogFile -Append
}

# Empty the Schema Admins and Enterprise Admins
$Schema = Get-ADGroupMember -Identity "Schema Admins" | Get-ADUser -Properties SamAccountName -ErrorAction SilentlyContinue
Foreach ($S in $Schema)
{
Remove-ADGroupMember -Identity "Schema Admins" -Members $S.SamaccountName -Confirm:$false -ErrorAction SilentlyContinue
}
$Enterprise = Get-ADGroupMember -Identity "Enterprise Admins" | Get-ADUser -Properties SamAccountName
Foreach ($E in $Enterprise)
{
Remove-ADGroupMember -Identity "Enterprise Admins" -Members $E.SamaccountName -Confirm:$false -ErrorAction SilentlyContinue
}
Echo "INFORMATION: Removed all members in Schema Admins and Enterprise Admins" | Out-File $LogFile -Append

# Prevent administrator accounts from being delegated
Get-ADGroupMember "Domain Admins" | Get-ADuser -Properties AccountNotDelegated -ErrorAction SilentlyContinue  | Where-Object {-not $_.AccountNotDelegated -and $_.ObjectClass -EQ "User"} | Set-ADUser -AccountNotDelegated $True -ErrorAction SilentlyContinue
Echo "INFORMATION: All members of Domain Admins set to not allow delegation" | Out-File $LogFile -Append

# Protect Orginizational Units from accidental deletion
Get-ADOrganizationalUnit -filter {Name -like "*"} -Properties ProtectedFromAccidentalDeletion | Where {$_.ProtectedFromAccidentalDeletion -eq $false} | Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $true -ErrorAction SilentlyContinue
Echo "INFORMATION: Set all OU's to be protected from accidential deletion" | Out-File $LogFile -Append

# Enable Powershell Audit logging
Foreach ($D in $DC)
{
Invoke-Command $D.HostName {
New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
}
    }
Echo "INFORMATION: Enabled Powershell audit logging" | Out-File $LogFile -Append

# Set Primary Group to 'Domain Users' for anyone but the 'Guest' account
$PrimaryGroup = Get-ADUser -Filter * -Properties SamAccountName, PrimaryGroup | Where-Object {$_.PrimaryGroup -ne (Get-ADGroup -Identity "Domain Users").DistinguishedName -and $_.SamAccountName -NE "Guest"}
Foreach ($Primary in $PrimaryGroup)
{
Set-ADUser $Primary.SamAccountName -Replace @{PrimaryGroupID='513'} -ErrorAction SilentlyContinue
}
Echo "INFORMATION: Changed primary group of all users to 'Domain Users'" | Out-File $LogFile -Append

# Disable NTLMV1 and only allow NTLMV2
Echo "REMINDER: Change the Default Domain Controllers Policy with the below settings to disable NTLMV1 and only allow NTLMV2:" | Out-File $LogFile -Append
Echo "Computer Configuration -> Windows Settings ->  Security Settings -> Local Policies -> Security Options -> Network security: LAN Manager authentication level -> Send NTLMv2 response only\refuse LM & NTLM" | Out-File $LogFile -Append

# Export a list of all AD-users that have a password that never expires
Get-ADUser -Filter * -Properties DisplayName, SamAccountName, LastLogonDate, PasswordLastSet | Select DisplayName, SamAccountName, LastLogonDate, PasswordLastSet |
Export-csv $LogPath\PasswordNeverExpire.csv -NoTypeInformation -Encoding Unicode

# Recommendations based on membership of the groups Domain Admins and Administrators
Echo "# Domain Admins & Administrators groups #" | Out-File $Logpath\Recommendations.txt
$DA = (Get-ADGroupMember "Domain admins").count
If ($DA -GT 5)
{
Echo "$DA members found in domain admins, should be kept to a minimum of 5 members" | Out-File $Logpath\Recommendations.txt -Append
}
$DAExpire = ((Get-ADGroupMember "Domain Admins" | Get-ADUser -Properties SamAccountName, PasswordNeverExpires -ErrorAction SilentlyContinue | Where {$_.PasswordNeverExpires -EQ $true}).SamAccountName).count
If ($DAExpire -GT 1)
{
Echo "$DAExpire members of Domain Admins have a password that never expire" | Out-File $Logpath\Recommendations.txt -Append
}
$GroupsinDA = ((Get-ADGroupMember "Domain Admins" | Get-ADObject | Where {$_.ObjectClass -EQ "Group"}).ObjectClass).Count
If ($GroupsinDA -GE 1)
{
Echo "$GroupsinDA groups is direct members of domain admins. Only user-objects should be a member of this group" | Out-File $LogPath\Recommendations.txt -Append
}

$DAdmin = (Get-ADGroupMember "Administrators").count
If ($DAdmin -GT 3)
{
Echo "$DAdmin members found in the group Administrators. Only 'Administrator, Enterprise Admins and Domain Admins' should be members of this group" | Out-File $Logpath\Recommendations.txt -Append
}

# Default Domain Password Policy recommendations following CIS18 standard
Echo "

# Password Policy #" | Out-File $Logpath\Recommendations.txt -Append
$DomainPWD = Get-ADDefaultDomainPasswordPolicy
If ($DomainPWD) {
}
If ($DomainPWD.MinPasswordLength -lt 14) {
Echo "Minimum password length is below 14 characters, we recommend using atleast 14 characters in passwords and a maximum password age set to 365 days" | Out-File $LogPath\Recommendations.txt -Append
}
If ($DomainPWD.LockoutThreshold -lt 5)
{
Echo "LockOut ThreshHold is less than the CIS18 recommendation. This allows brute-force attacks to be more efficient. To follow CIS18 standards we recommend setting it to 5." | Out-File $LogPath\Recommendations.txt -Append
}
If ($DomainPWD.LockoutDuration -lt "00:15:00") {
Echo "Lockout Duration is less than the CIS18 recommendation. This allows brute-force attacks to be more efficient, To follow CIS18 standards we recommend setting it to 15" | Out-File $LogPath\Recommendations.txt -Append
}
if ($DomainPWD.ComplexityEnabled -eq $false) {
Echo "Password complexity is not enabled - To add complexity to passwords, we advise you to enable this simple setting." | Out-File $LogPath\Recommendations.txt -Append
}
If ($DomainPWD.PasswordHistoryCount -LT 10) {
Echo "Password History is less than 10. By having a password history lower than 10, users will at somepoint be able to re-use their old passwords. To prevent this, we recommend setting it to atleast 20." | Out-File $LogPath\Recommendations.txt -Append
}

# Recommendation on users with a password that never expires
$PasswordNeverExpires = ((Get-ADUser -Filter * -Properties PasswordNeverExpires | Where {$_.PasswordNeverExpires -EQ $true}).PasswordNeverExpires).Count
Echo "

# Users with a password that never expires #
Found $PasswordNeverExpires users with a password that never expires. A csv-file was created containing all of the users. 
Users with a password that never changes can pose a risk to the domain. If breached, they grant long-time access to the domain" | Out-File $Logpath\Recommendations.txt -Append

Get-ADUser -Filter * -Properties DisplayName, SamAccountName, LastLogonDate, PasswordLastSet, PasswordNeverExpires | Where {$_.PasswordNeverExpires -EQ $true} | Select DisplayName, SamAccountName, LastLogonDate, PasswordLastSet |
Export-csv $LogPath\PasswordNeverExpire.csv -NoTypeInformation -Encoding Unicode

# Users locked in Active Directory caused by a bad password
Echo "

# Users locked in Active Directory because of a bad password #" | Out-File $LogPath\Recommendations.txt -Append
$LockedCount = (Get-WinEvent -ComputerName $env:COMPUTERNAME -FilterHashTable @{LogName='Security'; ID=4740} -ErrorAction SilentlyContinue).count
If ($LockedCount -GE 1)
{
Echo "Security logs indicate that one or more accounts was recently locked $LockedCount times because of a bad password." | Out-File $LogPath\Recommendations.txt -Append
}
Else
{
Echo "No accounts was recently locked in Active Directory" | Out-File $LogPath\Recommendations.txt -Append
}

# Recommendations based on settings found in Advanced Audit Policies
Echo "

# Audit Policy settings #
Default Domain Controllers Policy - Computer Configuration -> Security Settings -> Advanced Audit Policy Configuration" | Out-File $Logpath\Recommendations.txt -Append
$EventLog = Get-EventLog -List
Foreach ($E in $EventLog)
{
If ($E.Log -eq "Security" -and $E.MaximumKiloBytes -LT "4194240")
{
Echo "
The eventlog 'Security' is not set to 4GB (Maximum size)" | Out-File $LogPath\Recommendations.txt -Append
}
    }

$AuditPolicySettings = auditpol /get /category:* /r | ConvertFrom-Csv | Select Subcategory, 'Inclusion Setting'
Foreach ($Audit in $AuditPolicySettings)
{
If ($Audit.SubCategory -like "Security System Extension" -and $Audit.'Inclusion Setting' -EQ "No Auditing")
{
Echo "
Target: System
Subcategory: Audit Security System Extention
Setting: Success/Failure" | Out-File $LogPath\Recommendations.txt -Append
}


If (-Not $Audit.SubCategory -EQ "Logon" -and $Audit.'Inclusion Setting' -EQ "No Auditing")
{
Echo "
Target: Logon/Logoff
Subcategory: Audit Logon
Setting: Success/Failure" | Out-File $LogPath\Recommendations.txt -Append
}

If ($Audit.SubCategory -EQ "Logoff" -and $Audit.'Inclusion Setting' -EQ "No Auditing")
{
Echo "
Target: Logon/Logoff
Subcategory: Audit Logoff
Setting: Success/Failure" | Out-File $LogPath\Recommendations.txt -Append
}

If ($Audit.SubCategory -EQ "Special Logon" -and $Audit.'Inclusion Setting' -EQ "No Auditing")
{
Echo "
Target: Logon/Logoff
Subcategory: Audit Special Logon
Setting: Success/Failure" | Out-File $LogPath\Recommendations.txt -Append
}

If ($Audit.SubCategory -EQ "Sensitive Privilege Use" -and $Audit.'Inclusion Setting' -EQ "No Auditing")
{
Echo "
Target: Privilege Use
Subcategory: Audit Sensitive Privilege Use
Setting: Success/Failure" | Out-File $LogPath\Recommendations.txt -Append
}

If ($Audit.SubCategory -EQ "Process Creation" -and $Audit.'Inclusion Setting' -EQ "No Auditing")
{
Echo "
Target: Detailed Tracking
Subcategory: Audit Process Creation
Setting: Success/Failure" | Out-File $LogPath\Recommendations.txt -Append
}

If ($Audit.SubCategory -EQ "DPAPI Activity" -and $Audit.'Inclusion Setting' -EQ "No Auditing")
{
Echo "
Target: Detailed Tracking
Subcategory: Audit DPAPI Activity
Setting: Success/Failure" | Out-File $LogPath\Recommendations.txt -Append
}

If ($Audit.SubCategory -EQ "Authentication Policy Change" -and $Audit.'Inclusion Setting' -EQ "No Auditing")
{
Echo "
Target: Policy Change
Subcategory: Audit Authentication Policy Change
Setting: Success/Failure" | Out-File $LogPath\Recommendations.txt -Append
}

If ($Audit.SubCategory -EQ "Computer Account Management" -and $Audit.'Inclusion Setting' -EQ "No Auditing")
{
Echo "
Target: Account Management
Subcategory: Audit Computer Account Management
Setting: Success/Failure" | Out-File $LogPath\Recommendations.txt -Append
}

If ($Audit.SubCategory -EQ "Security Group Management" -and $Audit.'Inclusion Setting' -EQ "No Auditing")
{
Echo "
Target: Account Management
Subcategory: Audit Security Group Management
Setting: Success/Failure" | Out-File $LogPath\Recommendations.txt -Append
}

If ($Audit.SubCategory -EQ "User Account Management" -and $Audit.'Inclusion Setting' -EQ "No Auditing")
{
Echo "
Target: Account Management
Subcategory: Audit User Account Management
Setting: Success/Failure" | Out-File $LogPath\Recommendations.txt -Append
}

If ($Audit.SubCategory -EQ "Kerberos Service Ticket Operations" -and $Audit.'Inclusion Setting' -EQ "No Auditing")
{
Echo "
Target: Account Logon
Subcategory: Audit Kerberos Service Ticket Operations
Setting: Success/Failure" | Out-File $LogPath\Recommendations.txt -Append
}

If ($Audit.SubCategory -EQ "Kerberos Authentication Service" -and $Audit.'Inclusion Setting' -EQ "No Auditing")
{
Echo "
Target: Account Logon
Subcategory: Audit Kerberos Authentication Service
Setting: Success/Failure" | Out-File $LogPath\Recommendations.txt -Append
}
    }

Write-Host "Files gathered by the script can be found here: $Logpath" -ForegroundColor Green
