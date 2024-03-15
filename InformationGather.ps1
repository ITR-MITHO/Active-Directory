<#

  THIS SCRIPT IS NOT READY FOR PRODUCTION, IT IS STILL BEING TESTED AND DEVELOPED. RUN AT YOUR OWN RISK

  Recommendations:
  Which advanced audit policies is missing and where you change them
  How many users have a password that never expires, and makes a list of all the accounts
  Recommendations to Domain Admins and Administrators
  Checking your password policy and gives CIS18 recommendations
  Checking how many users was recently locked in Active Directory caused by bad passwords
  
#>

# Standard Variables: 
$LogPath = "$Home\Desktop\ADAssesment"
If ($LogPath)
{
Remove-Item $Logpath -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
}
MKDIR $LogPath -ErrorAction SilentlyContinue | Out-Null

# Export a list of all AD-users that have a password that never expires
Get-ADUser -Filter * -Properties DisplayName, SamAccountName, LastLogonDate, PasswordLastSet | Select DisplayName, SamAccountName, LastLogonDate, PasswordLastSet |
Export-csv $LogPath\PasswordNeverExpire.csv -NoTypeInformation -Encoding Unicode

# Recommendations based on membership of the groups Domain Admins and Administrators
Echo "# Domain Admins & Administrators groups #" | Out-File $Logpath\Recommendations.txt
$DA = (Get-ADGroupMember "Domain admins").count
If ($DA -GT 5)
{

Echo "
Rule ID: itm8-DAMembers
Priority: 3
$DA members found in domain admins, should be kept to a minimum of 5 members" | Out-File $Logpath\Recommendations.txt -Append
}
$DAExpire = ((Get-ADGroupMember "Domain Admins" | Get-ADUser -Properties SamAccountName, PasswordNeverExpires -ErrorAction SilentlyContinue | Where {$_.PasswordNeverExpires -EQ $true}).SamAccountName).count
If ($DAExpire -GT 1)
{
Echo "$DAExpire members of Domain Admins have a password that never expire" | Out-File $Logpath\Recommendations.txt -Append
}
$GroupsinDA = ((Get-ADGroupMember "Domain Admins" | Get-ADObject | Where {$_.ObjectClass -EQ "Group"}).ObjectClass).Count
If ($GroupsinDA -GE 1)
{
Echo "
Rule ID: itm8-DAGroupMembers
Priority: 3
$GroupsinDA groups is direct members of domain admins. Only user-objects should be a member of this group" | Out-File $LogPath\Recommendations.txt -Append
}

$DAdmin = (Get-ADGroupMember "Administrators").count
If ($DAdmin -GT 3)
{
Echo "
Rule ID: itm8-AdministratorMembers
Priority: 3
$DAdmin members found in the group Administrators. Only 'Administrator, Enterprise Admins and Domain Admins' should be members of this group" | Out-File $Logpath\Recommendations.txt -Append
}

# Default Domain Password Policy recommendations following CIS18 standard
Echo "

# Password Policy #" | Out-File $Logpath\Recommendations.txt -Append
$DomainPWD = Get-ADDefaultDomainPasswordPolicy
If ($DomainPWD) {
}
If ($DomainPWD.MinPasswordLength -lt 14) {
Echo "
Rule ID: itm8-PWDMinLength
Priority: 3
Minimum password length is below 14 characters, we recommend using atleast 14 characters in passwords and a maximum password age set to 365 days" | Out-File $LogPath\Recommendations.txt -Append
}
If ($DomainPWD.LockoutThreshold -GT 5)
{
Echo "
Rule ID: itm8-LockedThreshold
Priority: 3
Lockout Threshhold is higher than the CIS18 recommendation. This allows brute-force attacks to be more efficient. To follow CIS18 standards we recommend setting it to 5." | Out-File $LogPath\Recommendations.txt -Append
}
If ($DomainPWD.LockoutDuration -lt "00:15:00") {
Echo "
Rule ID: itm8-LockedDuration
Priority: 3
Lockout Duration is less than the CIS18 recommendation. This allows brute-force attacks to be more efficient, To follow CIS18 standards we recommend setting it to 15" | Out-File $LogPath\Recommendations.txt -Append
}
if ($DomainPWD.ComplexityEnabled -eq $false) {
Echo 
Rule ID: itm8-Complexity
Priority: 3
"Password complexity is not enabled. To add complexity to passwords, we advise you to enable this simple setting." | Out-File $LogPath\Recommendations.txt -Append
}
If ($DomainPWD.PasswordHistoryCount -LT 24) {
Echo "Password History is less than 24. By having a password history lower than 24, users will at somepoint be able to re-use their old passwords. To prevent this, we recommend setting it to atleast 24." | Out-File $LogPath\Recommendations.txt -Append
}
If (($DomainPWD.MinPasswordAge).Days -EQ 0) {
Echo "Minimum password age is 0 days. To prevent users from cycling through passwords to use their favorite password, it should be set atleast 1 day" | Out-File $LogPath\Recommendations.txt -Append
}

# Recommendation on users with a password that never expires
$PasswordNeverExpires = ((Get-ADUser -Filter * -Properties PasswordNeverExpires | Where {$_.PasswordNeverExpires -EQ $true}).PasswordNeverExpires).Count
Echo "

# Users with a password that never expires #
Found $PasswordNeverExpires users with a password that never expires. A csv-file was created containing all of the users. 
Users with a password that never changes can pose a risk to the domain. If breached, they grant long-time access to the domain" | Out-File $Logpath\Recommendations.txt -Append

Import-Module ActiveDirectory
$UserList = Get-ADuser -filter * -Properties * | Where {$_.PasswordNeverExpires -EQ $true}
$ExportList = @()

foreach ($User in $UserList) {
    switch ($User.msExchRecipientTypeDetails) {
        1 {$MailboxValue = "UserMailbox"}
        2 {$MailboxValue = "LinkedMailbox"}
        4 {$MailboxValue = "SharedMailbox"}
        16 {$MailboxValue = "RoomMailbox"}
        32 {$MailboxValue = "EquipmentMailbox"}
        128 {$MailboxValue = "MailUser"}
        2147483648 {$MailboxValue = "RemoteUserMailbox"}
        8589934592 {$MailboxValue = "RemoteRoomMailbox"}
        17179869184 {$MailboxValue = "RemoteEquipmentMailbox"}
        34359738368 {$MailboxValue = "RemoteSharedMailbox"}
        default {$MailboxValue = ""}
      }

IF ($User.WhenCreated)
{
$WhenCreated = $User.WhenCreated.ToString("dd-MM-yyyy")
}
Else
{
$WhenCreated = ""
}

IF ($User.LastLogonDate)
{
$LastLogonDate = $User.LastlogonDate.ToString("dd-MM-yyyy")
}
Else
{
$LastLogonDate = ""
}

IF ($User.PasswordLastSet)
{
$PasswordLastSet = $User.PasswordLastSet.ToString("dd-MM-yyyy")
}
Else
{
$PasswordLastSet = ""
}


$OU = $User | Select @{n='OU';e={$_.DistinguishedName -replace '^.+?,(CN|OU.+)','$1'}} -ErrorAction SilentlyContinue
$Collection = New-Object PSObject -Property @{

DisplayName = ($User).DisplayName
Username = ($User).SamAccountName
Description = ($User).Description
WhenCreated = $WhenCreated
LastLogonDate = $LastLogonDate
PasswordLastSet = $PasswordLastSet
PasswordNeverExpires = ($User).PasswordNeverExpires
PasswordExpired = ($User).PasswordExpired
Enabled = ($User).Enabled
MailType = $MailboxValue
OU = $OU.OU

}
$ExportList += $Collection
}

# Select fields in specific order rather than random.
$ExportList | Select DisplayName, Username, Description, WhenCreated, LastlogonDate, PasswordLastSet, PasswordNeverExpires, PasswordExpired, Manager, Enabled, MailType, OU  | 
Export-csv $LogPath\PasswordNeverExpires.txt -NoTypeInformation -Encoding Unicode

# Users locked in Active Directory caused by a bad password
Echo "

# Users locked in Active Directory because of a bad password #" | Out-File $LogPath\Recommendations.txt -Append
$LockedCount = (Get-WinEvent -ComputerName $env:COMPUTERNAME -FilterHashTable @{LogName='Security'; ID=4740} -ErrorAction SilentlyContinue).count
If ($LockedCount -GE 1)
{
Echo "
Rule ID: itm8-LockedAccounts
Priority: 1
Security logs indicate that one or more accounts was recently locked $LockedCount times because of a bad password." | Out-File $LogPath\Recommendations.txt -Append
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
