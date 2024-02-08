<#

  THIS SCRIPT IS NOT READY FOR PRODUCTION, IT IS STILL BEING TESTED AND DEVELOPED. RUN AT YOUR OWN RISK

  Functionality:
  Stops and DISABLES the Print Spooler service on all domain controllers
  Enables AD Recycle Bin (If not already enabled)
  Removes all members from Schema Admins and Enterprise Admins
  Prevents all domain admins from being delegated in the domain
  Enables PowerShell logging on all domain controllers
  Change primary group for all users to "Domain Users"
  Disables NTLMV1 and only allows NTLMV2 by registry
  Protects all Orginizational Units from accidential deletion
  Creates a csv-file containing all AD-users that have a password that never expires
  Creates a file listing the Default Domain Password Policy
  Creates a file listing the audit policies
  Creates a csv-file containing all administrator accounts

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
$Schema = Get-ADGroupMember -Identity "Schema Admins" | Get-ADUser -Properties SamAccountName
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
Get-ADGroupMember "Domain Admins" | Get-ADuser -Properties AccountNotDelegated | Where-Object {-not $_.AccountNotDelegated -and $_.ObjectClass -EQ "User"} | Set-ADUser -AccountNotDelegated $True
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

<# Disable NTLMV1 and only allow NTLMV2  - DISABLED SINCE IT CAN IMPACT PRODUCTION
Foreach ($D in $DC)
{
Invoke-Command $D.HostName {
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name 'LmCompatibilityLevel' -PropertyType DWORD -Value 5 -ErrorAction SilentlyContinue | Out-Null}
}
ECHO "INFORMATION: Disabled NTLMV1 and only allowed NTLMV2 on all domain controllers through registry" | Out-File $LogFile -Append

Echo "REMINDER: Change the Default Domain Controllers Policy with the below settings:" | Out-File $LogFile -Append
Echo "Computer Configuration -> Windows Settings ->  Security Settings -> Local Policies -> Security Options -> Network security: LAN Manager authentication level -> Send NTLMv2 response only\refuse LM & NTLM" | Out-File $LogFile -Append
#>


# Export a list of all AD-users that have a password that never expires
Get-ADUser -Filter * -Properties DisplayName, SamAccountName, LastLogonDate, PasswordLastSet | Select DisplayName, SamAccountName, LastLogonDate, PasswordLastSet |
Export-csv $LogPath\2-PasswordNeverExpire.csv -NoTypeInformation -Encoding Unicode

# Export a list of the audit policy
auditpol /get /category:* | Out-File  $Home\desktop\ADAssesment\4-AuditPolicy.txt

# Export a list of all administrator accounts
Get-ADGroupMember "Domain admins" | Get-ADUser -Properties * -ErrorAction SilentlyContinue | Select DisplayName, SamAccountName, LastLogonDate, PasswordLastSet, PasswordNeverExpires, Description |
Export-csv $LogPath\5-DomainAdmins.csv -NoTypeInformation -Encoding Unicode

Get-ADGroupMember "Administrators" | Get-ADUser -Properties * -ErrorAction SilentlyContinue | Select DisplayName, SamAccountName, LastLogonDate, PasswordLastSet, PasswordNeverExpires, Description |
Export-csv $LogPath\5-Administrators.csv -NoTypeInformation -Encoding Unicode

Write-Host "Find all your logs in $Logpath" -ForegroundColor Green

# Export a list of the Default Domain Password Policy with recommendations following CIS18 standard
Get-ADDefaultDomainPasswordPolicy | Out-File $LogPath\3-PasswordPolicy.txt
$DomainPWD = Get-ADDefaultDomainPasswordPolicy
If ($DomainPWD) {
}
If ($DomainPWD.MinPasswordLength -LT 14) {
Echo "
Minimum password length is below 14 characters, we recommend using atleast 14 characters in passwords and a maximum password age set to 365 days" | Out-File $Home\Desktop\ADAssesment\3-PasswordPolicy.txt -Append
}
If ($DomainPWD.LockoutThreshold -GT 5)
{
Echo "LockOut ThreshHold is higher than the CIS18 recommendation. This allows brute-force attacks to be more efficient. To follow CIS18 standards we recommend setting it to 5." | Out-File $Home\Desktop\ADAssesment\3-PasswordPolicy.txt -Append
}
If ($DomainPWD.LockoutDuration -LT "00:15:00") {
Echo "Lockout Duration is less than the CIS18 recommendation. This allows brute-force attacks to be more efficient, To follow CIS18 standards we recommend setting it to 15" | Out-File $Home\Desktop\ADAssesment\3-PasswordPolicy.txt -Append
}
if ($DomainPWD.ComplexityEnabled -EQ $false) {
Echo "Password complexity is not enabled - To add complexity to passwords, we advise you to enable this simple setting." | Out-File $Home\Desktop\ADAssesment\3-PasswordPolicy.txt -Append
}
If ($DomainPWD.PasswordHistoryCount -GE 10) {
Echo "Password History is less than 10. By having a password history lower than 10, users will at somepoint be able to re-use their old passwords. To prevent this, we recommend setting it to atleast 20." | Out-File $Home\Desktop\ADAssesment\3-PasswordPolicy.txt -Append
}
