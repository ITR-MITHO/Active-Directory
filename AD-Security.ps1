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


# Stop and disable Print Spooler on all domain controllers
$DomainName = (Get-ADDomain).DNSRoot
$DC = Get-ADDomainController -filter * | Select Hostname
Foreach ($D in $DC)
{
Invoke-Command $D.HostName {
Get-Service Spooler | Stop-Service -Force
Set-Service Spooler -StartupType Disabled
}
    }
Write-Host "INFORMATION: Print spoolers stopped and disabled" -ForegroundColor Yellow

# Enable AD Recycle Bin if not already present
If (-Not (Get-ADOptionalFeature -Filter {Name -like "Recycle*"}).EnabledScopes)
{
$BinDestination = Get-ADOptionalFeature "Recycle Bin Feature" | Select DistinguishedName
Enable-ADOptionalFeature $BinDestination.DistinguishedName -Scope ForestOrConfigurationSet -Target $DomainName -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "INFORMATION: AD Recycle bin enabled" -ForegroundColor Yellow
}

# Empty the Schema Admins and Enterprise Admins
$Schema = Get-ADGroupMember -Identity "Schema Admins" | Get-ADUser -Properties SamAccountName
Foreach ($S in $Schema)
{
Remove-ADGroupMember -Identity "Schema Admins" -Members $S.SamaccountName -Confirm:$false
}
$Enterprise = Get-ADGroupMember -Identity "Enterprise Admins" | Get-ADUser -Properties SamAccountName
Foreach ($E in $Enterprise)
{
Remove-ADGroupMember -Identity "Enterprise Admins" -Members $E.SamaccountName -Confirm:$false
}
Write-Host "INFORMATION: Removed all members in Schema Admins and Enterprise Admins" -ForegroundColor Yellow

# Prevent administrator accounts from being delegated
Get-ADGroupMember "Domain Admins" | Get-ADuser -Properties AccountNotDelegated | Where-Object {-not $_.AccountNotDelegated -and $_.ObjectClass -EQ "User"} | Set-ADUser -AccountNotDelegated $True
Write-Host "INFORMATION: All members of Domain Admins set to not allow delegation" -ForegroundColor Yellow

# Protect Orginizational Units from accidental deletion
Get-ADOrganizationalUnit -filter {Name -like "*"} -Properties ProtectedFromAccidentalDeletion | Where {$_.ProtectedFromAccidentalDeletion -eq $false} | Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $true -ErrorAction SilentlyContinue
Write-Host "INFORMATION: Set all OU's to be protected from accidential deletion" -ForegroundColor Yellow

# Enable Powershell Audit logging
Foreach ($D in $DC)
{
Invoke-Command $D.HostName {
New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
}
    }
Write-Host "INFORMATION: Enabled Powershell audit logging" -ForegroundColor Yellow

# Set Primary Group to 'Domain Users' for anyone but the 'Guest' account
$PrimaryGroup = Get-ADUser -Filter * -Properties SamAccountName, PrimaryGroup | Where-Object { $_.PrimaryGroup -ne (Get-ADGroup -Identity "Domain Users").DistinguishedName -and $_.SamAccountName -NE "Guest"}
Foreach ($Primary in $PrimaryGroup)
{
Set-ADUser $Primary.SamAccountName -Replace @{PrimaryGroupID='513'}
}
Write-Host "INFORMATION: Changed primary group of all users to 'Domain Users'" -ForegroundColor Yellow

# Disable NTLMV1 and only allow NTLMV2  - DISABLED SINCE IT CAN IMPACT PRODUCTION
<#Foreach ($D in $DC)
{
Invoke-Command $D.HostName {
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name 'LmCompatibilityLevel' -PropertyType DWORD -Value 5 -ErrorAction SilentlyContinue | Out-Null}
}
Write-Host "INFORMATION: Disabled NTLMV1 and only allowed NTLMV2 on all domain controllers" -ForeGroundColor Yellow
Write-Host "
REMINDER: Change the Default Domain Controllers Policy with the below settings:" -ForegroundColor Red
Write-Host "Computer Configuration -> Windows Settings ->  Security Settings -> Local Policies -> Security Options -> Network security: LAN Manager authentication level -> Send NTLMv2 response only\refuse LM & NTLM" -ForegroundColor Yellow
#>

# Export a list of all AD-users that have a password that never expires
MKDIR $Home\Desktop\ADAssesment -ErrorAction SilentlyContinue | Out-Null
Get-ADUser -Filter * -Properties DisplayName, SamAccountName, LastLogonDate, PasswordLastSet | Select DisplayName, SamAccountName, LastLogonDate, PasswordLastSet |
Export-csv $Home\Desktop\ADAssesment\PasswordNeverExpire.csv -NoTypeInformation -Encoding Unicode

# Export a list of the Default Domain Password Policy
Get-ADDefaultDomainPasswordPolicy | Out-File $Home\Desktop\ADAssesment\PasswordPolicy.txt

# Export a list of the audit policy
auditpol /get /category:* | Out-File  $Home\desktop\ADAssesment\AuditPolicy.txt

# Export a list of all administrator accounts
Get-ADGroupMember "Domain admins" | Get-ADUser -Properties * | Select DisplayName, SamAccountName, LastLogonDate, PasswordLastSet, PasswordNeverExpires, Description |
Export-csv $Home\Desktop\ADAssesment\Administrators.csv -NoTypeInformation -Encoding Unicode
