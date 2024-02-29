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