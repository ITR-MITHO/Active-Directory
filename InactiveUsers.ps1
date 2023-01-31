<#

Finds users that haven't logged in within the last 90 days. 
To change the search scope, change the number of days from "90" to "XX" where XX is how many days it should filter from

#>

Import-Module ActiveDirectory
$Date = (Get-Date).AddDays(-90)
$UserList = Get-ADuser -filter * -Properties * | Where {$_.LastLogonDate -LT $Date}
$ExportList = @()



foreach ($User in $UserList) {


If ($User.msExchRecipientTypeDetails -eq "1")
{

$MailboxValue = "UserMailbox"

}


If ($User.msExchRecipientTypeDetails -eq "4")

{

$MailboxValue = "SharedMailbox"

}


If ($User.msExchRecipientTypeDetails -eq "16")

{

$MailboxValue = "RoomMailbox"

}

If ($User.msExchRecipientTypeDetails -eq "32")

{

$MailboxValue = "EquipmentMB"

}


If ($User.msExchRecipientTypeDetails -eq "2147483648")

{

$MailboxValue = "RemoteUserMB"

}
     

If ($User.msExchRecipientTypeDetails -eq "8589934592")
{

$MailboxValue = "RemoteRoomMB"

}


If ($User.msExchRecipientTypeDetails -eq "17179869184")
{

$MailboxValue = "RemoteEquipMB"

}


If ($User.msExchRecipientTypeDetails -eq "34359738368")
{

$MailboxValue = "RemoteSharedMB"

}

if (-not $User.msExchRecipientTypeDetails)

{

$MailboxValue = "No Mailbox"

}


$Manager = Get-ADObject $User -Properties Manager | Select-Object @{Name="Manager";Expression={(Get-ADUser -property DisplayName $_.Manager).DisplayName}} 
if ($Manager)
{
$MName = $Manager
}

$OU = Get-ADUser $User | Select @{n='OU';e={$_.DistinguishedName -replace '^.+?,(CN|OU.+)','$1'}}
$Collection = New-Object PSObject -Property @{

FullName = (Get-ADUser $User -Properties DisplayName).DisplayName
Username = (Get-ADUser $User -Properties SamAccountName).SamAccountName
Created = (Get-ADUser $User -Properties WhenCreated).WhenCreated
LastLogonDate = (Get-ADUser $User -Properties LastLogonDate).LastLogonDate
PWDReset = (Get-ADUser $User -Properties PasswordLastSet).PasswordLastSet
Manager = $MName.Manager
Enabled = (Get-ADUser $User -Properties Enabled).Enabled
MailType = $MailboxValue
OU = $OU.OU


}

$ExportList += $Collection

}

# Select fields in specific order rather than random.
$ExportList | Select FullName, Username, Created, LastlogonDate, PWDReset, Manager, Enabled, Type, OU  | 
Export-csv $Home\Desktop\Report.csv -NoTypeInformation -Encoding Unicode

Write-Host "Script completed. Find your export here: $Home\Desktop\Report.csv" -ForegroundColor Green
