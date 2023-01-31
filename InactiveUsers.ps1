<#

Finds users that haven't logged in within the last 90 days. 
To change the search scope, change the number of days from "90" to "XX" where XX is how many days you want to look back.

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

if ($User.msExchRecipientTypeDetails -eq "")
{

$MailboxValue = "No Mailbox"

}
     
$OUOutput = Get-ADUser $User | Select @{n='OU';e={$_.DistinguishedName -replace '^.+?,(CN|OU.+)','$1'}}
$Collection = New-Object PSObject -Property @{

FullName = (Get-ADUser $User -Properties DisplayName).DisplayName
Username = (Get-ADUser $User -Properties SamAccountName).SamAccountName
Created = (Get-ADUser $User -Properties WhenCreated).WhenCreated
LastLogonDate = (Get-ADUser $User -Properties LastLogonDate).LastLogonDate
PWDReset = (Get-ADUser $User -Properties PasswordLastSet).PasswordLastSet
Manager = (Get-ADUser $User -Properties Manager).Manager
Enabled = (Get-ADUser $User -Properties Enabled).Enabled
Type = $MailboxValue
OU = $OUOutput


}

$ExportList += $Collection

}

# Select fields in specific order rather than random.
$ExportList | Select FullName, Username, Created, LastlogonDate, PWDReset, Manager, Enabled, Type, OU | 
Export-csv $Home\Desktop\Report.csv -NoTypeInformation -Encoding Unicode
