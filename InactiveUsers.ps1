$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
If (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
write-host "Script is not running as Administrator" -ForegroundColor Yellow
Break
}

Write-Host "The script can take up to two minutes to complete." -ForegroundColor Yellow
Import-Module ActiveDirectory
$UserList = Get-ADuser -filter * -Properties *
$ExportList = @()

foreach ($User in $UserList) {
    switch ($User.msExchRecipientTypeDetails) {
        1 {$MailboxValue = "UserMailbox"}
        4 {$MailboxValue = "SharedMailbox"}
        16 {$MailboxValue = "RoomMailbox"}
        32 {$MailboxValue = "EquipmentMailbox"}
        2147483648 {$MailboxValue = "RemoteUserMailbox"}
        8589934592 {$MailboxValue = "RemoteRoomMailbox"}
        17179869184 {$MailboxValue = "RemoteEquipmentMailbox"}
        34359738368 {$MailboxValue = "RemoteSharedMailbox"}
        default {$MailboxValue = ""}
      }

$Manager = Get-ADObject $User -Properties Manager | Select-Object @{Name="Manager";Expression={(Get-ADUser -property DisplayName $_.Manager).DisplayName}} 
if ($Manager)
{
$MName = $Manager
}

$OU = Get-ADUser $User | Select @{n='OU';e={$_.DistinguishedName -replace '^.+?,(CN|OU.+)','$1'}}
$Collection = New-Object PSObject -Property @{

DisplayName = ($User).DisplayName
Username = ($User).SamAccountName
Description = ($User).Description
WhenCreated = ($User).WhenCreated
LastLogonDate = ($User).LastLogonDate
PasswordLastSet = ($User).PasswordLastSet
PasswordNeverExpires = ($User).PasswordNeverExpires
PasswordExpired = ($User).PasswordExpired
Manager = $MName.Manager
Enabled = ($User).Enabled
MailType = $MailboxValue
OU = $OU.OU

}

$ExportList += $Collection

}

# Select fields in specific order rather than random.
$ExportList | Select DisplayName, Username, Description, WhenCreated, LastlogonDate, PasswordLastSet, PasswordNeverExpires, PasswordExpired, Manager, Enabled, MailType, OU  | 
Export-csv $Home\Desktop\InactiveUsers.csv -NoTypeInformation -Encoding Unicode

Write-Host "Script completed. Find your export here: $Home\Desktop\InactiveUsers.csv" -ForegroundColor Green
