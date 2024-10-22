# Checking permissions
$PMError = Test-Path $Home\desktop\PermissionIssue.txt
if ($PMError)
{
Remove-Item "$Home\desktop\PermissionIssue.txt" -Force
}
timeout 3
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
If (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
echo "Start PowerShell as an Administrator" > $Home\desktop\PermissionIssue.txt
Start $home\desktop\PermissionIssue.txt
Break
}

Write-Host "The script can take up to two minutes to complete." -ForegroundColor Yellow
Import-Module ActiveDirectory
$UserList = Get-ADuser -filter * -Properties *
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
Export-csv $Home\Desktop\InactiveUsers.csv -NoTypeInformation -Encoding Unicode

Write-Host "Script completed. Find your export here: $Home\Desktop\InactiveUsers.csv" -ForegroundColor Green
