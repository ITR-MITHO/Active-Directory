<#

Finds users that haven't logged in within the last 90 days. 
Exports the following information; 
Displayname
SamAccountName
LastLogonDate
PasswordLastSet
Manager

#>

Import-Module ActiveDirectory
$Date = (Get-Date).AddDays(-90)
Get-ADuser  -filter * -Properties DisplayName, SamAccountName, LastLogonDate, PasswordLastSet, Manager | Where {$_.LastLogonDate -LT $Date} | Select DisplayName, SamAccountName, LastLogonDate, PasswordLastSet, Manager |
Export-csv $Home\Desktop\InactiveUsers.csv -Notypeinformation -Encoding Unicode

Write-Host "Find the exported data here: $home\Desktop\InactiveUsers.csv" -ForegroundColor Green
