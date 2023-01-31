<#

Finds users that haven't logged in within the last 90 days. 
To change the search scope, change the number of days from "90" to "XX" where XX is how many days you want to look back.

#>

Import-Module ActiveDirectory
$Date = (Get-Date).AddDays(-90)
Get-ADuser  -filter * -Properties DisplayName, SamAccountName, LastLogonDate, PasswordLastSet, Manager | Where {$_.LastLogonDate -LT $Date} | Select DisplayName, SamAccountName, LastLogonDate, PasswordLastSet, Manager, Enabled, DistinguishedName |
Export-csv $Home\Desktop\InactiveUsers.csv -Notypeinformation -Encoding Unicode

Write-Host "Find the exported data here: $home\Desktop\InactiveUsers.csv" -ForegroundColor Green
