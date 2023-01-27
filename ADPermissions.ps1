Import-Module ActiveDirectory
$FileCheck = Test-Path "C:\Users\$ENV:Username\Desktop\ADPermissions.csv"
If ($Filecheck) 
{
Remove-Item "C:\Users\$ENV:Username\Desktop\ADPermissions.csv"
}
 
cls
Write-Host "Starting Export.. The script is estimated to take about 5 minutes to complete." -ForegroundColor Yellow
$ErrorActionPreference = 'silentlycontinue'
$Groups = Get-ADGroup -filter * -Properties SamAccountname, Description | Select SamAccountname, Description


foreach ($Group in $Groups) 
{

$GroupName = $Group.SamAccountname


    Get-ADGroupMember $GroupName | 
    Get-ADObject -Properties * | Where {$_.ObjectClass -NE "Computer"} | 
    Select-Object @{Name="Type";Expression={$_.ObjectClass}},
    @{Name="Full name";Expression={$_.DisplayName}},
    @{Name="Username";Expression={$_.SamAccountName}},
    @{Name="Department";Expression={$_.Department}},
    @{Name="Title";Expression={$_.Title}},
    @{Name="Manager";Expression={(Get-ADUser -property DisplayName $_.Manager).DisplayName}},
    @{Name="Manager username";Expression={(Get-ADUser -property SamAccountName $_.Manager).SamAccountname}},
    @{Name="Last Logon";Expression={(Get-ADUser -property LastLogonDate $_.SamAccountName).LastLogonDate}},
    @{Name="PWD changed";Expression={(Get-ADUser -property PasswordLastSet $_.SamAccountName).PasswordLastSet}},
    @{Name="Member of";Expression={$Group.SamAccountName}},
    @{Name="Group Description";Expression={$Group.Description}} |
    Export-csv "C:\Users\$ENV:Username\Desktop\ADPermissions.csv" -NoTypeInformation -Encoding UNICODE -Append
    
    
}
cls
Write-Host "Export completed. File can be found here: $home\desktop\ADPermissions.csv" -ForegroundColor Green
