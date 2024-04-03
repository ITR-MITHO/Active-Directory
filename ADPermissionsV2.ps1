<#
The script will export the following information on all AD-users. 

                DisplayName
                SamAccountName
                LastLogonDate
                PasswordNeverExpires
                PasswordLastSet
                GroupName
                GroupDescription

If you're having any issues with the script, please reach out to me.
https://github.com/ITR-MITHO
#>

# Checking permissions

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
If (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
Write-Host "Start PowerShell as an Administrator" -ForeGroundColor Red
Break
}

Import-Module ActiveDirectory
$Users = Get-ADUser -Filter * -Properties MemberOf, DisplayName, SamAccountName, LastLogonDate, PasswordLastSet, PasswordNeverExpires
$Results = @()

Foreach ($User in $Users)
{
    $Groups = $User.MemberOf
    if ($Groups)
    {
        Foreach ($Group in $Groups)
        {
            $GroupName = (Get-ADGroup -Identity $Group).Name
            $GroupDescription = (Get-ADGroup -Identity $Group -Properties Description).Description

            $Results += [PSCustomObject]@{
                Name = $User.DisplayName
                UserName = $User.SamAccountName
                LastLogon = $User.LastLogonDate
                PWDExpires = $User.PasswordNeverExpires
                PWDChanged = $User.PasswordLastSet
                Group = $GroupName
                Description = $GroupDescription
            }
        }
    }
}

$Results | Select Name, UserName, LastLogon, PWDExpires, PWDChanged, Group, Description | Export-csv "$Home\Desktop\ADPermissions.csv" -NoTypeInformation -Encoding UNICODE -Append
Write-Host "Export completed. File can be found here: $home\desktop\ADPermissions.csv" -ForegroundColor Green
