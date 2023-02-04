Import-Module ActiveDirectory
$Users = Get-ADUser -Filter * -Properties MemberOf, DisplayName, SamAccountName, LastLogonDate, PasswordLastSet
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
                PWDChanged = $User.PasswordLastSet
                Group = $GroupName
                Description = $GroupDescription
            }
        }
    }
}

$Results | Export-csv "$Home\Desktop\ADPermissions.csv" -NoTypeInformation -Encoding UNICODE -Append
Write-Host "Export completed. File can be found here: $home\desktop\ADPermissions.csv" -ForegroundColor Green
