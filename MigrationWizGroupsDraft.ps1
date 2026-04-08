Add-PSSnapin *EXC*
Import-Module ActiveDirectory

$Groups = Get-DistributionGroup | Select SamAccountName, Alias, DisplayName, PrimarySMTPAddress, RecipientType, EmailAddresses, Description
$Groups | Export-csv $home\desktop\Groups.csv -NoTypeInformation -Encoding Unicode
$Data = Import-Csv $home\desktop\Groups.csv
$Results = @()


Foreach ($D in $Data)
{
$GroupName = $D.Alias
$GroupDes = $D.Description
$User = Get-DistributionGroupMember -Identity $GroupName | Select SamAccountName, DisplayName, PrimarySMTPAddress

Foreach ($U in $User)

{

$Results += [PSCustomObject]@{
                Group = $GroupName
                User = $U.SamAccountName               
                UserDisplay = $U.DisplayName
                UserEmail = $U.PrimarySMTPAddress

}
    }
        }
$Results
