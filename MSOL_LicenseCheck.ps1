<#
 The script will prompt for O365 credentials to connect to MSOnline to gather license information about all users
If MSOnline module is missing, it will be installed

#>

Try
{
Connect-MsolService -ErrorAction Stop
}
Catch
{

Write-Host "Installing the missing PowerShell Module: MSOnline. Please re-run the script afterwards" -ForegroundColor Yellow
Install-Module MSOnline -Confirm:$false
Break
}

$Users  = Get-MsolUser -ALL
$Results = @()

Foreach ($User in $Users) {
    $UPN = $User.UserPrincipalName
    $Blocked = $User.BlockCredential
    $DisplayName = $User.DisplayName

    $License = (Get-MsolUser -UserPrincipalName $UPN -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Licenses -ErrorAction SilentlyContinue)
    If (-Not $License) {
        $License = "No license"
    } Else {

        $License = $License.AccountSkuId -join ", "
    }

    If ($License -like "*SPE_E3*") {
        $License = "Microsoft 365 E3"

    } Elseif ($License -like "*SPE_E5*") {
        $License = "Microsoft 365 E5"

    } Elseif ($License -like "*SPB*") {
        $License = "Microsoft Business Premium"

    } Elseif ($License -like "*EXCHANGESTANDARD*") {
        $License = "Exchange Online Plan 1"

    } Elseif ($License -like "*EXCHANGEPREMIUM*") {
        $License = "Exchange Online Plan 2"
    }


    $Results += [PSCustomObject]@{
        DisplayName = $DisplayName
        UPN = $UPN
        Blocked = $Blocked
        License = $License
        
    }
}

$Results | Select-Object DisplayName, UPN, Blocked, License | Export-csv $home\desktop\Licenses.csv -NotypeInformation -Encoding Unicode -Delimiter ";"
Write-Host "Export Completed, find your file here: $Home\Desktop\Licenses.csv" -ForeGroundColor Green
