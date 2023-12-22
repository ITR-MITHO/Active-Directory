<#

The script will ask you to enter the word to search for. Whatever you type in, the script will wildcard search for. If you enter "Outlook" it will find anything that have Outlook inside of it, from Office templates, to registry keys.

#>
$Phrase = Read-Host "Enter what setting you want to search for, the script will wildcard search"

$DC = (Get-ADDomainController | Select Name -First 1).Name
Invoke-Command -ComputerName $DC {
$AllGPO = Get-GPO -All -Domain $env:SERDNSDOMAIN
[string[]] $MatchedGPOList = @()

ForEach ($GPO in $AllGPO) { 
    $Report = Get-GPOReport -Guid $GPO.Id -ReportType XML 
    if ($Report -match $Phrase) { 
        Write-Host "$($GPO.DisplayName)" -ForeGroundColor "Green"
        $MatchedGPOList += "$($GPO.DisplayName)";
} 
  }
    }
