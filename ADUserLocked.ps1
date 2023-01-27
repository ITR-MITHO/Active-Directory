$DC = Get-ADDomainController -Filter * | Select Hostname 
$properties = @(
    @{n='User';e={$_.Properties[0].Value}},
    @{n='Locked by';e={$_.Properties[1].Value}},
    @{n='TimeStamp';e={$_.TimeCreated}},
    @{n='DCName';e={$_.Properties[4].Value}}
)
Foreach ($D in $DC)
{
Get-WinEvent -ComputerName $D.Hostname -FilterHashTable @{LogName='Security'; ID=4740} | 
Select $properties
}