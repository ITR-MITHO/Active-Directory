<#
.DESCRIPTION
Automatically find all DNS records corrosponding to a specific IP-address. It searches all DNS zones automatically.

.OUTPUTS
Displayed directly in the console

#>

$TargetIPs = @('192.168.1.5') # Search multiple IPs by '192.168.1.10', '192.168.1.11'
$Pattern   = ($TargetIPs | ForEach-Object { [regex]::Escape($_) }) -join '|'

# Automatically finds all zones 
$Zones = Get-DnsServerZone | 
    Where-Object { $_.ZoneType -eq "Primary" -and $_.ZoneName -notlike "*.in-addr.arpa" -and $_.ZoneName -ne "TrustAnchors" } | 
    Select-Object -ExpandProperty ZoneName

$Results = @()

foreach ($Zone in $Zones) {
    Write-Host "Scanning $Zone..." -ForegroundColor Gray
    
    $Records = Get-DnsServerResourceRecord -ZoneName $Zone -ErrorAction SilentlyContinue | 
        Where-Object { $_.RecordData.IPv4Address -match $Pattern -or $_.RecordData.RecordData -match $Pattern } | 
        Select-Object @{Name="Zone"; Expression={$Zone}}, HostName, RecordType, @{Name="IPAddress"; Expression={if($_.RecordData.IPv4Address){$_.RecordData.IPv4Address}else{$_.RecordData.RecordData}}}
    
    if ($Records) { $Results += $Records }
}

# Output combined results
Write-Host "`nSearch Complete. Results:" -ForegroundColor Green
$Results | Format-Table -AutoSize
