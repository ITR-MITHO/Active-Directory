Import-Module ActiveDirectory
$ImportPath = "$Home\Desktop\ADUserExport.csv"
$OutputPath = "$Home\Desktop\NewUsersWithPasswords.csv"

## Change these to ensure the correct OU is chosen and the correct domain is used when creating! ##
$OU = "OU=Users,DC=yourdomain,DC=local"
$Domain = "yourdomain.local"

# Generate random 15 character password
function New-RandomPassword {
    param ([int]$Length = 15)
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=[]{}'
    -join ((1..$Length) | ForEach-Object { $chars | Get-Random })
}

$Users = Import-Csv $ImportPath
$Output = @()

# --- PASS 1: CREATE USERS ---
foreach ($User in $Users) {

    $PasswordPlain = New-RandomPassword
    $SecurePassword = ConvertTo-SecureString $PasswordPlain -AsPlainText -Force

    try {
        New-ADUser `
            -SamAccountName $User.SamAccountName `
            -UserPrincipalName ($User.SamAccountName + "@$Domain") `
            -Name $User.DisplayName `
            -DisplayName $User.DisplayName `
            -Description $User.Description `
            -Enabled ([System.Convert]::ToBoolean($User.Enabled)) `
            -Title $User.Title `
            -Department $User.Department `
            -OfficePhone $User.TelephoneNumber `
            -MobilePhone $User.Mobile `
            -AccountPassword $SecurePassword `
            -ChangePasswordAtLogon $true `
            -Path $OU

        $Output += [PSCustomObject]@{
            SamAccountName = $User.SamAccountName
            DisplayName    = $User.DisplayName
            Password       = $PasswordPlain
        }
    }
    catch {
        Write-Host "Failed to create user: $($User.SamAccountName)" -ForegroundColor Red
    }
}

# --- PASS 2: SET REMAINING ATTRIBUTES ---
foreach ($User in $Users) {

    try {
        $ADUser = Get-ADUser -Identity $User.SamAccountName

        if ($User.PasswordNeverExpires -eq "True") {
            Set-ADUser -Identity $ADUser -PasswordNeverExpires $true
        }

        if ($User.Manager) {
            $ManagerObj = Get-ADUser -Filter "SamAccountName -eq '$($User.Manager)'"
            if ($ManagerObj) {
                Set-ADUser -Identity $ADUser -Manager $ManagerObj.DistinguishedName
            }
        }

    }
    catch {
        Write-Host "Failed to update user: $($User.SamAccountName)" -ForegroundColor Yellow
    }
}

# Export passwords
$Output | Export-Csv $OutputPath -NoTypeInformation -Encoding UNICODE
Write-Host "Output file: $OutputPath" -ForegroundColor Green
