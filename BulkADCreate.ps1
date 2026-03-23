Import-Module ActiveDirectory
$ImportPath = "$Home\Desktop\ADUserExport.csv"

# Path to output CSV with passwords
$OutputPath = "$Home\Desktop\NewUsersWithPasswords.csv"

# Generate random passwords
function New-RandomPassword {
    param (
        [int]$Length = 15
    )

    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=[]{}'
    -join ((1..$Length) | ForEach-Object { $chars | Get-Random })
}

$Users = Import-Csv $ImportPath
$Output = @()
foreach ($User in $Users) {

    $PasswordPlain = New-RandomPassword
    $SecurePassword = ConvertTo-SecureString $PasswordPlain -AsPlainText -Force

    try {
        New-ADUser `
            -SamAccountName $User.Username `
            -UserPrincipalName ($User.Username + "@yourdomain.local") ` # REMEMBER TO CHANGE THIS TO THE CORRECT DOMAIN SUFFIX
            -Name $User.DisplayName `
            -DisplayName $User.DisplayName `
            -Enabled $true `
            -AccountPassword $SecurePassword `
            -ChangePasswordAtLogon $true `
            -Path "OU=Users,DC=yourdomain,DC=local" # REMEMBER TO CHANGE THIS TO THE CORRECT OU

        # Store output
        $Output += [PSCustomObject]@{
            SamAccountName = $User.Username
            DisplayName    = $User.DisplayName
            Password       = $PasswordPlain
        }
    }
    catch {
        Write-Host "Failed to create user: $($User.Username)" -ForegroundColor Red
    }
}

# Export credentials
$Output | Export-Csv $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Output file: $OutputPath" -ForegroundColor Green
