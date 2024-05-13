<#

The PowerShell script will send an e-mail notification to users when their password is 14 days away from expiring.
If any questions, reach out to mitho@itm8.com

#>
Import-Module ActiveDirectory
$CurrentDate = Get-Date -Format "dd-MM-yyyy"
$Users = Get-ADUser -Filter * -Properties SamAccountName, PasswordLastSet, EmailAddress, PasswordNeverExpires, PasswordLastSet

# E-mail configuration
$Subject = "Your Active Directory password expires in 14 days"
$To = $User.EmailAddress
$From = "it@domain.com"
$SMTP = "domain-com.protection.outlook.com"

foreach ($User in $Users) 
    {
    # Password expiration is set to 90 days in the customers password policy, 76 days is therefore 14 days before expiration.
    $PasswordExpiryDate = $User.PasswordLastSet.AddDays(76)
    $PasswordExpires = $PasswordExpiryDate.ToString("dd-MM-yyyy")
    
    if ($PasswordExpires -eq $CurrentDate) 
    {
        Send-MailMessage -SmtpServer $SMTP -Port 25 -From $From -To $To -Subject $Subject -Encoding Unicode -Body "

        Your password expires in 14 days, please change it as soon as possible to prevent yourself from being locked out of the system.
        To change your password now you can simply hold down CTRL+ALT+DELETE and choose the option 'Change a password'"
    }

    # Logging whenever an e-mail was sent.
    Write-Output "Sent e-mail to $to" | Out-File C:\ITR\PasswordNotify\Log.txt -Append
}
