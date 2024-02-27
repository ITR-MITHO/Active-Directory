<#

The PowerShell script will send an e-mail notification to users when their password is 14 days away from expiring.
If any questions, reach out to mitho@itrelation.dk

#>

Import-Module ActiveDirectory
$CurrentDate = Get-Date -Format "dd-MM-yyyy"
$Users = Get-ADUser -filter * -Properties "SamAccountName", "PasswordLastSet", "EmailAddress", "PasswordNeverExpires", "PasswordLastSet"

# E-mail configuration
$Subject = "Your Active Directory password expires in 14 days"
$To = $User.EmailAddress
$From = "PasswordService@domain.com"
$SMTP = "smtp.domain.com"

foreach ($User in $Users) {
    # Password expiration is set to 180 days in the customers password policy, 166 days is therefore 14 days before expiration.
    $PasswordExpiryDate = $User.PasswordLastSet.AddDays(166)
    $PasswordExpires = $PasswordExpiryDate.ToString("dd-MM-yyyy")

    if ($PasswordExpires -eq $CurrentDate) {

        Send-MailMessage -SmtpServer $SMTP -Port 25 -From $From -To $To -Subject $Subject -Encoding Unicode
    }
}
