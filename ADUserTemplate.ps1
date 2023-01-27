# Active Directory and Exchange 2010 modules.
Add-PSSnapin *EXC*
Import-Module ActiveDirectory

# Arrays for the script
$FirstName = Read-Host "First Name"
$Surname = Read-Host "Last Name"
$Username = Read-Host "Username"
# $EmployeeID = Read-Host "EmployeeID"
$Department = Read-Host "Department"
$Title = Read-Host "Title"
$Manager = Read-Host "Users manager (credentials)"
$CopyOF = Read-Host "Copy permissions from user (credentials)"
$Password = Read-Host "Password" | ConvertTo-SecureString -AsPlainText -Force

# Decrypts password and saves it to C:\password.txt ready to sent via mail to the users manager. 
$BSTR = `
     [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$PlainPassword | Out-File -FilePath C:\Password.txt

# Creating Displayname, First name, surname, samaccountname, UPN, What OU to place it in and a password for the user.
 New-ADUser `
-Name "$FirstName $Surname" `
-GivenName $FirstName `
-Surname $Surname `
-SamAccountName $Username `
-UserPrincipalName $Username@domain.com `
-Displayname "$FirstName $Surname" `
-Path "CN=Users,DC=domain,DC=com" `
-AccountPassword $Password

# Set details like, change password, Company, Department, title, homedrive, e-mailadress and enables the account in AD
Set-ADUser $Username -Enabled $True
Set-ADUser $Username -ChangePasswordAtLogon $True 
Set-ADUser $Username -Title $Title
Set-ADUser $Username -Department $Department
Set-ADUser $Username -Company "Company"
Set-ADUser $Username -Manager "$Manager"
Set-ADUser $Username -EmailAddress "$Username@domain.com"
Set-ADUser $Username -ScriptPath Logon.bat
# Set-ADUser $Username -Add @{"extensionattribute1"="$EmployeeID"}
Set-ADuser $Username -HomeDrive "P" -HomeDirectory "\\SERVER\DRIVE\$USERNAME"

# Add the new user to specific AD-groups.
#Add-ADGroupMember -Identity "ADGROUP1" -Members $Username
#Add-ADGroupMember -Identity "ADGROUP2" -Members $Username
#Add-ADGroupMember -Identity "ADGROUP3" -Members $Username

# Finds all the AD-groups that the "Copy of" user has and adds it to the new user automatically.
Get-ADPrincipalGroupMembership -Identity $CopyOF | select SamAccountName | ForEach-Object {Add-ADGroupMember -Identity $_.SamAccountName -Members $Username}

# Creates a home directory for the user
New-Item -Path \\SERVER\DRIVE\$Username -ItemType Directory


# Creates a mailbox for the user in Exchange 2010.
Enable-Mailbox $Username

# Sends a mail to the 'manager' with the password for the new user.
$To = "$Manager <$Manager@domain.com>"
$From = "Access Management <AccessManagement@domain.com>"
$Subject = "Password for $FullName"
$Body = "The password can be found in the attached file 'Password'"
$Attachment = "C:\Password.txt"
$SMTP = "Mailrelay.domain.com"
Send-MailMessage -To "$To" -From "$From" -Subject "$Subject" -Body "$Body" -Attachments "$Attachment" -SmtpServer "$SMTP"

# Message to ServiceDesk so they know that the script is done.
Write-Host "AD & Exchange user created. The manager have recieved a password for the new employee in their mailbox." -ForegroundColor Green