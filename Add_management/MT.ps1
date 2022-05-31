<#1 Creating New User and Computer Accounts
#1.1
Get-Command New-ADUser -Syntax
#>

<#1.2 Create Single users
New-ADUser New_UserStudent #default path on CN=Users
New-ADUser B.Johnson -Path "OU=NewUsers,DC=sheridan-ra,DC=local" #put on a specific OU
#>

<#1.3 Aduser with properties
New-ADUser `
-Name "Jack Robinson" `
-GivenName "Jack" `
-Surname "Robinson" `
-SamAccountName "J.Robinson" `
-UserPrincipalName "J.Robinson@sheridan-ra.local" `
-Path "OU=NewUsers,DC=sheridan-ra,DC=local" `
-AccountPassword(Read-Host -AsSecureString "Input Password") `
-Enabled $true
#>

<#1.4 bulk user create
$path="OU=BulkUsers,DC=sheridan-ra,DC=local"
$username="Students_"
$count=1..5
foreach($i in $count)`
{`
    New-AdUser `
    -Name $username$i `
    -Path $path `
    -Enabled $True `
    -ChangePasswordAtLogon $true ` `
    -AccountPassword(ConvertTo-SecureString "P@ssword" -AsPlainText -force) `
    -PassThru `
}
#>

<#1.5 Bulk With Prompt
$path="OU=BulkUsers,DC=sheridan-ra,DC=local"
$username=Read-Host "Enter name"
$n=Read-Host "Enter Number"
$count=1..$n
foreach($i in $count)`
{`
    New-AdUser `
    -Name $username$i `
    -Path $path `
    -Enabled $True `
    -ChangePasswordAtLogon $true `
    -AccountPassword(ConvertTo-SecureString "P@ssword" -AsPlainText -force) `
    -PassThru `
}
#>

<#1.6 CSV import
$ADUsers = Import-Csv C:\Users\Administrator\Downloads\import_users.csv -Delimiter ","
foreach($User in $ADUsers)`
{`
    $Firstname = $User.firstname
    $Lastname = $User.lastname
    $Username = $User.username
    $Department = $User.department
    $Password = $User.password
    $OU = $User.ou
    
    if(Get-ADUser -F {SamAccountName -eq $Username})
    {
        Write-Warning "A user account $Username has already exist in Active Directory."
    }
    else
    {
        New-ADUser `
        -SamAccountName $Username `
        -UserPrincipalName "$Username@Sheridan-ra.local" `
        -Name "$Firstname $Lastname" `
        -GivenName $Firstname `
        -Surname $Lastname `
        -Enabled $True `
        -ChangePasswordAtLogon $True `
        -DisplayName "$Lastname, $Firstname" `
        -Department $Department `
        -Path $OU `
        -AccountPassword (convertto-securestring $Password -AsPlainText -Force)
    }
}
#>

<#1.7 create computer object
Test-NetConnection 192.168.10.13 -InformationLevel Detailed #windows10 client in fast server
Resolve-DnsName 192.168.10.13 #expose computer name
$computerName = "DESKTOP-NI90JJ8"
New-ADComputer `
-Name $computerName `
-SamAccountName $computerName `
-path "OU=NewComputers,DC=sheridan-ra,DC=local"
#>


<#1.8 import compObj from CSV
Resolve-DnsName 192.168.10.11 #expose srv01 name
Resolve-DnsName 192.168.10.13 #expose win10_client name

$File="C:\Users\Administrator\Downloads\import_computers.csv" # Specify the import CSV position.
$Path="OU=NewComputers,DC=sheridan-ra,DC=local" # Specify the path to the OU.
Import-Csv -Path $File | `
ForEach-Object `
{`
    New-ADComputer `
    -Name $_.ComputerName `
    -Path $Path `
    -Enabled $True `
}
#>

#2.1 Local PC to Domain Controller
$dc = "sheridan-ra.local" # Specify the domain to join.
$pw = "P@ssword" | ConvertTo-SecureString -asPlainText -Force # Specify the password for the domain admin.
$usr = "$dc\Administrator" # Specify the domain admin account.
$creds = New-Object System.Management.Automation.PSCredential($usr,$pw)
Add-Computer -DomainName $dc -Credential $creds -restart -force -verbose # Note that the computer will be restarted automatically.

