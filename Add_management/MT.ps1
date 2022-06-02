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

#1.7 create computer object
Test-NetConnection 192.168.10.13 -InformationLevel Detailed #windows10 client in fast server
Resolve-DnsName 192.168.10.13 #expose computer name
$computerName = "WIN-GDO4MDI2UCO"
New-ADComputer `
-Name $computerName `
-SamAccountName $computerName `
-path "OU=NewComputers,DC=sheridan-ra,DC=local"



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

<#2.1 Local PC to Domain Controller
$dc = "sheridan-ra.local" # Specify the domain to join.
$pw = "P@ssword" | ConvertTo-SecureString -asPlainText -Force # Specify the password for the domain admin.
$usr = "$dc\administrator" # Specify the domain admin account.
$creds = New-Object System.Management.Automation.PSCredential($usr,$pw)
add-computer -DomainName $dc -credential $creds -restart -force -verbose # Note that the computer will be restarted automatically
#>

<#2.2 remote to DC
Resolve-DnsName 192.168.10.13 #expose remote hostname
$dc = "sheridan-ra.local"
$pw = "P@ssword" | ConvertTo-SecureString -asPlainText -Force
$usr = "$dc\administrator"
$pc = "DESKTOP-NI90JJ8" # Specify the computer that should be joined to the domain.
$creds = New-Object System.Management.Automation.PSCredential($usr,$pw)
Add-Computer -ComputerName $pc -LocalCredential $pc\vmadmin -DomainName $dc -Credential $creds -Verbose -Restart -Force
#>

<#2.3 join multiple remote from dc
$dc = "Sheridan-ra.local"
$pw = "P@ssword" | ConvertTo-SecureString -asPlainText -Force
$usr = "$dc\Administrator"
$creds = New-Object System.Management.Automation.PSCredential($usr,$pw)
$pcname = 'WIN-GDO4MDI2UCO','DESKTOP-NI90JJ8'#specify computer name
$pcuser = 'Administrator','vmadmin' # Specify computers username
$count = $pcname.Count
for($i = 0; $i -le $count) 
{
     $a = $pcname[$i]
     $b = $pcuser[$i]
    Add-Computer -ComputerName $a -LocalCredential $a\$b -DomainName $dc -credential $creds -Verbose -Restart -Force 
    $i++
}


<#Get-WmiObject -ComputerName WIN-GDO4MDI2UCO -Class win32_OperatingSystem
Get-WmiObject -ComputerName 192.168.10.13 -Class win32_OperatingSystem -Credential $Credential
#>

<#2.4 join multiple computers from domain using text
$dc = "Sheridan-ra.local"
$pw = "P@ssword" | ConvertTo-SecureString -asPlainText -Force
$usr = "$dc\Administrator"
$pcname = Get-Content -Path C:\Users\Administrator\Downloads\import_computers.txt# Specify the path to the computers list. `
$creds = New-Object System.Management.Automation.PSCredential($usr,$pw)
$pcuser = 'Administrator','vmadmin' # Specify computers username
$count = $pcname.Count
for($i = 0; $i -le $count) 
{
     $a = $pcname[$i]
     $b = $pcuser[$i]
    Add-Computer -ComputerName $a -LocalCredential $a\$b -DomainName $dc -credential $creds -Verbose -Restart -Force 
    $i++
}
#>

<#2.5 remove computers remotely domain-
$dc = "Sheridan-ra.local"
$pw = "P@ssword" | ConvertTo-SecureString -asPlainText -Force
$usr = "$dc\Administrator"
$pc = "DESKTOP-NI90JJ8"
$creds = New-Object System.Management.Automation.PSCredential($usr,$pw)
Remove-Computer -ComputerName $pc -LocalCredential $pc\vmadmin -Credential $creds -restart -force -passthru -Verbose
#Restart-Computer -computername "DESKTOP-NI90JJ8" -Force
#>

<#3.1 rename a computer(must be online and connected to DC)
get-adcomputer -Filter * | Format-Table name, DistinguishedName #expose computer name in the domain
Rename-Computer -ComputerName "DESKTOP-NI90JJ8" -NewName "win10-Client" -DomainCredential sheridan-ra\Administrator -Force -restart -Verbose
#>

<#3.2 joining computer to the domain
Resolve-DnsName 192.168.10.11 #expose remote hostname
$NewComputerName = "winServer01" # Specify the new computer name. 
$DC = "sheridan-ra.local" # Specify the domain to join. 
$Path = "OU=ServerPC,DC=sheridan-ra,DC=local" # Specify the path to the OU where to put the computer account in the domain. 
Add-Computer -computername "WIN-GDO4MDI2UCO" -DomainName $DC -DomainCredential $DC\administrator -LocalCredential .\administrator -OUPath $Path -NewName $NewComputerName -Restart -Force -verbose
#>

<#4 Reseting a computer account
get-adcomputer -Filter 'Name -like "*"' | Format-Table Name, DistinguishedName -a #search computers
$pc = read-host -Prompt “Input computer name to reset“ # Specify the computer name. 
$pw = read-host -Prompt “Input random characters for temp password“ -AsSecureString # Specify the password. 
Get-ADComputer $pc | Set-ADAccountPassword -NewPassword:$pw -Reset:$true -Verbose
Restart-Computer -computername $pc -credential $pc\ -Force -Verbose
#>