###ADDS setup----------
#add windows feature
Add-WindowsFeature ad-domain-services -IncludeManagementTools #ad-domain-services

#heck windows feature
get-windowsfeature -name *AD*

#promote to domain controller
#Step3
install-addsforest -domainname sheridan-ra.local
#will ask for safemode admin password

#1.2 promote to domain controller
#default is Y or yes

#check domain controller connected to the system
Get-ADDomainController -discover
###------------------------------

###Organization management-------

#Get all of the OUs in a domain
Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Format-Table Name, DistinguishedName -A

#Create OU(option for accidental delete)..important to set the path

New-ADOrganizationalUnit "ChildOU" -Path "OU=OU-test,DC=sheridan-ra,dc=local" #no protect
New-ADOrganizationalUnit "ChildOU" -Path "OU=OU-test,DC=sheridan-ra,dc=local" -ProtectedFromAccidentalDeletion $False #$true

#set OU protections
Set-ADOrganizationalUnit -Identity "OU=OU-test,DC=sheridan-ra,dc=local" -ProtectedFromAccidentalDeletion $False #$true

#delete OU
Remove-ADOrganizationalUnit -Identity "OU=OU-test,DC=sheridan-ra,dc=local" -Confirm $False #$true

###User Management--------------------------------------

#check current users in the domain
Get-ADUser -Filter * #-SearchBase "OU=Finance,OU=UserAccounts,DC=FABRIKAM,DC=COM"

#new user(disabled by default)
New-ADUser user1 -UserPrincipalName user1@sheridan-ra.local

#@@@@ create new user full
New-ADUser -Name "Jack Robinson" -GivenName "Jack" -Surname "Robinson" -SamAccountName 
"J.Robinson" -UserPrincipalName "J.Robinson@sheridan-ra.local" <#-Path 
"OU=Managers,DC=enterprise,DC=com"#> -AccountPassword(Read-Host -AsSecureString "UserPassword") -Enabled $true

#@@@@ bulk user create(defaultpath)
#$path="OU=IT,DC=enterprise,DC=com"
$username="PW-student_"
$count=1..5
foreach ($i in $count)
{ New-AdUser -Name $username$i <#-Path $path#> -Enabled $True -ChangePasswordAtLogon $true `
-AccountPassword (ConvertTo-SecureString "P@ssword" -AsPlainText -force) -passThru }

#@@@@ bulk user create(defaultpath), Input specified
#$path="OU=IT,DC=enterprise,DC=com"
$username=Read-Host "Enter name"
$n=Read-Host "Enter Number"
$count=1..$n
foreach ($i in $count)
{ New-AdUser -Name $username$i <#-Path $path#> -Enabled $True -ChangePasswordAtLogon $true `
-AccountPassword (ConvertTo-SecureString "P@ssword" -AsPlainText -force) -passThru }

#@@@@ import from csv. Col firstname,lastname,user,department,password,OU path


#check user properties
Get-ADUser user1

#set password(individual)
Set-ADAccountPassword -Identity user1
#if empty press enter
#then set the desired password for that user

#Enable User account
Enable-ADAccount -Identity user1

#confirm enabled account
Get-ADUser user1 -Properties enabled

#create user to an OU(ask a password)
New-ADUser -Name user1 -UserPrincipalName user1@sheridan-ra.local -Path "OU=OU-test,DC=sheridan-ra,dc=local" -AccountPassword(Read-Host -AsSecureString "AccountPassword") -PassThru | Enable-ADAccount

#check specific user and its properties
Get-ADUser -Identity user1 -Properties department

#set properties for the specific user
Set-ADUser user1 -Department Administration
Get-ADUser -Identity user1 -Properties department

#search list of user
Get-ADUser -Filter * <#path#> -SearchBase "OU=OU-test,DC=sheridan-ra,dc=local" | Format-List name

#search list of user then set properties
Get-ADUser -Filter * <#path#> -SearchBase "OU=OU-test,DC=sheridan-ra,dc=local" | Set-ADUser -Department Administration

#move users to OU(set spefic)
Get-ADUser -Filter * | Move-ADObject -TargetPath 'OU=OU-test,DC=sheridan-ra,dc=local'

#remove specific user
Remove-ADUser -Identity user1
