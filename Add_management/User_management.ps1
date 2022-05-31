###User Management--------------------------------------
#check current users in the domain
Get-ADUser -Filter * #-SearchBase "OU=Finance,OU=UserAccounts,DC=FABRIKAM,DC=COM"

#new user(disabled by default)
New-ADUser user1 -UserPrincipalName user1@sheridan-ra.local

#check user properties
Get-ADUser B.Johnson

#set password(individual)
Set-ADAccountPassword -Identity user1
#if empty press enter
#then set the desired password for that user

#Enable User account
Enable-ADAccount -Identity user1

#confirm enabled account
Get-ADUser user1 -Properties enabled

#create user to an OU(ask a password)
New-ADUser -Name usertest -UserPrincipalName usertest@sheridan-ra.local -Path "OU=BulkUsers,DC=sheridan-ra,DC=local" -AccountPassword(Read-Host -AsSecureString "AccountPassword") -PassThru | Enable-ADAccount

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
Remove-ADUser -Identity B.Johnson
Get-ADUser -Filter * -SearchBase "OU=NewUsers,DC=sheridan-ra,DC=local"
