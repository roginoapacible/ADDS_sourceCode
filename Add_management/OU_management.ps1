###Organization management-------

#Get all of the OUs in a domain
Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Format-Table Name, DistinguishedName -a

#Create OU(option for accidental delete)..important to set the path

New-ADOrganizationalUnit "CSV_Users" -Path "DC=sheridan-ra,DC=local" #no protect
New-ADOrganizationalUnit "ChildOU" -Path "OU=OU-test,DC=sheridan-ra,dc=local" -ProtectedFromAccidentalDeletion $False #$true

#set OU protections
Set-ADOrganizationalUnit -Identity "OU=OU-test,DC=sheridan-ra,dc=local" -ProtectedFromAccidentalDeletion $False #$true

#delete OU
Remove-ADOrganizationalUnit -Identity "OU=OU-test,DC=sheridan-ra,dc=local" #$true
