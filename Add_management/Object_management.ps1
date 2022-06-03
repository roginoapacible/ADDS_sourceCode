Move-ADObject -Identity "WINSERVER01$" -TargetPath "CN=WIN10-CLIENT,CN=Computers,DC=sheridan-ra,DC=local"

Move-ADObject -Identity (Get-ADComputer "WINSERVER01").objectguid -TargetPath 'CN=Computers,DC=sheridan-ra,DC=local'