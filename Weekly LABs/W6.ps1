#Verify the network configuration is correct
Get-NetIPAddress -InterfaceIndex 6

#Identify the network path between hosts
Test-NetConnection -TraceRoute 192.168.10.11 #srv01

#See if the remote host responds
Test-Connection 192.168.10.11   #srv01

#Test the service on a remote host
Test-NetConnection 192.168.10.11 -InformationLevel "Detailed"  #srv01

#See if the default gateway responds
Test-NetConnection 192.168.10.1 -InformationLevel Detailed