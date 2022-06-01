###ADDS setup----------
#add windows feature
Add-WindowsFeature ad-domain-services -IncludeManagementTools #ad-domain-services



#no RSAT
Add-WindowsFeature RSAT-role-tools -IncludeAllSubFeature



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

get-windowsfeature 

