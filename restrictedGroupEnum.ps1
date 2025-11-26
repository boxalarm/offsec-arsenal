# To run this script, you must first import PowerView.ps1
# https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

# Uses PowerView cmdlets to enumerate any restricted groups plus the OUs and OU members
# that a restricted group GPO has been linked to

# Grab all restricted group GPOs
$result = Get-DomainGPOLocalGroup | Where-Object { $_.GPOType -like "*RestrictedGroups*" }

foreach ($gpo in $result) {
    $gpo # Output the typical result from Get-DomainGPOLocalGroup
    Write-Output "[+] $($gpo.GroupName) is a member of $($gpo.GroupMemberOf)`n"

	# Find all OUs that the GPO is linked to
    $gpoGuid = $gpo.GPOName
    $linkedOUs = Get-DomainOU | Where-Object { $_.gPLink -like "*$gpoGuid*" } | Select-Object name, distinguishedname
    
    foreach ($ou in $linkedOUs) {
		Write-Output "[+] The $($gpo.gpoDisplayName) GPO is linked to the $($ou.name) OU which has the following members:`n"
		    
		# List all members in the OUs that the GPO is linked to (skip first result - that is just the GPO itself)
        $ouMembers = Get-DomainObject -SearchBase $ou.distinguishedname | Select-Object -Skip 1 | Select-Object name, samaccounttype
				
        $formattedMembers = $ouMembers | Format-Table -AutoSize -Wrap | Out-String -Stream | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        $formattedMembers | ForEach-Object { Write-Host "  $_" }
    }
    Write-Output "`n----`n"
}
