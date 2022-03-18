
# Script : Invoke-HuntPersistPR
# Module : analyze-startup-files-allusers-outlier-file-owner
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework.  This looks for unusual ownership of the executables run out of all users startup folders.
# License: 3-clause BSD


# Filter out common owners
$AnalysisResult = $CollectedData | where {($_.fileowner -notlike 'NT SERVICE\TrustedInstaller' -and $_.fileowner -notlike 'NT AUTHORITY\SYSTEM' -and $_.fileowner -notlike "BUILTIN\Administrators" -and $_.fileowner -notlike "")}

# Save result details
$AnalysisModuleFileName = $_.name -replace(".ps1",".csv")
$Time =  Get-Date -UFormat "%m/%d/%Y %R"
$AnalysisResult | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$TargetDomain-$AnalysisModuleFileName"

# Save result summary
$AnalysisModuleFileName = $_.name -replace(".ps1","-counts.csv")
$AnalysisResult | group FileOwner | Sort-Object count -Descending | select count,name | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$TargetDomain-$AnalysisModuleFileName"