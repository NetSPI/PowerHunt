
# Script : Invoke-HuntPersistPR
# Module : analyze-events-4732-add-user-computer
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework. This filters for computer accounts they may have been added to the local administrators group.
# License: 3-clause BSD

# Potential Computer account added to group
$AnalysisResult = $CollectedData | where PrincipalName -like "*`$"

# Save result details
$AnalysisModuleFileName = $_.name -replace(".ps1",".csv")
$Time =  Get-Date -UFormat "%m/%d/%Y %R"
$AnalysisResult | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$TargetDomain-$AnalysisModuleFileName"

# Save result summary
$AnalysisModuleFileName = $_.name -replace(".ps1","-counts.csv")
$AnalysisResult | group PrincipalName | Sort-Object count -Descending | select count,name | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$TargetDomain-$AnalysisModuleFileName"
