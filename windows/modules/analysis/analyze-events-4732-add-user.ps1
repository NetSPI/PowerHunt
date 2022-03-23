
# Script : Invoke-PowerHunt
# Module : analyze-events-4732-add-user
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework.
# License: 3-clause BSD


# Potential Computer account added to group
$AnalysisResult = $CollectedData | where PrincipalName -like "*`$"

# Save result details
$AnalysisModuleFileName = $_.name -replace(".ps1",".csv")
$AnalysisResult | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\Hunt-$AnalysisModuleFileName"

# Save result summary
$AnalysisModuleFileName = $_.name -replace(".ps1","-counts.csv")
$AnalysisResult | group PrincipalName | Sort-Object count -Descending | select count,name | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\Hunt-$AnalysisModuleFileName"