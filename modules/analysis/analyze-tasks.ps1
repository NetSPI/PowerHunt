
# Script : Invoke-PowerHunt
# Module : analyze-tasks
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework.
# License: 3-clause BSD


# Save result summary
$AnalysisModuleFileName = $_.name -replace(".ps1","-counts.csv")
$CollectedData  | group PrincipalName | Sort-Object count -Descending | select count,name | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\Hunt-$AnalysisModuleFileName"
