
# Script : PowerHunt
# Module : analyze-connections
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework.
# License: 3-clause BSD


# Save result summary
$AnalysisModuleFileName = $_.name -replace(".ps1","RemoteAddress-counts.csv")
$CollectedData  | group RemoteAddress | Sort-Object count -Descending | select count,name | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\Hunt-$AnalysisModuleFileName"

# Save result summary
$AnalysisModuleFileName = $_.name -replace(".ps1","FilePath-counts.csv")
$CollectedData  | group FilePath | Sort-Object count -Descending | select count,name | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\Hunt-$AnalysisModuleFileName"
