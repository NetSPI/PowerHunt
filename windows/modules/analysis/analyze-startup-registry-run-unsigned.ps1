
# Script : Invoke-HuntPersistPR
# Module : analyze-startup-registry-run-unsigned
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework. This checks registry that are running unsigned binaries.
# License: 3-clause BSD


# Uunsigned binaries
$AnalysisResult = $CollectedData | where Authenticode -like "false" 

# Save result details
$AnalysisModuleFileName = $_.name -replace(".ps1",".csv")
$Time =  Get-Date -UFormat "%m/%d/%Y %R"
$AnalysisResult | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$TargetDomain-$AnalysisModuleFileName"

# Save result summary
$AnalysisModuleFileName = $_.name -replace(".ps1","-counts.csv")
$AnalysisResult | group FilePath | Sort-Object count -Descending | select count,name | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$TargetDomain-$AnalysisModuleFileName"
