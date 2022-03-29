
# Script : Invoke-PowerHunt
# Module : analyze-connections-process-paths
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework.
# License: 3-clause BSD


# Save result summary
$AnalysisModuleFileName = $_.name -replace(".ps1","ProcessPath-counts.csv")
$FinalOutput = $CollectedData  | group FilePath | Sort-Object count -Descending | select count,name 
$FinalOutput | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$AnalysisSubDir\Hunt-$AnalysisModuleFileName"

# Count instances
$InstanceCount = $FinalOutput | measure | select count -expandproperty count

# Save summary metrics
$null = $ModuleOutputSummary.Rows.Add("$ModuleName","$AnalysisModuleName","$ModuleType","$AnalysisType","$InstanceCount")
