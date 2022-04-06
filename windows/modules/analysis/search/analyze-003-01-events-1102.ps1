
# Script : Invoke-PowerHunt
# Module : analyze-events-1102-count
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework.
# License: 3-clause BSD

$AnalysisModuleDesc = "Place holder description."

# Save result summary
$AnalysisModuleFileName = $_.name -replace(".ps1","-counts.csv")
$FinalOutput = $CollectedData  | group PrincipalName | Sort-Object count -Descending | select count,name 
$FinalOutput | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$AnalysisSubDir\Hunt-$AnalysisModuleFileName"

# Count instances
$InstanceCount = $FinalOutput | measure | select count -expandproperty count

# Count affected computers 
$AnalysisModuleAffectedComputerCount = $FinalOutput | select PSComputerName -Unique | measure | select count -ExpandProperty count                    

# Save summary metrics
$null = $ModuleOutputSummary.Rows.Add("$ModuleType","$CollectionModuleName","$CollectionDataSource","$AnalysisModuleName","$AnalysisModuleDesc","$AnalysisType","$InstanceCount","$AnalysisModuleAffectedComputerCount")