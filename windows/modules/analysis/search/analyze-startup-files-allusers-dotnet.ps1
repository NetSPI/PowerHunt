
# Script : Invoke-PowerHunt
# Module : analyze-startup-files-allusers-dotnet
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework. This filters for dotnet assemblies running out of the all users startup folder.
# License: 3-clause BSD


# .net assemblies
$AnalysisResult = $CollectedData  | where dotnet -like "true"

# Save result details
$AnalysisModuleFileName = $_.name -replace(".ps1",".csv")
$Time =  Get-Date -UFormat "%m/%d/%Y %R"
$AnalysisResult | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$AnalysisSubDir\Hunt-$AnalysisModuleFileName"

# Save result summary
$AnalysisModuleFileName = $_.name -replace(".ps1","-counts.csv")
$FinalOutput = $AnalysisResult | group FilePath | Sort-Object count -Descending | select count,name 
$FinalOutput | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$AnalysisSubDir\Hunt-$AnalysisModuleFileName"

# Count instances
$InstanceCount = $FinalOutput | measure | select count -expandproperty count

# Save summary metrics
$null = $ModuleOutputSummary.Rows.Add("$ModuleName","$AnalysisModuleName","$ModuleType","$AnalysisType","$InstanceCount")