
# Script : Invoke-PowerHunt
# Module : analyze-startup-registry-run-outlier-owner
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework.  This looks for unusual ownership of the executables run out of registry run keys.
# License: 3-clause BSD


# Filter out common owners
$AnalysisResult = $CollectedData | where {($_.fileowner -notlike 'NT SERVICE\TrustedInstaller' -and $_.fileowner -notlike 'NT AUTHORITY\SYSTEM' -and $_.fileowner -notlike "BUILTIN\Administrators" -and $_.fileowner -notlike "")}

# Save result details
$AnalysisModuleFileName = $_.name -replace(".ps1",".csv")
$Time =  Get-Date -UFormat "%m/%d/%Y %R"
$AnalysisResult | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$AnalysisSubDir\Hunt-$AnalysisModuleFileName"

# Save result summary
$AnalysisModuleFileName = $_.name -replace(".ps1","-counts.csv")
$FinalOutput = $AnalysisResult | group FileOwner | Sort-Object count -Descending | select count,name 
$FinalOutput | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$AnalysisSubDir\Hunt-$AnalysisModuleFileName"

# Count instances
$InstanceCount = $FinalOutput | measure | select count -expandproperty count

# Save summary metrics
$null = $ModuleOutputSummary.Rows.Add("$ModuleType","$CollectionModuleName","$CollectionDataSource","$AnalysisModuleName","$AnalysisType","$InstanceCount")
