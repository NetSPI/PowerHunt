
# Script : Invoke-PowerHunt
# Module : analyze-services-outlier-owner
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework.  This looks for unusual ownership of the executables run by the service.
# License: 3-clause BSD

$AnalysisModuleDesc = "Place holder description."


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

# Count affected computers 
$AnalysisModuleAffectedComputerCount = $FinalOutput | select PSComputerName -Unique | measure | select count -ExpandProperty count                    

# Save summary metrics
$null = $ModuleOutputSummary.Rows.Add("$ModuleType","$CollectionModuleName","$CollectionDataSource","$AnalysisModuleName","$AnalysisModuleDesc","$AnalysisType","$InstanceCount","$AnalysisModuleAffectedComputerCount")