
# Script : Invoke-PowerHunt
# Module : analyze-services-badpath
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework. This checks for services running svchost.exe or dllhost.exe services from non-default directory.
# License: 3-clause BSD


# Look for svchost/dllhost not running out of c:\windows\system32
$AnalysisResult = $CollectedData | where { $_.pathname -like "*\svchost.exe*" -or $_.pathname -like "*\dllhost.exe*"} | where pathname -notlike "c:\windows\system32\*"

# Save result details
$AnalysisModuleFileName = $_.name -replace(".ps1",".csv")
$Time =  Get-Date -UFormat "%m/%d/%Y %R"
$AnalysisResult | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$AnalysisSubDir\Hunt-$AnalysisModuleFileName"

# Save result summary
$AnalysisModuleFileName = $_.name -replace(".ps1","-counts.csv")
$FinalOutput = $AnalysisResult | group pathname | Sort-Object count -Descending | select count,name 
$FinalOutput | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$AnalysisSubDir\Hunt-$AnalysisModuleFileName"

# Count instances
$InstanceCount = $FinalOutput | measure | select count -expandproperty count

# Save summary metrics
$null = $ModuleOutputSummary.Rows.Add("$ModuleType","$CollectionModuleName","$CollectionDataSource","$AnalysisModuleName","$AnalysisType","$InstanceCount")