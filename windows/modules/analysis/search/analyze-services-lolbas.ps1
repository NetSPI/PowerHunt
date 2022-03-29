
# Script : Invoke-PowerHunt
# Module : analyze-services-lolbas
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework. This filters for services that are running LOLBAS commonly used by threat actors.
# License: 3-clause BSD


# Import strings
$TargetStrings = gc .\windows\modules\lists\list-lolbas.txt

# Generate filter from keywords
$Filter = 'where {('
$TargetStrings |
foreach{
    $Filter = $Filter + '$_.pathname -like "*' + $_ + '*" -or '
}
$Filter = $Filter + '$_.pathname -like ""' + ")}"

# Build PS query
$PsQuery = '$CollectedData | ' +  $Filter

# Run PS query
$AnalysisResult = Invoke-Expression $PsQuery 

# Save result details
$AnalysisModuleFileName = $_.name -replace(".ps1",".csv")
$AnalysisResult | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$AnalysisSubDir\Hunt-$AnalysisModuleFileName"

# Save result summary
$AnalysisModuleFileName = $_.name -replace(".ps1","-counts.csv")
$FinalOutput = $AnalysisResult | group pathname | Sort-Object count -Descending | select count,name 
$FinalOutput | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$AnalysisSubDir\Hunt-$AnalysisModuleFileName"

# Count instances
$InstanceCount = $FinalOutput | measure | select count -expandproperty count

# Save summary metrics
$null = $ModuleOutputSummary.Rows.Add("$AnalysisModuleName","$ModuleType","$AnalysisType","$InstanceCount")