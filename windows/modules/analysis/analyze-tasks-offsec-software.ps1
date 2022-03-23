
# Script : Invoke-PowerHunt
# Module : analyze-tasks-offsec-software
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework. This filters for tasks running LOLBAS commonly used by threat actors.
# License: 3-clause BSD


# Import strings
$TargetStrings = gc .\windows\modules\lists\list-lolbas.txt

# Generate filter from keywords
$Filter = 'where {('
$TargetStrings |
foreach{
    $Filter = $Filter + '$_.FilePath -like "*' + $_ + '*" -or '
}
$Filter = $Filter + '$_.FilePath -like ""' + ")}"

# Build PS query
$PsQuery = '$CollectedData | ' +  $Filter

# Run PS query
$AnalysisResult = Invoke-Expression $PsQuery 

# Save result details
$AnalysisModuleFileName = $_.name -replace(".ps1",".csv")
$Time =  Get-Date -UFormat "%m/%d/%Y %R"
$AnalysisResult | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\Hunt-$AnalysisModuleFileName"

# Save result summary
$AnalysisModuleFileName = $_.name -replace(".ps1","-counts.csv")
$AnalysisResult | group FilePath | Sort-Object count -Descending | select count,name | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\Hunt-$AnalysisModuleFileName"



