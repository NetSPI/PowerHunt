
# Script : Invoke-HuntPersistPR
# Module : analyze-startup-registry-run-badpath
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework. This checks for reg run keys running svchost.exe or dllhost.exe services from non-default directory.
# License: 3-clause BSD


# Look for svchost/dllhost not running out of c:\windows\system32
$AnalysisResult = $CollectedData | where { $_.FilePath -like "*\svchost.exe*" -or $_.FilePath -like "*\dllhost.exe*"} | where pathname -notlike "c:\windows\system32\*"

# Save result details
$AnalysisModuleFileName = $_.name -replace(".ps1",".csv")
$Time =  Get-Date -UFormat "%m/%d/%Y %R"
$AnalysisResult | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$TargetDomain-$AnalysisModuleFileName"

# Save result summary
$AnalysisModuleFileName = $_.name -replace(".ps1","-counts.csv")
$AnalysisResult | group FilePath | Sort-Object count -Descending | select count,name | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$TargetDomain-$AnalysisModuleFileName"