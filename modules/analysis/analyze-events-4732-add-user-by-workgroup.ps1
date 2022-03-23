
# Script : Invoke-PowerHunt
# Module : analyze-events-4732-add-user-by-workgroup
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework. This filters for user additions that have been made where the subject domain is "workgroup".  
#          In lab environments the appear to be associated with the addition of member from local system. However, testing need to be done to determine if group 
#          policy additions have the same profile.
# License: 3-clause BSD


# Member add to local security group with subject of workgroup
$AnalysisResult = $CollectedData  | where SubjectUserDomain -like "*workgroup*" | Where PrincipalName -notlike "*Domain Admins*"

# Save result details
$AnalysisModuleFileName = $_.name -replace(".ps1",".csv")
$Time =  Get-Date -UFormat "%m/%d/%Y %R"
$AnalysisResult | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\Hunt-$AnalysisModuleFileName"

# Save result summary
$AnalysisModuleFileName = $_.name -replace(".ps1","-counts.csv")
$AnalysisResult | group PrincipalName | Sort-Object count -Descending | select count,name | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\Hunt-$AnalysisModuleFileName"