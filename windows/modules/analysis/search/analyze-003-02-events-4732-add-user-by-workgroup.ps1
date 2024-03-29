﻿
# Script : Invoke-PowerHunt
# Module : analyze-events-4732-add-user-by-workgroup
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework. This filters for user additions that have been made where the subject domain is "workgroup".  
#          In lab environments the appear to be associated with the addition of member from local system. However, testing need to be done to determine if group 
#          policy additions have the same profile.
# License: 3-clause BSD

$AnalysisModuleDesc = "Place holder description."

# Member add to local security group with subject of workgroup
$FinalOutput = $CollectedData  | where SubjectUserDomain -like "*workgroup*" | Where PrincipalName -notlike "*Domain Admins*"

# Save result details
$AnalysisModuleFileName = $_.name -replace(".ps1",".csv")
$Time =  Get-Date -UFormat "%m/%d/%Y %R"
$FinalOutput | Export-Csv -NoTypeInformation "$OutputDirectory\analysis\$AnalysisSubDir\Hunt-$AnalysisModuleFileName"

# Count instances
$InstanceCount = $FinalOutput | measure | select count -expandproperty count

# Count affected computers 
$AnalysisModuleAffectedComputerCount = $FinalOutput | select PSComputerName -Unique | measure | select count -ExpandProperty count                    

# Save summary metrics
$null = $ModuleOutputSummary.Rows.Add("$ModuleType","$CollectionModuleName","$CollectionDataSource","$AnalysisModuleName","$AnalysisModuleDesc","$AnalysisType","$InstanceCount","$AnalysisModuleAffectedComputerCount")
