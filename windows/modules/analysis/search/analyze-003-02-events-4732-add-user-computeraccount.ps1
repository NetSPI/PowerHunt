﻿
# Script : Invoke-PowerHunt
# Module : analyze-events-4732-add-user-computer
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework. This filters for computer accounts they may have been added to the local administrators group.
# License: 3-clause BSD

$AnalysisModuleDesc = "Place holder description."

# Potential Computer account added to group
$FinalOutput = $CollectedData | where PrincipalName -like "*`$"

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
