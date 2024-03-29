﻿
# Script : Invoke-PowerHunt
# Module : analyze-events-4732-add-user-remotecomputer
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework. This filters for instances of logs that show the member was added from a remote computer.
#          a.k.a the local system name does not match the subject used to add the member to the group.
# License: 3-clause BSD

$AnalysisModuleDesc = "Place holder description."


# The local system name does not match the subject used to add the member to the group.
$FinalOutput = $CollectedData | 
foreach {
    
    # Check if a computer account was used to add the user to the group
    if ($_.SubjectUser -like "*`$"){
        
        # Parse computer and computer account
        $ComputerName = $_.ComputerName.split(".")[0]
        $ComputerAccount = $_.SubjectUser.split('$')[0]

        # Check if the remote computer and computer account used to add account match
        if($ComputerName -notlike $ComputerAccount){
            "rare we have a MISmatch"
            $_
        }
    }
}

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
