# Script : Invoke-PowerHunt
# Module : collect-named-pipes
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework 
#          and is used to collect information from named pipes.
# License: 3-clause BSD


# Get named pipes
$FinalOutput = Get-ChildItem \\.\pipe\  | select name

# Count instances
$InstanceCount = $FinalOutput | measure | select count -expandproperty count

# Save summary metrics
$null = $ModuleOutputSummary.Rows.Add("$ModuleType","$ModuleName","NA","NA","NA","$InstanceCount")

# Return data
$FinalOutput 
