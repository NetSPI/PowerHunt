
# Script : Invoke-PowerHunt
# Module : collect-environmental-variables
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework and collect connection information.
# License: 3-clause BSD


# Get list of environmental variables
$FinalOutput = Get-ChildItem env:

# Count instances
$InstanceCount = $FinalOutput | measure | select count -expandproperty count

# Save summary metrics
$null = $ModuleOutputSummary.Rows.Add("$ModuleName","NA","NA","$InstanceCount")

# Return data
$FinalOutput 