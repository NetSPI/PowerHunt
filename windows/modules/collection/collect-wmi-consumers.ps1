# Script : Invoke-PowerHunt
# Module : collect-wmi-consumers
# Version: 1.0
# Author : Scott Sutherland
# Author : Alexander Polce Leary 
# Summary: This is script is part of the PowerHunt framework.
# License: 3-clause BSD


# Get wmi consumer information
$FinalOutput = Get-WmiObject -Namespace root/subscription -Class __EventConsumer

# Count instances
$InstanceCount = $FinalOutput | measure | select count -expandproperty count

# Save summary metrics
$null = $ModuleOutputSummary.Rows.Add("$ModuleName","NA","NA","$InstanceCount")

# Return data
$FinalOutput 
