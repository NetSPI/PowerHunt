# Script : Invoke-PowerHunt
# Module : collect-wmi-filters
# Version: 1.0
# Author : Scott Sutherland
# Author : Alexander Polce Leary 
# Summary: This is script is part of the PowerHunt framework.
# License: 3-clause BSD


# Get wmi filter information
Get-WmiObject -Namespace root/subscription -Class __EventFilter 
