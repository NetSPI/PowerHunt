
# Script : Invoke-PowerHunt
# Module : collect-mapped-drives
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework and collect connection information.
# License: 3-clause BSD


# Get list of mapped drives
Get-WmiObject -ClassName Win32_MappedLogicalDisk
