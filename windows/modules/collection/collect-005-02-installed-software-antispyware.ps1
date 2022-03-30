
# Script : Invoke-PowerHunt
# Module : collect-installed-software-antispyware
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework and collect connection information.
# License: 3-clause BSD


# Get registred security software
Get-WmiObject -Namespace ROOT/SecurityCenter2 -Class AntiSpywareProduct 
