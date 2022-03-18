# Script : Invoke-HuntPersistPR
# Module : collect-process
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework and collect process information.
# License: 3-clause BSD


# Collect process list
Get-WMIObject Win32_Process | Select ProcessId,description, commandline,creationdate
