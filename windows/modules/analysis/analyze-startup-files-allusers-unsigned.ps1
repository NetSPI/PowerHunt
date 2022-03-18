
# Script : Invoke-HuntPersistPR
# Module : analyze-startup-files-allusers-unsigned
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework. This checks startup files running unsigned binaries.
# License: 3-clause BSD


# Check for unsigned binaries
$CollectedData | where Authenticode -like "false" 

