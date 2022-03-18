
# Script : Invoke-HuntPersistPR
# Module : analyze-services-unsigned
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework. This checks services running unsigned binaries.
# License: 3-clause BSD


# Windows services running unsigned binaries
$CollectedData | where Authenticode -like "false" 