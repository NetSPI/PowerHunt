
# Script : Invoke-HuntPersistPR
# Module : analyze-startup-registry-run-unsigned
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework. This checks registry that are running unsigned binaries.
# License: 3-clause BSD


# Uunsigned binaries
$CollectedData | where Authenticode -like "false" 

