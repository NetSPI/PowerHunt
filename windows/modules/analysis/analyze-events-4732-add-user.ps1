
# Script : Invoke-HuntPersistPR
# Module : analyze-events-4732-add-user
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework.
# License: 3-clause BSD


# Potential Computer account added to group
$CollectedData | where PrincipalName -like "*`$"
