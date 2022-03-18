
# Script : Invoke-HuntPersistPR
# Module : analyze-events-4732-add-user-computer
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework. This filters for computer accounts they may have been added to the local administrators group.
# License: 3-clause BSD

# Potential Computer account added to group
$CollectedData | where PrincipalName -like "*`$"
