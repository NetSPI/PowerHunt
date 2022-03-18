
# Script : Invoke-HuntPersistPR
# Module : analyze-startup-files-allusers-dotnet
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework. This filters for dotnet assemblies running out of the all users startup folder.
# License: 3-clause BSD


# .net assemblies
$CollectedData  | where dotnet -like "true"

