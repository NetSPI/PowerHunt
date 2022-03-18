
# Script : Invoke-HuntPersistPR
# Module : analyze-tasks-dotnet
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework. This filters for tasks running dotnet assemblies.
# License: 3-clause BSD


# .net assemblies
$CollectedData  | where dotnet -like "true"

