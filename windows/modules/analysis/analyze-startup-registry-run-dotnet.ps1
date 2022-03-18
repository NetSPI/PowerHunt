
# Script : Invoke-HuntPersistPR
# Module : analyze-startup-registry-run-dotnet
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework. This filters for registry run keys running dotnet assemblies.
# License: 3-clause BSD


# .net assemblies
$CollectedData  | where dotnet -like "true"

