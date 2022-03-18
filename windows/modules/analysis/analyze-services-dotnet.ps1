
# Script : Invoke-HuntPersistPR
# Module : analyze-services-dotnet
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework. This filters for Windows services running dotnet assemblies.
# License: 3-clause BSD

# Windows services running .net assemblies
$CollectedData  | where dotnet -like "true"