
# Script : Invoke-HuntPersistPR
# Module : analyze-services-outlier-owner
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework.  This looks for unusual ownership of the executables run by the service.
# License: 3-clause BSD


# Filter out common owners
$CollectedData | where {($_.fileowner -notlike 'NT SERVICE\TrustedInstaller' -and $_.fileowner -notlike 'NT AUTHORITY\SYSTEM' -and $_.fileowner -notlike "BUILTIN\Administrators" -and $_.fileowner -notlike "")}