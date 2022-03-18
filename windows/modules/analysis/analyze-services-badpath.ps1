
# Script : Invoke-HuntPersistPR
# Module : analyze-services-badpath
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework. This checks for services running svchost.exe or dllhost.exe services from non-default directory.
# License: 3-clause BSD


# Look for svchost/dllhost not running out of c:\windows\system32
$CollectedData | where { $_.pathname -like "*\svchost.exe*" -or $_.pathname -like "*\dllhost.exe*"} | where pathname -notlike "c:\windows\system32\*"