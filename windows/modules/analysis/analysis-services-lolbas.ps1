
# Script : Invoke-HuntPersistPR
# Module : analysis-services-lolbas
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework.
# License: 3-clause BSD

# //////////////////////////////
# Identify lolbas
# //////////////////////////////

# Create a keyword list for lolbas
$KeywordsLolBas =  @('te.exe',
					'cmd.exe ',
					'powershell.exe',
					'wmic.exe',
					'cscript.exe',
					'wscript.exe',
					'msbuild.exe',
					'installutil.exe',
					'certutil.exe',
					'rundll32.exe',
					'sc.exe',
					'bitsadmin.exe ',
					'regasm.exe',
					'regsvcs.exe',
					'csc.exe',
					'java.exe',
					'reg.exe',
					'msiexec.exe',
					'remote.exe ',
					'cscript.exe',
					'netsh.exe',
					'mshta.exe',
					'shell32.exe'
					)

# Generate filter from keywords
$Filter = 'where {('
$KeywordsLolBas |
foreach{
    $Filter = $Filter + '$_.pathname -like "*' + $_ + '*" -or '
}
$Filter = $Filter + '$_.pathname -like ""' + ")}"

# Build PS query
$PsQuery = '$CollectedData | ' +  $Filter

# Run PS query
Invoke-Expression $PsQuery 
