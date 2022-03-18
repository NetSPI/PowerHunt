
# Script : Invoke-HuntPersistPR
# Module : analyze-named-pipes-known-bad
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework. This filters for named pipes commonly associated with offensive security tools.
# License: 3-clause BSD

# Create list of target keywords
$TargetStrings =      @('psexecsvc',
                        'remcom',
                        'csexecsvc',
			            'csexec',
			            'psexec',
			            'paexec',
                        'gruntsvc',
			            'msagent',
                        'msf-pipe'
						)

# Generate filter from keywords
$Filter = 'where {('
$TargetStrings |
foreach{
    $Filter = $Filter + '$_.Name -like "*' + $_ + '*" -or '
}
$Filter = $Filter + '$_.Name -like "not a thing"' + ")}"

# Build PS query
$PsQuery = '$CollectedData | where name -notlike "" | ' +  $Filter

# Run PS query
Invoke-Expression $PsQuery