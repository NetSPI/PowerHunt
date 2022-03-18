
# Script : Invoke-HuntPersistPR
# Module : analyze-startup-files-allusers-lolbas
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework. This filters for LOLBAS commonly used by threat actors running out of the all users startup folder.
# License: 3-clause BSD


# Import strings
$TargetStrings = gc .\windows\modules\lists\list-lolbas.txt

# Generate filter from keywords
$Filter = 'where {('
$TargetStrings |
foreach{
    $Filter = $Filter + '$_.FilePath -like "*' + $_ + '*" -or '
}
$Filter = $Filter + '$_.FilePath -like ""' + ")}"

# Build PS query
$PsQuery = '$CollectedData | ' +  $Filter

# Run PS query
Invoke-Expression $PsQuery 

