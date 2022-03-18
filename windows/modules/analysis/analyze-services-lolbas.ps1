
# Script : Invoke-HuntPersistPR
# Module : analyze-services-lolbas
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the Invoke-HuntPersistPR framework. This filters for services that are running LOLBAS commonly used by threat actors.
# License: 3-clause BSD


# Import strings
$TargetStrings = gc .\windows\modules\lists\list-lolbas.txt

# Generate filter from keywords
$Filter = 'where {('
$TargetStrings |
foreach{
    $Filter = $Filter + '$_.pathname -like "*' + $_ + '*" -or '
}
$Filter = $Filter + '$_.pathname -like ""' + ")}"

# Build PS query
$PsQuery = '$CollectedData | ' +  $Filter

# Run PS query
Invoke-Expression $PsQuery 