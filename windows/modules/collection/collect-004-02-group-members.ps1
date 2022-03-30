
# Script : Invoke-PowerHunt
# Module : collect-group-members
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework and collect connection information.
# License: 3-clause BSD


# Get list of group members
Get-LocalGroup |
foreach{
    $GroupName = $_.name
    Get-LocalGroupMember -Group $_.name |
    foreach {
        
        $PrincipalType    = $_.ObjectClass
        $PrincipalName  = $_.name
        $PrincipalSource = $_.PrincipalSource

        # Create new object to return
        $Object = New-Object PSObject
	    $Object | add-member Group       		  $GroupName
	    $Object | add-member MemberType  		  $PrincipalType
        $Object | add-member MemberName          $PrincipalName
        $Object | add-member MemberSource         $PrincipalSource   
        $Object 
    }
}
