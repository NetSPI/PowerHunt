
# Script : Invoke-PowerHunt
# Module : collect-environmental-paths
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework and collect connection information.
# License: 3-clause BSD


# Get list of environmental paths
$Env:Path |
foreach {
    
    $EnvPath = $_.split(",;")
    $EnvPath | 
    Foreach{

        # Verify folder exists
        $PathExists = Test-Path "$_"

        if($PathExists -eq $true){
            
            # Get folder info
            $FileInfo           =  Get-Item "$_"
            $FileOwner          =  $FileInfo.GetAccessControl().Owner
            $FileCreationTime   =  $FileInfo.CreationTime
            $FileLastWriteTime  =  $FileInfo.LastWriteTime
            $FileLastAccessTime =  $FileInfo.LastAccessTime
        }

        # Create new object
        $Object = New-Object PSObject
        $Object | add-member EnvPath              $_
        $Object | add-member PathExists           $PathExists 
        $Object | add-member FileOwner            $FileOwner 
        $Object | add-member FileCreationTime     $FileCreationTime 
        $Object | add-member FileLastWriteTime    $FileLastWriteTime
        $Object | add-member FileLastAccessTime   $FileLastAccessTime
        $Object
    }
}