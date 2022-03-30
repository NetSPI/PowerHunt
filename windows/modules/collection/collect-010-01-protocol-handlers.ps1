# Script : Invoke-PowerHunt
# Module : collect-protocol-handlers
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework.
# License: 3-clause BSD


# Create datatable for output
$null = $DataTable = New-Object System.Data.DataTable;
$null = $DataTable.Columns.Add("key");
$null = $DataTable.Columns.Add("path");

# Get protocol handlers
foreach ($Key in Get-ChildItem Microsoft.PowerShell.Core\Registry::HKEY_CLASSES_ROOT)
{ 
    $Path = $Key.PSPath + '\shell\open\command';
    $HasURLProtocol = $Key.Property -contains 'URL Protocol';

    if(($HasURLProtocol) -and (Test-Path $Path)){
        $CommandKey = Get-Item $Path;
        $ProtBin = $CommandKey.GetValue("")
        $ProtKey = $Key.Name.SubString($Key.Name.IndexOf('\') + 1)
        $null = $DataTable.Rows.Add($ProtKey,$ProtBin)
    }
}   

# Get protocol handlers
$DataTable