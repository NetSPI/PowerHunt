
# Script : Invoke-PowerHunt
# Module : collect-network-interfaces
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework and collect connection information.
# License: 3-clause BSD


# Get adapters
$AdapterInfo = Get-NetAdapter | Select name, InterfaceDescription, ifIndex, Status, MacAddress, LinkSpeed

# Get policy and IP information
$FinalOutput = $AdapterInfo |
foreach{

    # Set adapter variablse
    $AdapterName      = $_.name
    $Status           = $_.status
    $MacAddress       = $_.macaddress
    $LinkSpeed        = $_.linkspeed    
    $ifIndex          = $_.ifIndex

    # Get IP information
    $IPInfo = Get-NetAdapter | Get-NetIPAddress | select IPAddress, InterfaceIndex,InterfaceAlias,AddressFamily,Type,PrefixLength,Policy  |  where InterfaceAlias -like $_.name 
    $IPInfo | 
    Foreach {

        # Setup IP information variables
        $IpAddress        = $_.IPAddress
        $AddressFamily    = $_.AddressFamily
        $Type             = $_.Type
        $PrefixLength     = $_.PrefixLength
        $Policy          =  $_.Policy

        # Get policy information
        $ProfileInfo = Get-NetConnectionProfile | select Name,InterfaceIndex,InterfaceAlias,NetworkCategory,IPv4Connectivity,IPv6Connectivity |  where InterfaceAlias -like $AdapterName

        # Create new object to return
        $Object = New-Object PSObject
        $Object | add-member AdapterName      $AdapterName
        $Object | add-member Status           $status
        $Object | add-member MacAddress       $macaddress
        $Object | add-member IpAddress        $IPAddress
        $Object | add-member AddressFamily    $AddressFamily
        $Object | add-member Type             $Type
        $Object | add-member PrefixLength     $PrefixLength
        $Object | add-member Policy           $Policy
        $Object | add-member LinkSpeed        $linkspeed
        $Object | add-member DnsSuffix        $ProfileInfo.name
        $Object | add-member ifIndex          $ifIndex
        $Object | add-member InterfaceAlias   $ProfileInfo.InterfaceAlias
        $Object | add-member NetworkCategory  $ProfileInfo.NetworkCategory 
        $Object | add-member IPv4Connectivity $ProfileInfo.IPv4Connectivity
        $Object | add-member IPv6Connectivity $ProfileInfo.IPv6Connectivity

        $Object
    }
  }

# Count instances
$InstanceCount = $FinalOutput | measure | select count -expandproperty count

# Save summary metrics
$null = $ModuleOutputSummary.Rows.Add("$ModuleName","NA","NA","$InstanceCount")

# Return data
$FinalOutput 