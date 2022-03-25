# Script : Invoke-PowerHunt
# Module : collect-wmi-bindings
# Version: 1.0
# Author : Scott Sutherland
# Author : Alexander Polce Leary 
# Summary: This is script is part of the PowerHunt framework.
# License: 3-clause BSD

# Get WMI bindings
Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding |
foreach{

    # Grab value from binding
    $Filter = $_.Filter -replace('__EventFilter.Name="','') -replace('"','')
    $Consumer = $_.Consumer -replace('NTEventLogEventConsumer.Name=','') -replace('"','')

    # Get wmi filter information
    $FilterInfo = Get-WmiObject -Namespace root/subscription -Class __EventFilter | where name -like "$Filter"

    # Get wmi consumer information
    $ConsumerInfo = Get-WmiObject -Namespace root/subscription -Class __EventConsumer | where name -like "$Consumer"

    # Create new object to return
    $Object = New-Object PSObject

    # Filter info
    $object | add-member FilterName                 		$Filter
    $object | add-member FilterQuery               		$FilterInfo.Query
    $object | add-member FilterLanguage            		$FilterInfo.QueryLanguage
    $object | add-member FilterEventAccess          		$FilterInfo.EventAccess
    $object | add-member FilterCreatorSide          		(New-Object System.Security.Principal.SecurityIdentifier($FilterInfo.creatorsid,0)).Value

    # Consumer info
    $object | add-member ConsumerName				$Consumer
    $object | add-member ConsumerSourceName         		$ConsumerInfo.SourceName
    $object | add-member ConsumerInsertionStringTemplates 	$ConsumerInfo.InsertionStringTemplates
    $object | add-member ConsumerEventID            		$ConsumerInfo.EventID  
    $object | add-member ConsumerEventType          		$ConsumerInfo.EventType 
    $object | add-member ConsumerUncServerName      		$ConsumerInfo.UncServerName
    $object | add-member ConsumerCreatorSide         		(New-Object System.Security.Principal.SecurityIdentifier($ConsumerInfo.creatorsid,0)).Value

    # Binding info
    $object | add-member BindingCreatorSid  			(New-Object System.Security.Principal.SecurityIdentifier($_.creatorsid,0)).Value
    $object | add-member __PATH   				$_.__PATH
    $object | add-member __RELPATH   				$_.__RELPATH    
    $object | add-member __GENUS   				$_.__GENUS
    $object | add-member __CLASS   				$_.__CLASS
    $object | add-member __SUPERCLASS   			$_.__SUPERCLASS
    $object | add-member __DYNASTY   				$_.__DYNASTY
    $object | add-member __PROPERTY_COUNT   			$_.__PROPERTY_COUNT
    $object | add-member __DERIVATION   			$_.__DERIVATION
    $object | add-member __SERVER   				$_.__SERVER
    $object | add-member __NAMESPACE   				$_.__NAMESPACE
    $object | add-member SlowDownProviders  			$_.SlowDownProviders
    $object | add-member MaintainSecurityContext   		$_.MaintainSecurityContext
    $object | add-member DeliveryQoS   				$_.DeliveryQoS
    $object | add-member DeliverSynchronously   		$_.DeliverSynchronously

    $Object
}
