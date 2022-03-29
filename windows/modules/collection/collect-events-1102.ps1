# Script : Invoke-PowerHunt
# Module : collect-events-1102
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework 
#          and is used to collect information event 1102 (audit log was cleared).
# License: 3-clause BSD


# Get event data
$MyEvents = Get-WinEvent -FilterHashtable @{logname="security"; id="1102"} -ErrorAction SilentlyContinue | select MachineName,LogName,ProviderName,Id,ActivityId,Bookmark,ContainerLog,Keywords,KeywordsDisplayNames,Level,LevelDisplayName,MatchedQueryIds,Opcode,OpcodeDisplayName,ProcessId,Properties,ProviderId,Qualifiers,RecordId,RelatedActivityId,Task,TaskDisplayName,ThreadId,TimeCreated,UserId,Version,Message 
$FinalOutput = $MyEvents | 
foreach{
    $MachineName = $_.MachineName
    $LogName = $_.LogName
    $EventId = $_.Id
    $Message = $_.Message 

    # Parse domain of user
    $SubjectDomain = (($Message -split('\r?\n') | Select-String 'Domain Name:' -SimpleMatch) -split("Domain Name:"))[1].trim()

    # Parse name of user 
    $SubjectUser = (($Message -split('\r?\n') | Select-String 'Subject' -Context 0, 2 | % {$_.Context.PostContext}) -split("Account Name:"))[2].trim()

    # Parse sid of user
    $SubjectUserSid = (($Message -split('\r?\n') | Select-String 'Subject' -Context 0, 1 | % {$_.Context.PostContext}) -split("Security ID:"))[1].trim()    

    # If of the user or group added
    $objSID = New-Object System.Security.Principal.SecurityIdentifier $NewUserSid 
    $objUser = $objSID.Translate( [System.Security.Principal.NTAccount]) 
    $NewUser = $objUser.Value  
    if($NewUser.Name){
        $NewUserName = $NewUser.Name
    }else{
        $NewUserName = $NewUser
    }

    # Create new object to return
    $Object = New-Object PSObject
    $Object | add-member ComputerName $MachineName
	$Object | add-member DataSource1 "event"
	$Object | add-member DataSource2 "1102"
    $Object | add-member LogName $LogName
    $Object | add-member EventId $EventId           
    $Object | add-member SubjectUser $SubjectUser      
    $Object | add-member SubjectUserSid $SubjectUserSid
    $Object | add-member SubjectUserDomain $SubjectDomain
    $Object | add-member TimeCreated $_.TimeCreated  
    $Object | add-member LogMessage $Message 
    $Object
}

# Count instances
$InstanceCount = $FinalOutput | measure | select count -expandproperty count

# Save summary metrics
$null = $ModuleOutputSummary.Rows.Add("$ModuleType","$ModuleName","NA","NA","NA","$InstanceCount")

# Return data
$FinalOutput 