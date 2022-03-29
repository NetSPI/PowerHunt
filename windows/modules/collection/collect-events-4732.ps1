# Script : Invoke-PowerHunt
# Module : collect-events-4732
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework 
#          and is used to collect information event 4732 (member added to security-enabled local group).
# License: 3-clause BSD


# Get event data
$MyEvents = Get-WinEvent -FilterHashtable @{logname="security"; id="4732"} -ErrorAction SilentlyContinue | select MachineName,LogName,ProviderName,Id,ActivityId,Bookmark,ContainerLog,Keywords,KeywordsDisplayNames,Level,LevelDisplayName,MatchedQueryIds,Opcode,OpcodeDisplayName,ProcessId,Properties,ProviderId,Qualifiers,RecordId,RelatedActivityId,Task,TaskDisplayName,ThreadId,TimeCreated,UserId,Version,Message  | where message -like "*Administrators*"
$FinalOutput = $MyEvents | 
foreach{
    $MachineName = $_.MachineName
    $LogName = $_.LogName
    $EventId = $_.Id
    $Message = $_.Message 

    # Parse domain of user who added the new user
    $SubjectDomain = (($Message -split('\r?\n') | Select-String 'Account Domain:' -SimpleMatch) -split("Account Domain:"))[1].trim()

    # Parse name of user who added the new user
    $SubjectUser = (($Message -split('\r?\n') | Select-String 'Subject' -Context 0, 2 | % {$_.Context.PostContext}) -split("Account Name:"))[2].trim()

    # Parse sid of user who added the new user
    $SubjectUserSid = (($Message -split('\r?\n') | Select-String 'Subject' -Context 0, 1 | % {$_.Context.PostContext}) -split("Security ID:"))[1].trim()    

    # Parse user sid that was added
    $NewUserSid = (($Message -split('\r?\n') | Select-String 'member' -Context 0, 1 | % {$_.Context.PostContext}) -split("Security ID:"))[2].trim()   

    # Look up user's name from sid for local user
    # This step may not be needed

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
	$Object | add-member DataSource2 "4732"	
    $Object | add-member LogName $LogName
    $Object | add-member EventId $EventId           
    $Object | add-member SubjectUser $SubjectUser      
    $Object | add-member SubjectUserSid $SubjectUserSid
    $Object | add-member SubjectUserDomain $SubjectDomain
    $Object | add-member TimeCreated $_.TimeCreated  
    $Object | add-member PrincipalName $NewUserName               
    $Object | add-member PrincipalSid $NewUserSid
    $Object | add-member PrincipalEnabled $NewUser.Enabled
    $Object | add-member PrincipalLastLogon $NewUser.LastLogon
    $Object | add-member PrincipalPasswordLastSet $NewUser.PasswordLastSet
    $Object | add-member LogMessage $Message 
    $Object
}

# Count instances
$InstanceCount = $FinalOutput | measure | select count -expandproperty count

# Save summary metrics
$null = $ModuleOutputSummary.Rows.Add("$ModuleName","NA","NA","$InstanceCount")

# Return data
$FinalOutput 