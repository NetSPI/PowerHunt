# -------------------------------------------
# Function: Invoke-HuntPersistPR
# -------------------------------------------
# Version: 0.24
function Invoke-HuntPersistPR
{    
   <#
   
   # on a non domain system
   runas /netonly /user:domain\user powershell.exe
   Invoke-HuntPersistPR -Threads 100 -OutputDirectory c:\temp\test -DomainController 10.1.1.1 -Username domain\user -password 'password'
   Invoke-HuntPersistPR -Threads 100 -OutputDirectory c:\temp\test -DomainController 10.1.1.1 -Credential domain\user

   # on a domain system
   Invoke-HuntPersistPR -OutputDirectory "c:\temp\now" -Threads 100 -DomainController 10.1.1.1
   or
   Invoke-HuntPersistPR -OutputDirectory "c:\temp\now" -Threads 100 	
   #>
    [CmdletBinding()]
    Param(
       [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user. For computer lookup.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user. For computer lookup.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller. For computer lookup.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against. For computer lookup.')]
        [string]$DomainController,
        
        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads to process at once.')]
        [int]$Threads = 100,

        [Parameter(Mandatory = $true,
        HelpMessage = 'Directory to output files to.')]
        [string]$OutputDirectory,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Runspace time out.')]
        [int]$RunSpaceTimeOut = 15,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Show runspace errors if they occur.')]
        [switch] $ShowRunpaceError,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Show runspace errors if they occur.')]
        [switch] $CollectOnly,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only analyze offline data.  Requires OfflinePath.')]
        [switch] $AnalyzeOnly,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Collection scan directory. Can either be from full scan or CollectOnly scan.')]
        [string]$OfflinePath
        
    )
	
    
    Begin
    {
        
        # Set variables
        $GlobalThreadCount = $Threads

        Write-Output " ==========================================="
        Write-Output " INVOKE-HUNTPERSISTPR"
        Write-Output " ==========================================="

        # Run collection if analyze only not set
        if(-not $AnalyzeOnly){

            # Check for modules direcroty 
            $Time =  Get-Date -UFormat "%m/%d/%Y %R"
            if(Test-Path .\windows\modules){
             # Write-Output " [+][$Time] The windows\modules directory was found."
            }else{
             Write-Output " [x][$Time] The windows\modules directory was not found."
             Write-Output " [!][$Time] Aborting operation."
             break
            }    

            # Get start time
            $StartTime = Get-Date
	        $Time =  Get-Date -UFormat "%m/%d/%Y %R"
            Write-Output " [+][$Time] Start active testing"        
            $StopWatch =  [system.diagnostics.stopwatch]::StartNew()

            Write-Output " -------------------------------------------"
            Write-Output " ENABLING POWERSHELL REMOTING"
            Write-Output " -------------------------------------------"

            # Check for local administrator privileges
            if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false){
                $Time =  Get-Date -UFormat "%m/%d/%Y %R"
                Write-Output " [x][$Time] This is not a privileged processed, aborting operation."
                Write-Output " [!][$Time] Make sure to run this in a privileged process that can run the commands:"
                Write-Output "    [$Time]  Enable-PSRemoting –force"
                Write-Output "    [$Time]  Set-Service WinRM -StartMode Automatic"
                Write-Output "    [$Time]  Set-Item WSMan:localhost\client\trustedhosts -value *"
                break
            }else{

                $Time =  Get-Date -UFormat "%m/%d/%Y %R"
                Write-Output " [+][$Time] Confirmed local administrative privileges."  
                Write-Output " [+][$Time] Checking if PS Remoting is enabled..."
            
                # Check if ps remoting is enabled
                try{

                    # Test connection
                    Test-WSMan -ComputerName $env:COMPUTERNAME | Out-Null
                    Write-Output " [+][$Time] PS Remoting appears to be enabled."
                }catch{

                    # Enable ps remoting
                    Write-Output " [x][$Time] PSRemoting appears to be disabled."
                    Write-Output " [+][$Time] Enabling PSRemoting..."
                
                    #Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue
                    Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
                                
                    # Set start mode to automatic
                    Set-Service WinRM -StartMode Automatic -ErrorAction SilentlyContinue | Out-Null            
                }
               
                # Trust all hosts
                $Time =  Get-Date -UFormat "%m/%d/%Y %R"
                # Write-Output " [+][$Time] Trust configuration check..." 
                try{           
                    Set-Item WSMan:localhost\client\trustedhosts -value * -Force -ErrorAction SilentlyContinue | Out-Null
                    # Write-Output " [+][$Time] Trust configuration updated successfully."
                }catch{
                    Write-Output " [x][$Time] Trust configuration update failed."
                    Write-Output " [!][$Time] Aborting operation."
                    break
                }

                # Get service status
                $ServiceStatus = Get-WmiObject -Class win32_service | Where-Object {$_.name -like "WinRM"}

                # Get trust status
                $TrustStatus = Get-Item WSMan:\localhost\Client\TrustedHosts
    
                # One last configuration check
                $Time =  Get-Date -UFormat "%m/%d/%Y %R"
                if($ServiceStatus.State -eq "Running" -and $TrustStatus.Value -eq '*'){
                    Write-Output " [+][$Time] Local PowerShell Remoting requirements met."
                }else{
                    Write-Output " [x][$Time] Enabling PowerShell Remoting failed."
                    Write-Output " [!][$Time] Aborting operation."
	                break
                }
            }


            # ----------------------------------------------------------------------
            # Enumerate domain computers 
            # ----------------------------------------------------------------------

            # Set target domain 
            Write-Output " -------------------------------------------"
            Write-Output " DISCOVERY: DOMAIN COMPUTERS - LDAP QUERY"
            Write-Output " -------------------------------------------"       

            $Time =  Get-Date -UFormat "%m/%d/%Y %R"
            Write-Output " [+][$Time] Attempting to access domain controller..."          
            $DCRecord = Get-LdapQuery -LdapFilter "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -DomainController $DomainController -Username $username -Password $Password -Credential $Credential | select -first 1 | select properties -expand properties -ErrorAction SilentlyContinue
            [string]$DCHostname = $DCRecord.dnshostname
            [string]$DCCn = $DCRecord.cn
            [string]$TargetDomain = $DCHostname -replace ("$DCCn\.","") 
        
            $Time =  Get-Date -UFormat "%m/%d/%Y %R"        
            if($DCHostname)
            {
                Write-Output " [+][$Time] Successful connection to domain controller: $DCHostname"             
            }else{
                Write-Output " [x][$Time] There appears to have been an error connecting to the domain controller."
                Write-Output " [!][$Time] Aborting."
                break
            }           

            # Verify output directory exists
            $Time =  Get-Date -UFormat "%m/%d/%Y %R"
            if(Test-Path $OutputDirectory){
                # Write-Output " [+][$Time] The $OutputDirectory directory was found."
            
                # Create sub directory for output
                try{
                    $FolderDateTime =  Get-Date -Format "MMddyyyyHHmm"
                    $OutputDirectory = "$OutputDirectory\$TargetDomain-$FolderDateTime"
                    mkdir $OutputDirectory | Out-Null
                    mkdir "$OutputDirectory\collection" | Out-Null
                    mkdir "$OutputDirectory\analysis" | Out-Null
                    mkdir "$OutputDirectory\discovery" | Out-Null
                }catch{
                    Write-Output " [x][$Time] The $OutputDirectory was not writable."
                    Write-Output " [!][$Time] Aborting operation."
                    break
                }
            }else{
                Write-Output " [x][$Time] The $OutputDirectory directory was not found."
                Write-Output " [!][$Time] Aborting operation."
                break
            }

            # Status user
            Write-Output " [+][$Time] Performing LDAP query for computers associated with the $TargetDomain domain"

            # Get domain computers        
            $DomainComputersRecord = Get-LdapQuery -LdapFilter "(objectCategory=Computer)" -DomainController $DomainController -Username $username -Password $Password
            $DomainComputers = $DomainComputersRecord | 
            foreach{
                
                $DnsHostName = [string]$_.Properties['dnshostname']
                if($DnsHostName -notlike ""){
                    $object = New-Object psobject
                    $Object | Add-Member Noteproperty ComputerName $DnsHostName
                    $Object      
                }
            }

            # Status user
            $ComputerCount = $DomainComputers.count
            Write-Output " [+][$Time] - $ComputerCount computers found"

            # Save results
            # Write-Output " [+][$Time] - Saving to $OutputDirectory\$TargetDomain-Domain-Computers.csv"
            $DomainComputers | Export-Csv -NoTypeInformation "$OutputDirectory\discovery\$TargetDomain-Domain-Computers.csv"
            # $null = Convert-DataTableToHtmlTable -DataTable $DomainComputers -Outfile "$OutputDirectory\discovery\$TargetDomain-Domain-Computers.html" -Title "Domain Computers" -Description "This page shows the domain computers discovered for the $TargetDomain Active Directory domain."
            $DomainComputersFile = "$TargetDomain-Domain-Computers.csv"
            #$DomainComputersFileH = "$TargetDomain-Domain-Computers.html"

            Write-Output " [+][$Time] Output directory: $OutputDirectory"

            # ----------------------------------------------------------------------
            # Identify computers that respond to ping reqeusts
            # ----------------------------------------------------------------------

            Write-Output " -------------------------------------------"
            Write-Output " DISCOVERY: DOMAIN COMPUTERS - PING SCANS"
            Write-Output " -------------------------------------------"

            # Status user
            $Time =  Get-Date -UFormat "%m/%d/%Y %R"
            Write-Output " [+][$Time] Pinging $ComputerCount computers"

            # Ping computerss
            $PingResults = $DomainComputers | Invoke-Ping -Throttle $GlobalThreadCount

            # select computers that respond
            $ComputersPingable = $PingResults |
            foreach {

                $computername = $_.address
                $status = $_.status
                if($status -like "Responding"){
                    $object = new-object psobject            
                    $Object | add-member Noteproperty ComputerName $computername
                    $Object | add-member Noteproperty status $status
                    $Object
                }
            }

            # Status user
            $Time =  Get-Date -UFormat "%m/%d/%Y %R"
            $ComputerPingableCount = $ComputersPingable.count
            Write-Output " [+][$Time] - $ComputerPingableCount computers responded to ping requests."
        
            # Stop if no hosts are accessible
            If ($ComputerPingableCount -eq 0)
            {
                $Time =  Get-Date -UFormat "%m/%d/%Y %R"
                Write-Output " [x][$Time] - No computers responded to ping."
                Write-Output " [!][$Time] - Aborting."
                break
            }

            # Save results
            $Time =  Get-Date -UFormat "%m/%d/%Y %R"
            # Write-Output " [+][$Time] - Saving to $OutputDirectory\$TargetDomain-Domain-Computers-Pingable.csv"
            $ComputersPingable | Export-Csv -NoTypeInformation "$OutputDirectory\discovery\$TargetDomain-Domain-Computers-Pingable.csv"
            #$null = Convert-DataTableToHtmlTable -DataTable $ComputersPingable -Outfile "$OutputDirectory\discovery\$TargetDomain-Domain-Computers-Pingable.html" -Title "Domain Computers: Ping Response" -Description "This page shows the domain computers for the $TargetDomain Active Directory domain that responded to ping requests."
            $ComputersPingableFile = "$TargetDomain-Domain-Computers-Pingable.csv"
            #$ComputersPingableFileH =  "$TargetDomain-Domain-Computers-Pingable.html"


            Write-Output " -------------------------------------------"
            Write-Output " DISCOVERY: DOMAIN COMPUTERS - PORT SCANS"
            Write-Output " -------------------------------------------"

        
            # ----------------------------------------------------------------------
            # Identify computers that have TCP 5985 open and accessible
            # ----------------------------------------------------------------------

            # Status user
            $Time =  Get-Date -UFormat "%m/%d/%Y %R"
            Write-Output " [+][$Time] Checking if TCP Port 5985 (NonSSL) is open on $ComputerPingableCount computers"

            # Get clean list of pingable computers
            $ComputersPingableClean = $ComputersPingable | Select-Object ComputerName

            # Create script block to port scan tcp 5985
            $MyScriptBlock = {
                    $ComputerName = $_.ComputerName
                    try{                      
                        $Socket = New-Object System.Net.Sockets.TcpClient($ComputerName,"5985")
                    
                        if($Socket.Connected)
                        {
                            $Status = "Open"             
                            $Socket.Close()
                        }
                        else 
                        {
                            $Status = "Closed"    
                        }
                    }
                    catch{
                        $Status = "Closed"
                    }   

                    if($Status -eq "Open")
                    {            
                        $object = new-object psobject            
                        $Object | add-member Noteproperty ComputerName $computername
                        $Object | add-member Noteproperty 5985status $status
                        $Object                            
                    }
            }
           
            # Perform port scan of tcp 5985 threaded
            $Computers5985Open = $ComputersPingableClean | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $GlobalThreadCount -RunspaceTimeout $RunSpaceTimeOut -ErrorAction SilentlyContinue

            # Status user
            $Time =  Get-Date -UFormat "%m/%d/%Y %R"
            $Computers5985OpenCount = $Computers5985Open.count
            Write-Output " [+][$Time] - $Computers5985OpenCount computers have TCP port 5985 open."                

            # Save results
            # Write-Output " [+][$Time] - Saving to $OutputDirectory\$TargetDomain-Domain-Computers-Open5985.csv"        
            $Computers5985Open | Export-Csv -NoTypeInformation "$OutputDirectory\discovery\$TargetDomain-Domain-Computers-Open5985.csv"
            #$null = Convert-DataTableToHtmlTable -DataTable $Computers5985Open -Outfile "$OutputDirectory\discovery\$TargetDomain-Domain-Computers-Open5985.html" -Title "Domain Computers: Port 5985 Open" -Description "This page shows the domain computers for the $TargetDomain Active Directory domain with port 5985 open."
            $Computers5985OpenFile = "$TargetDomain-Domain-Computers-Open5985.csv"
            #$Computers5985OpenFileH ="$TargetDomain-Domain-Computers-Open5985.html"

            # ----------------------------------------------------------------------
            # Identify computers that have TCP 5986 open and accessible
            # ----------------------------------------------------------------------

            # Status user
            $Time =  Get-Date -UFormat "%m/%d/%Y %R"
            Write-Output " [+][$Time] Checking if TCP Port 5986 (SSL) is open on $ComputerPingableCount computers"

            # Get clean list of pingable computers
            $ComputersPingableClean = $ComputersPingable | Select-Object ComputerName

            # Create script block to port scan tcp 5986
            $MyScriptBlock = {
                    $ComputerName = $_.ComputerName
                    try{                      
                        $Socket = New-Object System.Net.Sockets.TcpClient($ComputerName,"5986")
                    
                        if($Socket.Connected)
                        {
                            $Status = "Open"             
                            $Socket.Close()
                        }
                        else 
                        {
                            $Status = "Closed"    
                        }
                    }
                    catch{
                        $Status = "Closed"
                    }   

                    if($Status -eq "Open")
                    {            
                        $object = new-object psobject            
                        $Object | add-member Noteproperty ComputerName $computername
                        $Object | add-member Noteproperty 5986status $status
                        $Object                            
                    }
            }
          
            # Perform port scan of tcp 5986 threaded
            $Computers5986Open = $ComputersPingableClean | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $GlobalThreadCount -RunspaceTimeout $RunSpaceTimeOut -ErrorAction SilentlyContinue

            # Status user
            $Computers5986OpenCount = $Computers5986Open.count
            $Time =  Get-Date -UFormat "%m/%d/%Y %R"
            Write-Output " [+][$Time] - $Computers5986OpenCount computers have TCP port 5986 open."            

            # Save results
            # Write-Output " [+][$Time] - Saving to $OutputDirectory\$TargetDomain-Domain-Computers-Open5986.csv"        
            $Computers5986Open | Export-Csv -NoTypeInformation "$OutputDirectory\discovery\$TargetDomain-Domain-Computers-Open5986.csv"
            #$null = Convert-DataTableToHtmlTable -DataTable $Computers5986Open -Outfile "$OutputDirectory\discovery\$TargetDomain-Domain-Computers-Open5986.html" -Title "Domain Computers: Port 5986 Open" -Description "This page shows the domain computers for the $TargetDomain Active Directory domain with port 5986 open."
            $Computers5986OpenFile = "$TargetDomain-Domain-Computers-Open5986.csv"
            #$Computers5986OpenFileH ="$TargetDomain-Domain-Computers-Open5986.html"

            # ----------------------------------------------------------------------
            # Create PS Remoting Sessions
            # ---------------------------------------------------------------------- 
            # Add percentage that likley support ps remoting
            if($Computers5986OpenCount -eq 0 -and $Computers5985OpenCount -eq 0){
                Write-Output " [x][$Time] - PS Remoting does not appear to be available."
                Write-Output " [!][$Time] - Aborting operation."
                break
            }else{

                # Combine host lists
                Write-Output " [+][$Time] Creating PS Remoting Target List."
                $PsRemotingTargetsAll = $Computers5986Open + $Computers5985Open
                $PsRemotingTargetsAll = $PsRemotingTargetsAll | select computername -Unique
                $PsRemotingTargetsAllCount = $PsRemotingTargetsAll | measure | select count -ExpandProperty count
                        
                # Save results
                $Time =  Get-Date -UFormat "%m/%d/%Y %R"
                Write-Output " [+][$Time] - $PsRemotingTargetsAllCount computers will be targeted."
                # Write-Output " [+][$Time] - Saving to $OutputDirectory\discovery\$TargetDomain-Domain-Computers-PsRemoting.csv"        
                $PsRemotingTargetsAll | Export-Csv -NoTypeInformation "$OutputDirectory\discovery\$TargetDomain-Domain-Computers-PsRemoting.csv"        
            }

            Write-Output " -------------------------------------------"
            Write-Output " COLLECTION: ESTABLISH PS REMOTING SESSIONS"
            Write-Output " -------------------------------------------"
            Write-Output " [+][$Time] - Attempting to establish PS Remoting sessions with $PsRemotingTargetsAllCount systems."
            $PsRemotingTargetsAll | select ComputerName | 
            Foreach{

                try{
                    # Try without ssl
                    New-PSSession -ErrorAction SilentlyContinue -ComputerName $_.ComputerName -Credential $Credential | Out-Null  
                }catch{
                    # Try with ssl if not access denied
                    if ($Error[0] -notlike "*Access is denied.*"){                                 
                        New-PSSession -UseSSL -ErrorAction SilentlyContinue -ComputerName $_.ComputerName -Credential $Credential  | Out-Null              
                    }
                }
            }

            $SessionCount = (Get-PSSession | where State -like 'Opened').count
            $Time =  Get-Date -UFormat "%m/%d/%Y %R"
            Write-Output " [+][$Time] - $SessionCount PS Remoting sessions were established."
            if($SessionCount -eq 0){          
                Write-Output " [!][$Time] - Aborting operation."
                break
            }
        
            Write-Output " -------------------------------------------"
            Write-Output " COLLECTION: RUN ALL MODULES"
            Write-Output " -------------------------------------------"

            # Get list of collection modules
            $CollectionModules = Get-ChildItem .\windows\modules\collection 
            $CollectionModulesCount = $CollectionModules | measure | select count -ExpandProperty count
            Write-Output " [+][$Time] $CollectionModulesCount collection modules will be run against $SessionCount sessions."        

            # Load and run each module
            $CurrentModulesCount = 0
            $CollectionModules | 
            foreach{
            
                # Counter
                $CurrentModulesCount = $CurrentModulesCount + 1            

                # Get time
                $Time =  Get-Date -UFormat "%m/%d/%Y %R"

                # Get file path
                $ModuleFilePath = $_.fullname    

                # Parse module name from file
                $ModuleName= $_.name -replace(".ps1","")
                $ModuleStartTime = Get-Date

                # Run module
                Write-Output " [+][$Time] - ($CurrentModulesCount of $CollectionModulesCount) $ModuleName"
                # Write-Output " [+][$Time] - Running module..."
                $MyCommand = Get-Content $_.fullname -Raw
                $Results = Invoke-Command -Session (Get-PSSession | where state -like "Opened") -ScriptBlock {Invoke-Expression -Command  "$args"} -ArgumentList $MyCommand -ErrorAction SilentlyContinue
                $ModuleStopTime = Get-Date
                $ModuleDuration = $ModuleStopTime - $ModuleStartTime
                $Time =  Get-Date -UFormat "%m/%d/%Y %R"
                # Write-Output " [+][$Time] - Completed"
                # Write-Output " [+][$Time] - Duration: $ModuleDuration"

                # Save output
                $FileName = $_.name -replace(".ps1",".csv")
                $Time =  Get-Date -UFormat "%m/%d/%Y %R"
                # Write-Output " [+][$Time] - Saving to $OutputDirectory\collection\$TargetDomain-$FileName"
                $Results | Export-Csv -NoTypeInformation "$OutputDirectory\collection\$TargetDomain-$FileName"

            }

        }

        # Run analysis modules if collectonly not set
        if( -not $CollectOnly){
        
            Write-Output " -------------------------------------------"
            Write-Output " ANALYSIS: RUN ALL MODULES"
            Write-Output " -------------------------------------------"

            # Check offline path if analysis model
            $Time =  Get-Date -UFormat "%m/%d/%Y %R"
            if($AnalyzeOnly){
                Write-Output " [+][$Time] ANALYSIS ONLY MODE"
                if(-not $OfflinePath){
                    Write-Output " [!][$Time] Analysis only mode failed.  Missing OfflinePath."
                    Write-Output " [x][$Time] Aborting operation."
                    break           
                }else{
                       
                    if(Test-Path "$OfflinePath"){

                        # Override outputdirectory if analysisonly mode
                        $OutputDirectory = $OfflinePath                        
                    }else{
                        Write-Output " [!][$Time] Analysis only mode failed.  Bad OfflinePath."
                        Write-Output " [x][$Time] Aborting operation."
                        break   
                    }
                }
            }

            # Get list of collection modules
            $CollectionModules = Get-ChildItem .\windows\modules\collection 
            $CollectionModulesCount = $CollectionModules | measure | select count -ExpandProperty count 
        
            # Get analysis module count
            $AnalysisModules = Get-ChildItem .\windows\modules\analysis 
            $AnalysisModulesCount = $AnalysisModules | measure | select count -ExpandProperty count
            Write-Output " [+][$Time] $AnalysisModulesCount analysis modules will be run against $CollectionModulesCount data sources."       

            # Review each collection module data source
            $CollectionModulesCountP = 0
            $CollectionModules | 
            foreach{
            
                # Data Source Counter
                $CollectionModulesCountP = $CollectionModulesCountP + 1                                      
   
                # Parse module name from file
                $CollectionDataSource = $_.name -replace(".ps1","") -replace("collect-","")
                $Time =  Get-Date -UFormat "%m/%d/%Y %R"
                Write-Output " [+][$Time] Data Source ($CollectionModulesCountP of $CollectionModulesCount): $CollectionDataSource"
            
                # Generate data source file path
                $CollectionModuleFile = $_.name -replace(".ps1",".csv")
                if($OfflinePath){ $TargetDomain = '*' }
                $CollectionDataSourcePath = "$OutputDirectory\collection\$TargetDomain-$CollectionModuleFile"   

                # Select analysis modules that match the current data source name
                # This is based on the collection file name
                if($OfflinePath){ $TargetDomain = "OfflineAnalysis" }
                $AnalysisModulesT = Get-ChildItem .\windows\modules\analysis | where fullname -like "*$CollectionDataSource*"
                $AnalysisModulesCountT = $AnalysisModulesT | measure | select count -ExpandProperty count    
            
                if($AnalysisModulesCountT -eq 0){
                    Write-Output " [+][$Time] - No analysis modules exist for this data source." 
                }else{
                    Write-Output " [+][$Time] - $AnalysisModulesCountT analysis modules found, loading data source."

                    # load the data source data here
                    $CollectedData = Import-Csv $CollectionDataSourcePath
                }

                # Data Source Counter
                $AnalysisModulesCountP = 0 

                # Process each analysis module
                $AnalysisModulesT  |
                Foreach {

                    # Set analysis counter 
                    $AnalysisModulesCountP = $AnalysisModulesCountP + 1

                    # Parse analysis file path
                    $AnalysisModuleFilePath = $_.fullname      
                
                    # Parse analysis module name
                    $AnalysisModuleName = $_.name -replace(".ps1","")                 

                    # Load and run analysis module
                    $Time =  Get-Date -UFormat "%m/%d/%Y %R" 
                    Write-Output " [+][$Time] - ($AnalysisModulesCountP of $AnalysisModulesCountT) $AnalysisModuleName"           
                
                    # Get module code
                    $AnalysisCommand = Get-Content $AnalysisModuleFilePath -Raw

                    # Run module code
                    Invoke-Expression $AnalysisCommand                
                }     

            } 

            Write-Output " -------------------------------------------"
            Write-Output " REPORTING: RUN ALL MODULES"
            Write-Output " -------------------------------------------"
            Write-Output " - HTML (pending)"
        }

        # Shutdown active sessions if not offline mode / analysis only
        if(-not $OfflinePath){ 
            Write-Output " -------------------------------------------"
            Write-Output " SHUTDOWN"
            Write-Output " -------------------------------------------"

 
            $Time =  Get-Date -UFormat "%m/%d/%Y %R"
            Write-Output " [+][$Time]  - Stopping active testing"
            Write-Output " [+][$Time]  - Terminating $SessionCount PowerShell Remoting sessions." 
            Get-PSSession | Disconnect-PSSession -ErrorAction SilentlyContinue | Out-Null
            Get-PSSession | Remove-PSSession -ErrorAction SilentlyContinue | Out-Null
            $Time =  Get-Date -UFormat "%m/%d/%Y %R"
            Write-Output " [+][$Time]  - All sessions terminated."
        
            # Final user status                
            $StopTime = Get-Date
            $ScanDuration = $StopTime - $StartTime        
            Write-Output " [+][$Time]  - Test duration: $ScanDuration"
        }
     }
}

# -------------------------------------------
# Function: Get-LdapQuery
# -------------------------------------------
# Author: Will Schroeder
# Modifications: Scott Sutherland
function Get-LdapQuery
{
    <#
            .SYNOPSIS
            Used to query domain controllers via LDAP. Supports alternative credentials from non-domain system
            Note: This will use the default logon server by default.
            .PARAMETER Username
            Domain account to authenticate to Active Directory.
            .PARAMETER Password
            Domain password to authenticate to Active Directory.
            .PARAMETER Credential
            Domain credential to authenticate to Active Directory.
            .PARAMETER DomainController
            Domain controller to authenticated to. Requires username/password or credential.
            .PARAMETER LdapFilter
            LDAP filter.
            .PARAMETER LdapPath
            Ldap path.
            .PARAMETER $Limit
            Maximum number of Objects to pull from AD, limit is 1,000.".
            .PARAMETER SearchScope
            Scope of a search as either a base, one-level, or subtree search, default is subtree..
            .EXAMPLE
            PS C:\temp> Get-DomainObject -LdapFilter "(&(servicePrincipalName=*))"
            .EXAMPLE
            PS C:\temp> Get-DomainObject -LdapFilter "(&(servicePrincipalName=*))" -DomainController 10.0.0.1:389
            It will use the security context of the current process to authenticate to the domain controller.
            IP:Port can be specified to reach a pivot machine.
            .EXAMPLE
            PS C:\temp> Get-DomainObject -LdapFilter "(&(servicePrincipalName=*))" -DomainController 10.0.0.1  -Username Domain\User  -Password Password123!
            .Notes
            This was based on Will Schroeder's Get-ADObject function from https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,

        [Parameter(Mandatory = $false,
        HelpMessage = 'LDAP Filter.')]
        [string]$LdapFilter = '',

        [Parameter(Mandatory = $false,
        HelpMessage = 'LDAP path.')]
        [string]$LdapPath,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Maximum number of Objects to pull from AD, limit is 1,000 .')]
        [int]$Limit = 1000,

        [Parameter(Mandatory = $false,
        HelpMessage = 'scope of a search as either a base, one-level, or subtree search, default is subtree.')]
        [ValidateSet('Subtree','OneLevel','Base')]
        [string]$SearchScope = 'Subtree'
    )
    Begin
    {
        # Create PS Credential object
        if($Username -and $Password)
        {
            $secpass = ConvertTo-SecureString $Password -AsPlainText -Force
            $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($Username, $secpass)
        }

        # Create Create the connection to LDAP
        if ($DomainController)
        {
           
            # Test credentials and grab domain
            try {

                $ArgumentList = New-Object Collections.Generic.List[string]
                $ArgumentList.Add("LDAP://$DomainController")

                if($Username){
                    $ArgumentList.Add($Credential.UserName)
                    $ArgumentList.Add($Credential.GetNetworkCredential().Password)
                }

                $objDomain = (New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $ArgumentList).distinguishedname

                # Authentication failed. distinguishedName property can not be empty.
                if(-not $objDomain){ throw }

            }catch{
                Write-Host "Authentication failed or domain controller is not reachable."
                Break
            }

            # add ldap path
            if($LdapPath)
            {
                $LdapPath = '/'+$LdapPath+','+$objDomain
                $ArgumentList[0] = "LDAP://$DomainController$LdapPath"
            }

            $objDomainPath= New-Object System.DirectoryServices.DirectoryEntry -ArgumentList $ArgumentList

            $objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher $objDomainPath
        }
        else
        {
            $objDomain = ([ADSI]'').distinguishedName

            # add ldap path
            if($LdapPath)
            {
                $LdapPath = $LdapPath+','+$objDomain
                $objDomainPath  = [ADSI]"LDAP://$LdapPath"
            }
            else
            {
                $objDomainPath  = [ADSI]''
            }

            $objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $objDomainPath
        }

        # Setup LDAP filter
        $objSearcher.PageSize = $Limit
        $objSearcher.Filter = $LdapFilter
        $objSearcher.SearchScope = 'Subtree'
    }

    Process
    {
        try
        {
            # Return object
            $objSearcher.FindAll() | ForEach-Object -Process {
                $_
            }
        }
        catch
        {
            "Error was $_"
            $line = $_.InvocationInfo.ScriptLineNumber
            "Error was in Line $line"
        }
    }

    End
    {
    }
}


# -------------------------------------------
# Function: Invoke-Parallel
# -------------------------------------------
# Author: RamblingCookieMonster
# Source: https://github.com/RamblingCookieMonster/Invoke-Parallel
# Notes: Added "ImportSessionFunctions" to import custom functions from the current session into the runspace pool.
function Invoke-Parallel
{
    <#
            .SYNOPSIS
            Function to control parallel processing using runspaces

            .DESCRIPTION
            Function to control parallel processing using runspaces

            Note that each runspace will not have access to variables and commands loaded in your session or in other runspaces by default.
            This behaviour can be changed with parameters.

            .PARAMETER ScriptFile
            File to run against all input objects.  Must include parameter to take in the input object, or use $args.  Optionally, include parameter to take in parameter.  Example: C:\script.ps1

            .PARAMETER ScriptBlock
            Scriptblock to run against all computers.

            You may use $Using:<Variable> language in PowerShell 3 and later.

            The parameter block is added for you, allowing behaviour similar to foreach-object:
            Refer to the input object as $_.
            Refer to the parameter parameter as $parameter

            .PARAMETER InputObject
            Run script against these specified objects.

            .PARAMETER Parameter
            This object is passed to every script block.  You can use it to pass information to the script block; for example, the path to a logging folder

            Reference this object as $parameter if using the scriptblock parameterset.

            .PARAMETER ImportVariables
            If specified, get user session variables and add them to the initial session state

            .PARAMETER ImportModules
            If specified, get loaded modules and pssnapins, add them to the initial session state

            .PARAMETER Throttle
            Maximum number of threads to run at a single time.

            .PARAMETER SleepTimer
            Milliseconds to sleep after checking for completed runspaces and in a few other spots.  I would not recommend dropping below 200 or increasing above 500

            .PARAMETER RunspaceTimeout
            Maximum time in seconds a single thread can run.  If execution of your code takes longer than this, it is disposed.  Default: 0 (seconds)

            WARNING:  Using this parameter requires that maxQueue be set to throttle (it will be by default) for accurate timing.  Details here:
            http://gallery.technet.microsoft.com/Run-Parallel-Parallel-377fd430

            .PARAMETER NoCloseOnTimeout
            Do not dispose of timed out tasks or attempt to close the runspace if threads have timed out. This will prevent the script from hanging in certain situations where threads become non-responsive, at the expense of leaking memory within the PowerShell host.

            .PARAMETER MaxQueue
            Maximum number of powershell instances to add to runspace pool.  If this is higher than $throttle, $timeout will be inaccurate

            If this is equal or less than throttle, there will be a performance impact

            The default value is $throttle times 3, if $runspaceTimeout is not specified
            The default value is $throttle, if $runspaceTimeout is specified

            .PARAMETER LogFile
            Path to a file where we can log results, including run time for each thread, whether it completes, completes with errors, or times out.

            .PARAMETER Quiet
            Disable progress bar.

            .EXAMPLE
            Each example uses Test-ForPacs.ps1 which includes the following code:
            param($computer)

            if(test-connection $computer -count 1 -quiet -BufferSize 16){
            $object = [pscustomobject] @{
            Computer=$computer;
            Available=1;
            Kodak=$(
            if((test-path "\\$computer\c$\users\public\desktop\Kodak Direct View Pacs.url") -or (test-path "\\$computer\c$\documents and settings\all users

            \desktop\Kodak Direct View Pacs.url") ){"1"}else{"0"}
            )
            }
            }
            else{
            $object = [pscustomobject] @{
            Computer=$computer;
            Available=0;
            Kodak="NA"
            }
            }

            $object

            .EXAMPLE
            Invoke-Parallel -scriptfile C:\public\Test-ForPacs.ps1 -inputobject $(get-content C:\pcs.txt) -runspaceTimeout 10 -throttle 10

            Pulls list of PCs from C:\pcs.txt,
            Runs Test-ForPacs against each
            If any query takes longer than 10 seconds, it is disposed
            Only run 10 threads at a time

            .EXAMPLE
            Invoke-Parallel -scriptfile C:\public\Test-ForPacs.ps1 -inputobject c-is-ts-91, c-is-ts-95

            Runs against c-is-ts-91, c-is-ts-95 (-computername)
            Runs Test-ForPacs against each

            .EXAMPLE
            $stuff = [pscustomobject] @{
            ContentFile = "windows\system32\drivers\etc\hosts"
            Logfile = "C:\temp\log.txt"
            }

            $computers | Invoke-Parallel -parameter $stuff {
            $contentFile = join-path "\\$_\c$" $parameter.contentfile
            Get-Content $contentFile |
            set-content $parameter.logfile
            }

            This example uses the parameter argument.  This parameter is a single object.  To pass multiple items into the script block, we create a custom object (using a PowerShell v3 language) with properties we want to pass in.

            Inside the script block, $parameter is used to reference this parameter object.  This example sets a content file, gets content from that file, and sets it to a predefined log file.

            .EXAMPLE
            $test = 5
            1..2 | Invoke-Parallel -ImportVariables {$_ * $test}

            Add variables from the current session to the session state.  Without -ImportVariables $Test would not be accessible

            .EXAMPLE
            $test = 5
            1..2 | Invoke-Parallel {$_ * $Using:test}

            Reference a variable from the current session with the $Using:<Variable> syntax.  Requires PowerShell 3 or later. Note that -ImportVariables parameter is no longer necessary.

            .FUNCTIONALITY
            PowerShell Language

            .NOTES
            Credit to Boe Prox for the base runspace code and $Using implementation
            http://learn-powershell.net/2012/05/10/speedy-network-information-query-using-powershell/
            http://gallery.technet.microsoft.com/scriptcenter/Speedy-Network-Information-5b1406fb#content
            https://github.com/proxb/PoshRSJob/

            Credit to T Bryce Yehl for the Quiet and NoCloseOnTimeout implementations

            Credit to Sergei Vorobev for the many ideas and contributions that have improved functionality, reliability, and ease of use

            .LINK
            https://github.com/RamblingCookieMonster/Invoke-Parallel
    #>
    [cmdletbinding(DefaultParameterSetName = 'ScriptBlock')]
    Param (
        [Parameter(Mandatory = $false,position = 0,ParameterSetName = 'ScriptBlock')]
        [System.Management.Automation.ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory = $false,ParameterSetName = 'ScriptFile')]
        [ValidateScript({
                    Test-Path $_ -PathType leaf
        })]
        $ScriptFile,

        [Parameter(Mandatory = $true,ValueFromPipeline = $true)]
        [Alias('CN','__Server','IPAddress','Server','ComputerName')]
        [PSObject]$InputObject,

        [PSObject]$Parameter,

        [switch]$ImportSessionFunctions,

        [switch]$ImportVariables,

        [switch]$ImportModules,

        [int]$Throttle = 20,

        [int]$SleepTimer = 200,

        [int]$RunspaceTimeout = 0,

        [switch]$NoCloseOnTimeout = $false,

        [int]$MaxQueue,

        [validatescript({
                    Test-Path (Split-Path -Path $_ -Parent)
        })]
        [string]$LogFile = 'C:\temp\log.log',

        [switch] $Quiet = $false
    )

    Begin {

        #No max queue specified?  Estimate one.
        #We use the script scope to resolve an odd PowerShell 2 issue where MaxQueue isn't seen later in the function
        if( -not $PSBoundParameters.ContainsKey('MaxQueue') )
        {
            if($RunspaceTimeout -ne 0)
            {
                $script:MaxQueue = $Throttle
            }
            else
            {
                $script:MaxQueue = $Throttle * 3
            }
        }
        else
        {
            $script:MaxQueue = $MaxQueue
        }

        #Write-Verbose "Throttle: '$throttle' SleepTimer '$sleepTimer' runSpaceTimeout '$runspaceTimeout' maxQueue '$maxQueue' logFile '$logFile'"

        #If they want to import variables or modules, create a clean runspace, get loaded items, use those to exclude items
        if ($ImportVariables -or $ImportModules)
        {
            $StandardUserEnv = [powershell]::Create().addscript({
                    #Get modules and snapins in this clean runspace
                    $Modules = Get-Module | Select-Object -ExpandProperty Name
                    $Snapins = Get-PSSnapin | Select-Object -ExpandProperty Name

                    #Get variables in this clean runspace
                    #Called last to get vars like $? into session
                    $Variables = Get-Variable | Select-Object -ExpandProperty Name

                    #Return a hashtable where we can access each.
                    @{
                        Variables = $Variables
                        Modules   = $Modules
                        Snapins   = $Snapins
                    }
            }).invoke()[0]

            if ($ImportVariables)
            {
                #Exclude common parameters, bound parameters, and automatic variables
                Function _temp
                {
                    [cmdletbinding()] param()
                }
                $VariablesToExclude = @( (Get-Command _temp | Select-Object -ExpandProperty parameters).Keys + $PSBoundParameters.Keys + $StandardUserEnv.Variables )
                #Write-Verbose "Excluding variables $( ($VariablesToExclude | sort ) -join ", ")"

                # we don't use 'Get-Variable -Exclude', because it uses regexps.
                # One of the veriables that we pass is '$?'.
                # There could be other variables with such problems.
                # Scope 2 required if we move to a real module
                $UserVariables = @( Get-Variable | Where-Object -FilterScript {
                        -not ($VariablesToExclude -contains $_.Name)
                } )
                #Write-Verbose "Found variables to import: $( ($UserVariables | Select -expandproperty Name | Sort ) -join ", " | Out-String).`n"
            }

            if ($ImportModules)
            {
                $UserModules = @( Get-Module |
                    Where-Object -FilterScript {
                        $StandardUserEnv.Modules -notcontains $_.Name -and (Test-Path -Path $_.Path -ErrorAction SilentlyContinue)
                    } |
                Select-Object -ExpandProperty Path )
                $UserSnapins = @( Get-PSSnapin |
                    Select-Object -ExpandProperty Name |
                    Where-Object -FilterScript {
                        $StandardUserEnv.Snapins -notcontains $_
                } )
            }
        }

        #region functions

        Function Get-RunspaceData
        {
            [cmdletbinding()]
            param( [switch]$Wait )

            #loop through runspaces
            #if $wait is specified, keep looping until all complete
            Do
            {
                #set more to false for tracking completion
                $more = $false

                #Progress bar if we have inputobject count (bound parameter)
                if (-not $Quiet)
                {
                    Write-Progress  -Activity 'Running Query' -Status 'Starting threads'`
                    -CurrentOperation "$startedCount threads defined - $totalCount input objects - $script:completedCount input objects processed"`
                    -PercentComplete $( Try
                        {
                            $script:completedCount / $totalCount * 100
                        }
                        Catch
                        {
                            0
                        }
                    )
                }

                #run through each runspace.
                Foreach($runspace in $runspaces)
                {
                    #get the duration - inaccurate
                    $currentdate = Get-Date
                    $runtime = $currentdate - $runspace.startTime
                    $runMin = [math]::Round( $runtime.totalminutes ,2 )

                    #set up log object
                    $log = '' | Select-Object -Property Date, Action, Runtime, Status, Details
                    $log.Action = "Removing:'$($runspace.object)'"
                    $log.Date = $currentdate
                    $log.Runtime = "$runMin minutes"

                    #If runspace completed, end invoke, dispose, recycle, counter++
                    If ($runspace.Runspace.isCompleted)
                    {
                        $script:completedCount++

                        #check if there were errors
                        if($runspace.powershell.Streams.Error.Count -gt 0)
                        {
                            #set the logging info and move the file to completed
                            $log.status = 'CompletedWithErrors'
                            #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                            foreach($ErrorRecord in $runspace.powershell.Streams.Error)
                            {
                                Write-Error -ErrorRecord $ErrorRecord
                            }
                        }
                        else
                        {
                            #add logging details and cleanup
                            $log.status = 'Completed'
                            #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                        }

                        #everything is logged, clean up the runspace
                        $runspace.powershell.EndInvoke($runspace.Runspace)
                        $runspace.powershell.dispose()
                        $runspace.Runspace = $null
                        $runspace.powershell = $null
                    }

                    #If runtime exceeds max, dispose the runspace
                    ElseIf ( $RunspaceTimeout -ne 0 -and $runtime.totalseconds -gt $RunspaceTimeout)
                    {
                        $script:completedCount++
                        $timedOutTasks = $true

                        #add logging details and cleanup
                        $log.status = 'TimedOut'
                        #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                        Write-Error -Message "Runspace timed out at $($runtime.totalseconds) seconds for the object:`n$($runspace.object | Out-String)"

                        #Depending on how it hangs, we could still get stuck here as dispose calls a synchronous method on the powershell instance
                        if (!$NoCloseOnTimeout)
                        {
                            $runspace.powershell.dispose()
                        }
                        $runspace.Runspace = $null
                        $runspace.powershell = $null
                        $completedCount++
                    }

                    #If runspace isn't null set more to true
                    ElseIf ($runspace.Runspace -ne $null )
                    {
                        $log = $null
                        $more = $true
                    }

                    #log the results if a log file was indicated
                    <#
                            if($logFile -and $log){
                            ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1] | out-file $LogFile -append
                            }
                    #>
                }

                #Clean out unused runspace jobs
                $temphash = $runspaces.clone()
                $temphash |
                Where-Object -FilterScript {
                    $_.runspace -eq $null
                } |
                ForEach-Object -Process {
                    $runspaces.remove($_)
                }

                #sleep for a bit if we will loop again
                if($PSBoundParameters['Wait'])
                {
                    Start-Sleep -Milliseconds $SleepTimer
                }

                #Loop again only if -wait parameter and there are more runspaces to process
            }
            while ($more -and $PSBoundParameters['Wait'])

            #End of runspace function
        }

        #endregion functions

        #region Init

        if($PSCmdlet.ParameterSetName -eq 'ScriptFile')
        {
            $ScriptBlock = [scriptblock]::Create( $(Get-Content $ScriptFile | Out-String) )
        }
        elseif($PSCmdlet.ParameterSetName -eq 'ScriptBlock')
        {
            #Start building parameter names for the param block
            [string[]]$ParamsToAdd = '$_'
            if( $PSBoundParameters.ContainsKey('Parameter') )
            {
                $ParamsToAdd += '$Parameter'
            }

            $UsingVariableData = $null


            # This code enables $Using support through the AST.
            # This is entirely from  Boe Prox, and his https://github.com/proxb/PoshRSJob module; all credit to Boe!

            if($PSVersionTable.PSVersion.Major -gt 2)
            {
                #Extract using references
                $UsingVariables = $ScriptBlock.ast.FindAll({
                        $args[0] -is [System.Management.Automation.Language.UsingExpressionAst]
                },$true)

                If ($UsingVariables)
                {
                    $List = New-Object -TypeName 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                    ForEach ($Ast in $UsingVariables)
                    {
                        [void]$List.Add($Ast.SubExpression)
                    }

                    $UsingVar = $UsingVariables |
                    Group-Object -Property SubExpression |
                    ForEach-Object -Process {
                        $_.Group |
                        Select-Object -First 1
                    }

                    #Extract the name, value, and create replacements for each
                    $UsingVariableData = ForEach ($Var in $UsingVar)
                    {
                        Try
                        {
                            $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath -ErrorAction Stop
                            [pscustomobject]@{
                                Name       = $Var.SubExpression.Extent.Text
                                Value      = $Value.Value
                                NewName    = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                            }
                        }
                        Catch
                        {
                            Write-Error -Message "$($Var.SubExpression.Extent.Text) is not a valid Using: variable!"
                        }
                    }
                    $ParamsToAdd += $UsingVariableData | Select-Object -ExpandProperty NewName -Unique

                    $NewParams = $UsingVariableData.NewName -join ', '
                    $Tuple = [Tuple]::Create($List, $NewParams)
                    $bindingFlags = [Reflection.BindingFlags]'Default,NonPublic,Instance'
                    $GetWithInputHandlingForInvokeCommandImpl = ($ScriptBlock.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl',$bindingFlags))

                    $StringScriptBlock = $GetWithInputHandlingForInvokeCommandImpl.Invoke($ScriptBlock.ast,@($Tuple))

                    $ScriptBlock = [scriptblock]::Create($StringScriptBlock)

                    #Write-Verbose $StringScriptBlock
                }
            }

            $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param($($ParamsToAdd -Join ', '))`r`n" + $ScriptBlock.ToString())
        }
        else
        {
            Throw 'Must provide ScriptBlock or ScriptFile'
            Break
        }

        Write-Debug -Message "`$ScriptBlock: $($ScriptBlock | Out-String)"
        If (-not($SuppressVerbose)){
            Write-Verbose -Message 'Creating runspace pool and session states'
        }


        #If specified, add variables and modules/snapins to session state
        $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        if ($ImportVariables)
        {
            if($UserVariables.count -gt 0)
            {
                foreach($Variable in $UserVariables)
                {
                    $sessionstate.Variables.Add( (New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Variable.Name, $Variable.Value, $null) )
                }
            }
        }
        if ($ImportModules)
        {
            if($UserModules.count -gt 0)
            {
                foreach($ModulePath in $UserModules)
                {
                    $sessionstate.ImportPSModule($ModulePath)
                }
            }
            if($UserSnapins.count -gt 0)
            {
                foreach($PSSnapin in $UserSnapins)
                {
                    [void]$sessionstate.ImportPSSnapIn($PSSnapin, [ref]$null)
                }
            }
        }

        # --------------------------------------------------
        #region - Import Session Functions
        # --------------------------------------------------
        # Import functions from the current session into the RunspacePool sessionstate

        if($ImportSessionFunctions)
        {
            # Import all session functions into the runspace session state from the current one
            Get-ChildItem -Path Function:\ |
            Where-Object -FilterScript {
                $_.name -notlike '*:*'
            } |
            Select-Object -Property name -ExpandProperty name |
            ForEach-Object -Process {
                # Get the function code
                $Definition = Get-Content -Path "function:\$_" -ErrorAction Stop

                # Create a sessionstate function with the same name and code
                $SessionStateFunction = New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList "$_", $Definition

                # Add the function to the session state
                $sessionstate.Commands.Add($SessionStateFunction)
            }
        }
        #endregion

        #Create runspace pool
        $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
        $runspacepool.Open()

        #Write-Verbose "Creating empty collection to hold runspace jobs"
        $Script:runspaces = New-Object -TypeName System.Collections.ArrayList

        #If inputObject is bound get a total count and set bound to true
        $bound = $PSBoundParameters.keys -contains 'InputObject'
        if(-not $bound)
        {
            [System.Collections.ArrayList]$allObjects = @()
        }

        <#
                #Set up log file if specified
                if( $LogFile ){
                New-Item -ItemType file -path $logFile -force | Out-Null
                ("" | Select Date, Action, Runtime, Status, Details | ConvertTo-Csv -NoTypeInformation -Delimiter ";")[0] | Out-File $LogFile
                }

                #write initial log entry
                $log = "" | Select Date, Action, Runtime, Status, Details
                $log.Date = Get-Date
                $log.Action = "Batch processing started"
                $log.Runtime = $null
                $log.Status = "Started"
                $log.Details = $null
                if($logFile) {
                ($log | convertto-csv -Delimiter ";" -NoTypeInformation)[1] | Out-File $LogFile -Append
                }
        #>
        $timedOutTasks = $false

        #endregion INIT
    }

    Process {

        #add piped objects to all objects or set all objects to bound input object parameter
        if($bound)
        {
            $allObjects = $InputObject
        }
        Else
        {
            [void]$allObjects.add( $InputObject )
        }
    }

    End {

        #Use Try/Finally to catch Ctrl+C and clean up.
        Try
        {
            #counts for progress
            $totalCount = $allObjects.count
            $script:completedCount = 0
            $startedCount = 0

            foreach($object in $allObjects)
            {
                #region add scripts to runspace pool

                #Create the powershell instance, set verbose if needed, supply the scriptblock and parameters
                $powershell = [powershell]::Create()

                if ($VerbosePreference -eq 'Continue')
                {
                    [void]$powershell.AddScript({
                            $VerbosePreference = 'Continue'
                    })
                }

                [void]$powershell.AddScript($ScriptBlock).AddArgument($object)

                if ($Parameter)
                {
                    [void]$powershell.AddArgument($Parameter)
                }

                # $Using support from Boe Prox
                if ($UsingVariableData)
                {
                    Foreach($UsingVariable in $UsingVariableData)
                    {
                        #Write-Verbose "Adding $($UsingVariable.Name) with value: $($UsingVariable.Value)"
                        [void]$powershell.AddArgument($UsingVariable.Value)
                    }
                }

                #Add the runspace into the powershell instance
                $powershell.RunspacePool = $runspacepool

                #Create a temporary collection for each runspace
                $temp = '' | Select-Object -Property PowerShell, StartTime, object, Runspace
                $temp.PowerShell = $powershell
                $temp.StartTime = Get-Date
                $temp.object = $object

                #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
                $temp.Runspace = $powershell.BeginInvoke()
                $startedCount++

                #Add the temp tracking info to $runspaces collection
                #Write-Verbose ( "Adding {0} to collection at {1}" -f $temp.object, $temp.starttime.tostring() )
                $null = $runspaces.Add($temp)

                #loop through existing runspaces one time
                if($ShowRunpaceErrors){
                    Get-RunspaceData -ErrorAction SilentlyContinue
                }else{
                    Get-RunspaceData -ErrorAction SilentlyContinue
                }

                #If we have more running than max queue (used to control timeout accuracy)
                #Script scope resolves odd PowerShell 2 issue
                $firstRun = $true
                while ($runspaces.count -ge $script:MaxQueue)
                {
                    #give verbose output
                    if($firstRun)
                    {
                        #Write-Verbose "$($runspaces.count) items running - exceeded $Script:MaxQueue limit."
                    }
                    $firstRun = $false

                    #run get-runspace data and sleep for a short while
                    Get-RunspaceData -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds $SleepTimer
                }

                #endregion add scripts to runspace pool
            }

            #Write-Verbose ( "Finish processing the remaining runspace jobs: {0}" -f ( @($runspaces | Where {$_.Runspace -ne $Null}).Count) )
            Get-RunspaceData -wait -ErrorAction SilentlyContinue

            if (-not $Quiet)
            {
                Write-Progress -Activity 'Running Query' -Status 'Starting threads' -Completed
            }
        }
        Finally
        {
            #Close the runspace pool, unless we specified no close on timeout and something timed out
            if ( ($timedOutTasks -eq $false) -or ( ($timedOutTasks -eq $true) -and ($NoCloseOnTimeout -eq $false) ) )
            {
                If (-not($SuppressVerbose)){
                    Write-Verbose -Message 'Closing the runspace pool'
                }
                $runspacepool.close()
            }

            #collect garbage
            [gc]::Collect()
        }
    }
}

# -------------------------------------------
# Function: Invoke-Ping
# -------------------------------------------
Function Invoke-Ping 
{
<#
.SYNOPSIS
    Ping or test connectivity to systems in parallel
    
.DESCRIPTION
    Ping or test connectivity to systems in parallel

    Default action will run a ping against systems
        If Quiet parameter is specified, we return an array of systems that responded
        If Detail parameter is specified, we test WSMan, RemoteReg, RPC, RDP and/or SMB

.PARAMETER ComputerName
    One or more computers to test

.PARAMETER Quiet
    If specified, only return addresses that responded to Test-Connection

.PARAMETER Detail
    Include one or more additional tests as specified:
        WSMan      via Test-WSMan
        RemoteReg  via Microsoft.Win32.RegistryKey
        RPC        via WMI
        RDP        via port 3389
        SMB        via \\ComputerName\C$
        *          All tests

.PARAMETER Timeout
    Time in seconds before we attempt to dispose an individual query.  Default is 20

.PARAMETER Throttle
    Throttle query to this many parallel runspaces.  Default is 100.

.PARAMETER NoCloseOnTimeout
    Do not dispose of timed out tasks or attempt to close the runspace if threads have timed out

    This will prevent the script from hanging in certain situations where threads become non-responsive, at the expense of leaking memory within the PowerShell host.

.EXAMPLE
    Invoke-Ping Server1, Server2, Server3 -Detail *

    # Check for WSMan, Remote Registry, Remote RPC, RDP, and SMB (via C$) connectivity against 3 machines

.EXAMPLE
    $Computers | Invoke-Ping

    # Ping computers in $Computers in parallel

.EXAMPLE
    $Responding = $Computers | Invoke-Ping -Quiet
    
    # Create a list of computers that successfully responded to Test-Connection

.LINK
    https://gallery.technet.microsoft.com/scriptcenter/Invoke-Ping-Test-in-b553242a

.FUNCTIONALITY
    Computers

#>
    [cmdletbinding(DefaultParameterSetName='Ping')]
    param(
        [Parameter( ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true, 
                    Position=0)]
        [string[]]$ComputerName,
        
        [Parameter( ParameterSetName='Detail')]
        [validateset("*","WSMan","RemoteReg","RPC","RDP","SMB")]
        [string[]]$Detail,
        
        [Parameter(ParameterSetName='Ping')]
        [switch]$Quiet,
        
        [int]$Timeout = 20,
        
        [int]$Throttle = 100,

        [switch]$NoCloseOnTimeout
    )
    Begin
    {

        #http://gallery.technet.microsoft.com/Run-Parallel-Parallel-377fd430
        function Invoke-Parallel {
            [cmdletbinding(DefaultParameterSetName='ScriptBlock')]
            Param (   
                [Parameter(Mandatory=$false,position=0,ParameterSetName='ScriptBlock')]
                    [System.Management.Automation.ScriptBlock]$ScriptBlock,

                [Parameter(Mandatory=$false,ParameterSetName='ScriptFile')]
                [ValidateScript({test-path $_ -pathtype leaf})]
                    $ScriptFile,

                [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
                [Alias('CN','__Server','IPAddress','Server','ComputerName')]    
                    [PSObject]$InputObject,

                    [PSObject]$Parameter,

                    [switch]$ImportVariables,

                    [switch]$ImportModules,

                    [int]$Throttle = 20,

                    [int]$SleepTimer = 200,

                    [int]$RunspaceTimeout = 0,

			        [switch]$NoCloseOnTimeout = $false,

                    [int]$MaxQueue,

                [validatescript({Test-Path (Split-Path $_ -parent)})]
                    [string]$LogFile = "C:\temp\log.log",

			        [switch] $Quiet = $false
            )
    
            Begin {
                
                #No max queue specified?  Estimate one.
                #We use the script scope to resolve an odd PowerShell 2 issue where MaxQueue isn't seen later in the function
                if( -not $PSBoundParameters.ContainsKey('MaxQueue') )
                {
                    if($RunspaceTimeout -ne 0){ $script:MaxQueue = $Throttle }
                    else{ $script:MaxQueue = $Throttle * 3 }
                }
                else
                {
                    $script:MaxQueue = $MaxQueue
                }

                Write-Verbose "Throttle: '$throttle' SleepTimer '$sleepTimer' runSpaceTimeout '$runspaceTimeout' maxQueue '$maxQueue' logFile '$logFile'"

                #If they want to import variables or modules, create a clean runspace, get loaded items, use those to exclude items
                if ($ImportVariables -or $ImportModules)
                {
                    $StandardUserEnv = [powershell]::Create().addscript({

                        #Get modules and snapins in this clean runspace
                        $Modules = Get-Module | Select -ExpandProperty Name
                        $Snapins = Get-PSSnapin | Select -ExpandProperty Name

                        #Get variables in this clean runspace
                        #Called last to get vars like $? into session
                        $Variables = Get-Variable | Select -ExpandProperty Name
                
                        #Return a hashtable where we can access each.
                        @{
                            Variables = $Variables
                            Modules = $Modules
                            Snapins = $Snapins
                        }
                    }).invoke()[0]
            
                    if ($ImportVariables) {
                        #Exclude common parameters, bound parameters, and automatic variables
                        Function _temp {[cmdletbinding()] param() }
                        $VariablesToExclude = @( (Get-Command _temp | Select -ExpandProperty parameters).Keys + $PSBoundParameters.Keys + $StandardUserEnv.Variables )
                        Write-Verbose "Excluding variables $( ($VariablesToExclude | sort ) -join ", ")"

                        # we don't use 'Get-Variable -Exclude', because it uses regexps. 
                        # One of the veriables that we pass is '$?'. 
                        # There could be other variables with such problems.
                        # Scope 2 required if we move to a real module
                        $UserVariables = @( Get-Variable | Where { -not ($VariablesToExclude -contains $_.Name) } ) 
                        Write-Verbose "Found variables to import: $( ($UserVariables | Select -expandproperty Name | Sort ) -join ", " | Out-String).`n"

                    }

                    if ($ImportModules) 
                    {
                        $UserModules = @( Get-Module | Where {$StandardUserEnv.Modules -notcontains $_.Name -and (Test-Path $_.Path -ErrorAction SilentlyContinue)} | Select -ExpandProperty Path )
                        $UserSnapins = @( Get-PSSnapin | Select -ExpandProperty Name | Where {$StandardUserEnv.Snapins -notcontains $_ } ) 
                    }
                }

                #region functions
            
                    Function Get-RunspaceData {
                        [cmdletbinding()]
                        param( [switch]$Wait )

                        #loop through runspaces
                        #if $wait is specified, keep looping until all complete
                        Do {

                            #set more to false for tracking completion
                            $more = $false

                            #Progress bar if we have inputobject count (bound parameter)
                            if (-not $Quiet) {
						        Write-Progress  -Activity "Running Query" -Status "Starting threads"`
							        -CurrentOperation "$startedCount threads defined - $totalCount input objects - $script:completedCount input objects processed"`
							        -PercentComplete $( Try { $script:completedCount / $totalCount * 100 } Catch {0} )
					        }

                            #run through each runspace.           
                            Foreach($runspace in $runspaces) {
                    
                                #get the duration - inaccurate
                                $currentdate = Get-Date
                                $runtime = $currentdate - $runspace.startTime
                                $runMin = [math]::Round( $runtime.totalminutes ,2 )

                                #set up log object
                                $log = "" | select Date, Action, Runtime, Status, Details
                                $log.Action = "Removing:'$($runspace.object)'"
                                $log.Date = $currentdate
                                $log.Runtime = "$runMin minutes"

                                #If runspace completed, end invoke, dispose, recycle, counter++
                                If ($runspace.Runspace.isCompleted) {
                            
                                    $script:completedCount++
                        
                                    #check if there were errors
                                    if($runspace.powershell.Streams.Error.Count -gt 0) {
                                
                                        #set the logging info and move the file to completed
                                        $log.status = "CompletedWithErrors"
                                        Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                        foreach($ErrorRecord in $runspace.powershell.Streams.Error) {
                                            Write-Error -ErrorRecord $ErrorRecord
                                        }
                                    }
                                    else {
                                
                                        #add logging details and cleanup
                                        $log.status = "Completed"
                                        Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                    }

                                    #everything is logged, clean up the runspace
                                    $runspace.powershell.EndInvoke($runspace.Runspace)
                                    $runspace.powershell.dispose()
                                    $runspace.Runspace = $null
                                    $runspace.powershell = $null

                                }

                                #If runtime exceeds max, dispose the runspace
                                ElseIf ( $runspaceTimeout -ne 0 -and $runtime.totalseconds -gt $runspaceTimeout) {
                            
                                    $script:completedCount++
                                    $timedOutTasks = $true
                            
							        #add logging details and cleanup
                                    $log.status = "TimedOut"
                                    Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                    Write-Error "Runspace timed out at $($runtime.totalseconds) seconds for the object:`n$($runspace.object | out-string)"

                                    #Depending on how it hangs, we could still get stuck here as dispose calls a synchronous method on the powershell instance
                                    if (!$noCloseOnTimeout) { $runspace.powershell.dispose() }
                                    $runspace.Runspace = $null
                                    $runspace.powershell = $null
                                    $completedCount++

                                }
                   
                                #If runspace isn't null set more to true  
                                ElseIf ($runspace.Runspace -ne $null ) {
                                    $log = $null
                                    $more = $true
                                }

                                #log the results if a log file was indicated
                                if($logFile -and $log){
                                    ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1] | out-file $LogFile -append
                                }
                            }

                            #Clean out unused runspace jobs
                            $temphash = $runspaces.clone()
                            $temphash | Where { $_.runspace -eq $Null } | ForEach {
                                $Runspaces.remove($_)
                            }

                            #sleep for a bit if we will loop again
                            if($PSBoundParameters['Wait']){ Start-Sleep -milliseconds $SleepTimer }

                        #Loop again only if -wait parameter and there are more runspaces to process
                        } while ($more -and $PSBoundParameters['Wait'])
                
                    #End of runspace function
                    }

                #endregion functions
        
                #region Init

                    if($PSCmdlet.ParameterSetName -eq 'ScriptFile')
                    {
                        $ScriptBlock = [scriptblock]::Create( $(Get-Content $ScriptFile | out-string) )
                    }
                    elseif($PSCmdlet.ParameterSetName -eq 'ScriptBlock')
                    {
                        #Start building parameter names for the param block
                        [string[]]$ParamsToAdd = '$_'
                        if( $PSBoundParameters.ContainsKey('Parameter') )
                        {
                            $ParamsToAdd += '$Parameter'
                        }

                        $UsingVariableData = $Null
                

                        # This code enables $Using support through the AST.
                        # This is entirely from  Boe Prox, and his https://github.com/proxb/PoshRSJob module; all credit to Boe!
                
                        if($PSVersionTable.PSVersion.Major -gt 2)
                        {
                            #Extract using references
                            $UsingVariables = $ScriptBlock.ast.FindAll({$args[0] -is [System.Management.Automation.Language.UsingExpressionAst]},$True)    

                            If ($UsingVariables)
                            {
                                $List = New-Object 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                                ForEach ($Ast in $UsingVariables)
                                {
                                    [void]$list.Add($Ast.SubExpression)
                                }

                                $UsingVar = $UsingVariables | Group Parent | ForEach {$_.Group | Select -First 1}
        
                                #Extract the name, value, and create replacements for each
                                $UsingVariableData = ForEach ($Var in $UsingVar) {
                                    Try
                                    {
                                        $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath -ErrorAction Stop
                                        $NewName = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                        [pscustomobject]@{
                                            Name = $Var.SubExpression.Extent.Text
                                            Value = $Value.Value
                                            NewName = $NewName
                                            NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                        }
                                        $ParamsToAdd += $NewName
                                    }
                                    Catch
                                    {
                                        Write-Error "$($Var.SubExpression.Extent.Text) is not a valid Using: variable!"
                                    }
                                }
    
                                $NewParams = $UsingVariableData.NewName -join ', '
                                $Tuple = [Tuple]::Create($list, $NewParams)
                                $bindingFlags = [Reflection.BindingFlags]"Default,NonPublic,Instance"
                                $GetWithInputHandlingForInvokeCommandImpl = ($ScriptBlock.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl',$bindingFlags))
        
                                $StringScriptBlock = $GetWithInputHandlingForInvokeCommandImpl.Invoke($ScriptBlock.ast,@($Tuple))

                                $ScriptBlock = [scriptblock]::Create($StringScriptBlock)

                                Write-Verbose $StringScriptBlock
                            }
                        }
                
                        $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param($($ParamsToAdd -Join ", "))`r`n" + $Scriptblock.ToString())
                    }
                    else
                    {
                        Throw "Must provide ScriptBlock or ScriptFile"; Break
                    }

                    Write-Debug "`$ScriptBlock: $($ScriptBlock | Out-String)"
                    Write-Verbose "Creating runspace pool and session states"

                    #If specified, add variables and modules/snapins to session state
                    $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
                    if ($ImportVariables)
                    {
                        if($UserVariables.count -gt 0)
                        {
                            foreach($Variable in $UserVariables)
                            {
                                $sessionstate.Variables.Add( (New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Variable.Name, $Variable.Value, $null) )
                            }
                        }
                    }
                    if ($ImportModules)
                    {
                        if($UserModules.count -gt 0)
                        {
                            foreach($ModulePath in $UserModules)
                            {
                                $sessionstate.ImportPSModule($ModulePath)
                            }
                        }
                        if($UserSnapins.count -gt 0)
                        {
                            foreach($PSSnapin in $UserSnapins)
                            {
                                [void]$sessionstate.ImportPSSnapIn($PSSnapin, [ref]$null)
                            }
                        }
                    }

                    #Create runspace pool
                    $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
                    $runspacepool.Open() 

                    Write-Verbose "Creating empty collection to hold runspace jobs"
                    $Script:runspaces = New-Object System.Collections.ArrayList        
        
                    #If inputObject is bound get a total count and set bound to true
                    $global:__bound = $false
                    $allObjects = @()
                    if( $PSBoundParameters.ContainsKey("inputObject") ){
                        $global:__bound = $true
                    }

                    #Set up log file if specified
                    if( $LogFile ){
                        New-Item -ItemType file -path $logFile -force | Out-Null
                        ("" | Select Date, Action, Runtime, Status, Details | ConvertTo-Csv -NoTypeInformation -Delimiter ";")[0] | Out-File $LogFile
                    }

                    #write initial log entry
                    $log = "" | Select Date, Action, Runtime, Status, Details
                        $log.Date = Get-Date
                        $log.Action = "Batch processing started"
                        $log.Runtime = $null
                        $log.Status = "Started"
                        $log.Details = $null
                        if($logFile) {
                            ($log | convertto-csv -Delimiter ";" -NoTypeInformation)[1] | Out-File $LogFile -Append
                        }

			        $timedOutTasks = $false

                #endregion INIT
            }

            Process {

                #add piped objects to all objects or set all objects to bound input object parameter
                if( -not $global:__bound ){
                    $allObjects += $inputObject
                }
                else{
                    $allObjects = $InputObject
                }
            }

            End {
        
                #Use Try/Finally to catch Ctrl+C and clean up.
                Try
                {
                    #counts for progress
                    $totalCount = $allObjects.count
                    $script:completedCount = 0
                    $startedCount = 0

                    foreach($object in $allObjects){
        
                        #region add scripts to runspace pool
                    
                            #Create the powershell instance, set verbose if needed, supply the scriptblock and parameters
                            $powershell = [powershell]::Create()
                    
                            if ($VerbosePreference -eq 'Continue')
                            {
                                [void]$PowerShell.AddScript({$VerbosePreference = 'Continue'})
                            }

                            [void]$PowerShell.AddScript($ScriptBlock).AddArgument($object)

                            if ($parameter)
                            {
                                [void]$PowerShell.AddArgument($parameter)
                            }

                            # $Using support from Boe Prox
                            if ($UsingVariableData)
                            {
                                Foreach($UsingVariable in $UsingVariableData) {
                                    Write-Verbose "Adding $($UsingVariable.Name) with value: $($UsingVariable.Value)"
                                    [void]$PowerShell.AddArgument($UsingVariable.Value)
                                }
                            }

                            #Add the runspace into the powershell instance
                            $powershell.RunspacePool = $runspacepool
    
                            #Create a temporary collection for each runspace
                            $temp = "" | Select-Object PowerShell, StartTime, object, Runspace
                            $temp.PowerShell = $powershell
                            $temp.StartTime = Get-Date
                            $temp.object = $object
    
                            #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
                            $temp.Runspace = $powershell.BeginInvoke()
                            $startedCount++

                            #Add the temp tracking info to $runspaces collection
                            Write-Verbose ( "Adding {0} to collection at {1}" -f $temp.object, $temp.starttime.tostring() )
                            $runspaces.Add($temp) | Out-Null
            
                            #loop through existing runspaces one time
                            if($ShowRunpaceErrors){
                                Get-RunspaceData -ErrorAction SilentlyContinue
                            }else{
                                Get-RunspaceData -ErrorAction SilentlyContinue
                            }

                            #If we have more running than max queue (used to control timeout accuracy)
                            #Script scope resolves odd PowerShell 2 issue
                            $firstRun = $true
                            while ($runspaces.count -ge $Script:MaxQueue) {

                                #give verbose output
                                if($firstRun){
                                    Write-Verbose "$($runspaces.count) items running - exceeded $Script:MaxQueue limit."
                                }
                                $firstRun = $false
                    
                                #run get-runspace data and sleep for a short while
                                Get-RunspaceData -ErrorAction SilentlyContinue
                                Start-Sleep -Milliseconds $sleepTimer
                    
                            }

                        #endregion add scripts to runspace pool
                    }
                     
                    Write-Verbose ( "Finish processing the remaining runspace jobs: {0}" -f ( @($runspaces | Where {$_.Runspace -ne $Null}).Count) )
                    Get-RunspaceData -wait -ErrorAction SilentlyContinue

                    if (-not $quiet) {
			            Write-Progress -Activity "Running Query" -Status "Starting threads" -Completed
		            }

                }
                Finally
                {
                    #Close the runspace pool, unless we specified no close on timeout and something timed out
                    if ( ($timedOutTasks -eq $false) -or ( ($timedOutTasks -eq $true) -and ($noCloseOnTimeout -eq $false) ) ) {
	                    Write-Verbose "Closing the runspace pool"
			            $runspacepool.close()
                    }

                    #collect garbage
                    [gc]::Collect()
                }       
            }
        }

        Write-Verbose "PSBoundParameters = $($PSBoundParameters | Out-String)"
        
        $bound = $PSBoundParameters.keys -contains "ComputerName"
        if(-not $bound)
        {
            [System.Collections.ArrayList]$AllComputers = @()
        }
    }
    Process
    {

        #Handle both pipeline and bound parameter.  We don't want to stream objects, defeats purpose of parallelizing work
        if($bound)
        {
            $AllComputers = $ComputerName
        }
        Else
        {
            foreach($Computer in $ComputerName)
            {
                $AllComputers.add($Computer) | Out-Null
            }
        }

    }
    End
    {

        #Built up the parameters and run everything in parallel
        $params = @($Detail, $Quiet)
        $splat = @{
            Throttle = $Throttle
            RunspaceTimeout = $Timeout
            InputObject = $AllComputers
            parameter = $params
        }
        if($NoCloseOnTimeout)
        {
            $splat.add('NoCloseOnTimeout',$True)
        }

        Invoke-Parallel @splat -ScriptBlock {
        
            $computer = $_.trim()
            $detail = $parameter[0]
            $quiet = $parameter[1]

            #They want detail, define and run test-server
            if($detail)
            {
                Try
                {
                    #Modification of jrich's Test-Server function: https://gallery.technet.microsoft.com/scriptcenter/Powershell-Test-Server-e0cdea9a
                    Function Test-Server{
                        [cmdletBinding()]
                        param(
	                        [parameter(
                                Mandatory=$true,
                                ValueFromPipeline=$true)]
	                        [string[]]$ComputerName,
                            [switch]$All,
                            [parameter(Mandatory=$false)]
	                        [switch]$CredSSP,
                            [switch]$RemoteReg,
                            [switch]$RDP,
                            [switch]$RPC,
                            [switch]$SMB,
                            [switch]$WSMAN,
                            [switch]$IPV6,
	                        [Management.Automation.PSCredential]$Credential
                        )
                            begin
                            {
	                            $total = Get-Date
	                            $results = @()
	                            if($credssp -and -not $Credential)
                                {
                                    Throw "Must supply Credentials with CredSSP test"
                                }

                                [string[]]$props = write-output Name, IP, Domain, Ping, WSMAN, CredSSP, RemoteReg, RPC, RDP, SMB

                                #Hash table to create PSObjects later, compatible with ps2...
                                $Hash = @{}
                                foreach($prop in $props)
                                {
                                    $Hash.Add($prop,$null)
                                }

                                function Test-Port{
                                    [cmdletbinding()]
                                    Param(
                                        [string]$srv,
                                        $port=135,
                                        $timeout=3000
                                    )
                                    $ErrorActionPreference = "SilentlyContinue"
                                    $tcpclient = new-Object system.Net.Sockets.TcpClient
                                    $iar = $tcpclient.BeginConnect($srv,$port,$null,$null)
                                    $wait = $iar.AsyncWaitHandle.WaitOne($timeout,$false)
                                    if(-not $wait)
                                    {
                                        $tcpclient.Close()
                                        Write-Verbose "Connection Timeout to $srv`:$port"
                                        $false
                                    }
                                    else
                                    {
                                        Try
                                        {
                                            $tcpclient.EndConnect($iar) | out-Null
                                            $true
                                        }
                                        Catch
                                        {
                                            write-verbose "Error for $srv`:$port`: $_"
                                            $false
                                        }
                                        $tcpclient.Close()
                                    }
                                }
                            }

                            process
                            {
                                foreach($name in $computername)
                                {
	                                $dt = $cdt= Get-Date
	                                Write-verbose "Testing: $Name"
	                                $failed = 0
	                                try{
	                                    $DNSEntity = [Net.Dns]::GetHostEntry($name)
	                                    $domain = ($DNSEntity.hostname).replace("$name.","")
	                                    $ips = $DNSEntity.AddressList | %{
                                            if(-not ( -not $IPV6 -and $_.AddressFamily -like "InterNetworkV6" ))
                                            {
                                                $_.IPAddressToString
                                            }
                                        }
	                                }
	                                catch
	                                {
		                                $rst = New-Object -TypeName PSObject -Property $Hash | Select -Property $props
		                                $rst.name = $name
		                                $results += $rst
		                                $failed = 1
	                                }
	                                Write-verbose "DNS:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
	                                if($failed -eq 0){
	                                    foreach($ip in $ips)
	                                    {
	    
		                                    $rst = New-Object -TypeName PSObject -Property $Hash | Select -Property $props
	                                        $rst.name = $name
		                                    $rst.ip = $ip
		                                    $rst.domain = $domain
		            
                                            if($RDP -or $All)
                                            {
                                                ####RDP Check (firewall may block rest so do before ping
		                                        try{
                                                    $socket = New-Object Net.Sockets.TcpClient($name, 3389) -ErrorAction stop
		                                            if($socket -eq $null)
		                                            {
			                                            $rst.RDP = $false
		                                            }
		                                            else
		                                            {
			                                            $rst.RDP = $true
			                                            $socket.close()
		                                            }
                                                }
                                                catch
                                                {
                                                    $rst.RDP = $false
                                                    Write-Verbose "Error testing RDP: $_"
                                                }
                                            }
		                                Write-verbose "RDP:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                        #########ping
	                                    if(test-connection $ip -count 2 -Quiet)
	                                    {
	                                        Write-verbose "PING:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
			                                $rst.ping = $true
			    
                                            if($WSMAN -or $All)
                                            {
                                                try{############wsman
				                                    Test-WSMan $ip -ErrorAction stop | Out-Null
				                                    $rst.WSMAN = $true
				                                }
			                                    catch
				                                {
                                                    $rst.WSMAN = $false
                                                    Write-Verbose "Error testing WSMAN: $_"
                                                }
				                                Write-verbose "WSMAN:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
			                                    if($rst.WSMAN -and $credssp) ########### credssp
			                                    {
				                                    try{
					                                    Test-WSMan $ip -Authentication Credssp -Credential $cred -ErrorAction stop
					                                    $rst.CredSSP = $true
					                                }
				                                    catch
					                                {
                                                        $rst.CredSSP = $false
                                                        Write-Verbose "Error testing CredSSP: $_"
                                                    }
				                                    Write-verbose "CredSSP:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
			                                    }
                                            }
                                            if($RemoteReg -or $All)
                                            {
			                                    try ########remote reg
			                                    {
				                                    [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $ip) | Out-Null
				                                    $rst.remotereg = $true
			                                    }
			                                    catch
				                                {
                                                    $rst.remotereg = $false
                                                    Write-Verbose "Error testing RemoteRegistry: $_"
                                                }
			                                    Write-verbose "remote reg:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                            }
                                            if($RPC -or $All)
                                            {
			                                    try ######### wmi
			                                    {	
				                                    $w = [wmi] ''
				                                    $w.psbase.options.timeout = 15000000
				                                    $w.path = "\\$Name\root\cimv2:Win32_ComputerSystem.Name='$Name'"
				                                    $w | select none | Out-Null
				                                    $rst.RPC = $true
			                                    }
			                                    catch
				                                {
                                                    $rst.rpc = $false
                                                    Write-Verbose "Error testing WMI/RPC: $_"
                                                }
			                                    Write-verbose "WMI/RPC:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                            }
                                            if($SMB -or $All)
                                            {

                                                #Use set location and resulting errors.  push and pop current location
                    	                        try ######### C$
			                                    {	
                                                    $path = "\\$name\c$"
				                                    Push-Location -Path $path -ErrorAction stop
				                                    $rst.SMB = $true
                                                    Pop-Location
			                                    }
			                                    catch
				                                {
                                                    $rst.SMB = $false
                                                    Write-Verbose "Error testing SMB: $_"
                                                }
			                                    Write-verbose "SMB:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"

                                            }
	                                    }
		                                else
		                                {
			                                $rst.ping = $false
			                                $rst.wsman = $false
			                                $rst.credssp = $false
			                                $rst.remotereg = $false
			                                $rst.rpc = $false
                                            $rst.smb = $false
		                                }
		                                $results += $rst	
	                                }
                                }
	                            Write-Verbose "Time for $($Name): $((New-TimeSpan $cdt ($dt)).totalseconds)"
	                            Write-Verbose "----------------------------"
                                }
                            }
                            end
                            {
	                            Write-Verbose "Time for all: $((New-TimeSpan $total ($dt)).totalseconds)"
	                            Write-Verbose "----------------------------"
                                return $results
                            }
                        }
                    
                    #Build up parameters for Test-Server and run it
                        $TestServerParams = @{
                            ComputerName = $Computer
                            ErrorAction = "Stop"
                        }

                        if($detail -eq "*"){
                            $detail = "WSMan","RemoteReg","RPC","RDP","SMB" 
                        }

                        $detail | Select -Unique | Foreach-Object { $TestServerParams.add($_,$True) }
                        Test-Server @TestServerParams | Select -Property $( "Name", "IP", "Domain", "Ping" + $detail )
                }
                Catch
                {
                    Write-Warning "Error with Test-Server: $_"
                }
            }
            #We just want ping output
            else
            {
                Try
                {
                    #Pick out a few properties, add a status label.  If quiet output, just return the address
                    $result = $null
                    if( $result = @( Test-Connection -ComputerName $computer -Count 2 -erroraction Stop ) )
                    {
                        $Output = $result | Select -first 1 -Property Address,
                                                                      IPV4Address,
                                                                      IPV6Address,
                                                                      ResponseTime,
                                                                      @{ label = "STATUS"; expression = {"Responding"} }

                        if( $quiet )
                        {
                            $Output.address
                        }
                        else
                        {
                            $Output
                        }
                    }
                }
                Catch
                {
                    if(-not $quiet)
                    {
                        #Ping failed.  I'm likely making inappropriate assumptions here, let me know if this is the case : )
                        if($_ -match "No such host is known")
                        {
                            $status = "Unknown host"
                        }
                        elseif($_ -match "Error due to lack of resources")
                        {
                            $status = "No Response"
                        }
                        else
                        {
                            $status = "Error: $_"
                        }

                        "" | Select -Property @{ label = "Address"; expression = {$computer} },
                                              IPV4Address,
                                              IPV6Address,
                                              ResponseTime,
                                              @{ label = "STATUS"; expression = {$status} }
                    }
                }
            }
        }
    }
}
