# Invoke-HuntPersistPR
Invoke-HuntPersistPR is a PowerShell framework designed to use PowerShell Remoting to collect and analyze data at the beginning of threat hunting exercises that focus on common persistence and related techniques. This script is intended to be used by security teams that can operate from a privileged context within their Active Directory domain.  This is not a novel idea, but I thought it was worth sharing for those who may be interested in playing with it.

## Requirements
* Domain user credentials
* Administrative privileges on the collection targets and local system
* PowerShell Remoting must be enabled and accessible on the target systems

## Command Examples
Run from domain joined system and use default domain controller:
<pre>Invoke-HuntPersistPR -OutputDirectory "c:\temp" -Threads 100 -DomainController 10.1.1.1</pre>

Run from domain joined system and use provided domain controller:
<pre>Invoke-HuntPersistPR -OutputDirectory "c:\temp" -Threads 100</pre> 

Run from non-domain joined system:
<pre>
runas /netonly /user:domain\user powershell.exe
Invoke-HuntPersistPR -Threads 100 -OutputDirectory c:\temp -DomainController 10.1.1.1 -Username domain\user -password 'password'
</pre>

## Command Benchmarks
* Based on initial testing collection can be conduct across approximetly 2000 system an hour.
* Please note that if analysis modules are not disabled, time to script completion may be longer.

## Framework Structure Summary
Invoke-HuntPersistPR.psm1<br>
\windows<br>
\windows\modules<br>
\windows\modules\collection<br>
\windows\modules\analysis<br>
                
## Collection Modules
Below is a summary of the currently supported collection modules.
|Module|MITRE ID|Description|Collection Method
|:--------------------------------|:-----------|:-----------|:-----------|
|collect-tasks|T1053.002|Collects Windows scheduled task information.|Get-ScheduledTask
|collect-services|T1569.002|Collects Windows service information.|Get-WmiObject -Class win32_service
|collect-wmi-providers|T1047|Collects WMI provider information.|Get-WmiObject -Class __Win32Provider
|collect-wmi-subscriptions|T1546.003|WMI Subscriptions|Collects WMI subscription information.|Get-WmiObject -Namespace root/subscription
|collect-startup-files-allusers|T1547.001|Collect information from all users startup folders|$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\StartUp\
|collect-startup-registry-run|T1547.001|Collect information from registry run keys|HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
|collect-installed-software|T1505|Installed Software|Get-Software
|collect-named-pipes|T1570|Collect information from named pipes|Get-ChildItem \\.\pipe\
|collect-events-4732|T1136.001|Event 4732|Collect information from 4732 events (member added to security-enabled local group)|Get-WinEvent -FilterHashtable @{logname="security"; id="4732"}
|collect-events-1102|T1070.001|Event 1102|Collect information from 1102 events (audit log cleared)|Get-WinEvent -FilterHashtable @{logname="security"; id="1102"}

## Analysis Modules / Filters
* LOLBAS
* Remote management software
* Known bad named pipes
* Unsigned binaries
* .net binaries
* File owner outliers (stacking)
* File path outliers  (stacking)

## Script Authors
### Primary
Scott Sutherland (@_nullbind) <Br>
![Twitter Follow](https://img.shields.io/twitter/follow/_nullbind.svg?style=social)
### Secondardy
These individuals wrote open source code that was used as part of this project.<br>
|Name|Site|
|:--------------------------------|:-----------|
|Eric Gruber (@egru)|https://github.com/NetSPI/PESecurity
|BoeProx (@proxb)|https://mcpmag.com/articles/2017/07/27/gathering-installed-software-using-powershell.aspx
|Will Schroeder (@harmj0y)|https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
|Warren F (@pscookiemonster)|https://github.com/RamblingCookieMonster/Invoke-Parallel
