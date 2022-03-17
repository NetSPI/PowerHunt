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
* Windows services
* Windows scheduled tasks
* WMI providers
* WMI subscriptions
* Startup Files: Starup Folders
* Startup Registry: Run keys
* Installed software
* Named pipes
* Event 4732 (A member was added to a security-enabled local group)
* Event 1102 (Audit log cleared)

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
Scott Sutherland (@_nullbind) ![Twitter Follow](https://img.shields.io/twitter/follow/_nullbind.svg?style=social)
### Secondardy
These individuals wrote open source code that was used as part of this project.<br>
|Name|Site|
|:--------------------------------|:-----------|
|Eric Gruber (@egru)|https://github.com/NetSPI/PESecurity
|BoeProx (@proxb)|https://mcpmag.com/articles/2017/07/27/gathering-installed-software-using-powershell.aspx
|Will Schroeder (@harmj0y)|https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
|Warren F (@pscookiemonster)|https://github.com/RamblingCookieMonster/Invoke-Parallel
