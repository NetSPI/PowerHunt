# Invoke-HuntPersistPR
Invoke-HuntPersistPR is a PowerShell framework designed to use PowerShell Remoting to collect and analyze data at the beginning of threat hunting exercises that focus on common persistence and related techniques. This script is intended to be used by security teams that can operate from a privileged context within their Active Directory domain.  This is not a novel idea, but I thought it was worth sharing for those who may be interested in playing with it.

User and developer guides can be found on the wiki  <a href="https://github.com/NetSPI/Invoke-HuntPersistPR/wiki">here</a>.

## TODO
* fix counts ... some are pathname and some are filepath; there may be others - consider makes count analysis modules instead
* Finalize credentials passthrough to ldap and remoting sessions
* Add single target
* Add group of targets
* Add -OnlyCollection flag
* Add -OnlyAnalysis -SourcePath flags
* Create an HTML summary report (summary for disco, collection, analysis; main page for each with dig in html files)
  * update collect-process to include owner pesecurity information
* add analysis-process-outlier-file-owner
* add analysis-process-lobas
* add analysis-task-author-run-user-mismatch
* add analysis-task-outliers-owner
* add analysis-task-outliers-user
* add analysis-task-outliers-creation
* add analysis-service-account-user
* update collect-startup-files-allusers to cover more directories
* update collect-startup-registry-run to cover HKU, not just HKLM
* add execution flow diagram
* update baked in help

## Script Authors
### Primary
Scott Sutherland (@_nullbind) <Br>
![Twitter Follow](https://img.shields.io/twitter/follow/_nullbind.svg?style=social)
### Secondardy
These individuals wrote open source code that was used as part of this project. A big thank you goes out them and their work!<br>
|Name|Site|
|:--------------------------------|:-----------|
|Eric Gruber (@egru)|https://github.com/NetSPI/PESecurity
|BoeProx (@proxb)|https://mcpmag.com/articles/2017/07/27/gathering-installed-software-using-powershell.aspx
|Will Schroeder (@harmj0y)|https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
|Warren F (@pscookiemonster)|https://github.com/RamblingCookieMonster/Invoke-Parallel
