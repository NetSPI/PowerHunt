# Invoke-HuntPersistPR
<a href="https://github.com/NetSPI/Invoke-HuntPersistPR/wiki"><strong>Invoke-HuntPersistPR</strong></a> is a modular hunting framework written in PowerShell designed to: 
*  Identify signs of compromise based on artifacts left behind by common MITRE ATT&CK techniques.  It is not designed for identifying known bad files/domains/IPs associated with specific APTs/malware. However, it would be easy to write modules for that. ;)
* <strong>Discover</strong> accessible systems associated with a Active Directory domain automatically.
* <strong>Collect</strong> data source information from systems using PowerShell Remoting and easy to build collection modules.
* <strong>Analyze</strong> collected data using easy to build analysis modules based on behavior.
* <strong>Repport</strong> summary data and initial insights that can help analysts get started on simple threat hunting exercises that focus on common persistence and related techniques.

This is not a novel approach to hunting, but I thought the project was worth sharing for those who want to play with it. User and developer guides can be found on the wiki  <a href="https://github.com/NetSPI/Invoke-HuntPersistPR/wiki">here</a>.<Br>

<strong>Author</strong><Br>
Scott Sutherland (@_nullbind) <Br>

<strong>License</strong><Br>
BSD 3-Clause

## TODO
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




