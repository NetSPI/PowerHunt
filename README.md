# Invoke-HuntPersistPR
Invoke-HuntPersistPR is a PowerShell framework that can be used for collecting and analyzing data at the beginning of threat hunting exercises that focus on common persistence and related techniques.

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

