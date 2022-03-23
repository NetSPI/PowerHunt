# PowerHunt
<a href="https://github.com/NetSPI/PowerHunt/wiki"><strong>PowerHunt</strong></a> is a modular threat hunting framework written in PowerShell. <br><br> 
It is designed to <strong>Identify signs of compromise</strong> based on artifacts left behind by common MITRE ATT&CK techniques.  It is not designed for identifying known bad files/domains/IPs associated with specific APTs/malware. Additionally, it supports functionality to:
* <strong>Authenticate</strong> using the current user context, a credential, or clear text user/password.
* <strong>Discover</strong> accessible systems associated with a Active Directory domain automatically.
* <strong>Target</strong> a single computer, list of computers, or discovered Active Directory computers (default).
* <strong>Collect</strong> data source information from systems using PowerShell Remoting and easy to build collection modules.
* <strong>Analyze</strong> collected data using easy to build analysis modules based on behavior.
* <strong>Report</strong> summary data and initial insights that can help analysts get started on simple threat hunting exercises that focus on common persistence and related techniques.

This is not a novel approach to threat hunting, but I thought the project was worth sharing for those who want to play with it. <br>
User and developer guides can be found on the wiki  <a href="https://github.com/NetSPI/PowerHunt/wiki">here</a>.<Br>

<strong>Author</strong><Br>
Scott Sutherland (@_nullbind) <Br>

<strong>License</strong><Br>
BSD 3-Clause

Primary Todo
--
* Fix primary analysis count export file types and rerun tests
* credential object is bombing for some reason from non domain system, but password works (which is turned into a cred objects... so??)- fix
* update module name in the modules to PowerHunt
* Report: Create an HTML summary report (summary for disco, collection, analysis; main page for each with dig in html files)







