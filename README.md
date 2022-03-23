# PowerHunt
<a href="https://github.com/NetSPI/PowerHunt/wiki"><strong>PowerHunt</strong></a> is a modular hunting framework written in PowerShell designed to: 
*  Identify signs of compromise based on artifacts left behind by common MITRE ATT&CK techniques.  It is not designed for identifying known bad files/domains/IPs associated with specific APTs/malware. However, it would be easy to write modules for that. ;)
* <strong>Discover</strong> accessible systems associated with a Active Directory domain automatically.
* <strong>Collect</strong> data source information from systems using PowerShell Remoting and easy to build collection modules.
* <strong>Analyze</strong> collected data using easy to build analysis modules based on behavior.
* <strong>Report</strong> summary data and initial insights that can help analysts get started on simple threat hunting exercises that focus on common persistence and related techniques.

This is not a novel approach to threat hunting, but I thought the project was worth sharing for those who want to play with it. User and developer guides can be found on the wiki  <a href="https://github.com/NetSPI/PowerHunt/wiki">here</a>.<Br>

<strong>Author</strong><Br>
Scott Sutherland (@_nullbind) <Br>

<strong>License</strong><Br>
BSD 3-Clause

Primary Todo
--
* Analysis: Add counts for all data sources
* Report: Create an HTML summary report (summary for disco, collection, analysis; main page for each with dig in html files)
* Final run through of all tests (domain, nondomain system; auth type; target types)






