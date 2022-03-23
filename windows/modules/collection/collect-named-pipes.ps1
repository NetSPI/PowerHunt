# Script : Invoke-PowerHunt
# Module : collect-named-pipes
# Version: 1.0
# Author : Scott Sutherland
# Summary: This is script is part of the PowerHunt framework 
#          and is used to collect information from named pipes.
# License: 3-clause BSD

# todo
# need to add datasource1 and datasource2 to output
Get-ChildItem \\.\pipe\  | select name
