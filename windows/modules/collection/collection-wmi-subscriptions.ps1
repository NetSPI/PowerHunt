# Script : Invoke-HuntPersistPR
# Module : collect-wmi-subscriptions
# Version: 1.0
# Author : Scott Sutherland
# Author : Alexander Polce Leary (Add-ObjectWMI)
# Summary: This is script is part of the Invoke-HuntPersistPR framework 
#          and is used to collect wmi subscription data.
# License: 3-clause BSD

    #--------------------------------------------------------------------------------
    # Add-ObjectWMI
    #--------------------------------------------------------------------------------
    Function local:Add-ObjectWMI{
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true,  Position=0, ValueFromPipeline=$true,
                ValueFromPipelineByPropertyName=$true, HelpMessage="Name")]
                [string]$Name = "",
            [Parameter(Mandatory=$true, ValueFromPipeline=$true, 
                ValueFromPipelineByPropertyName=$true, HelpMessage="Class")]
                [string]$Class = "",
            [Parameter(Mandatory=$true, ValueFromPipeline=$true, 
                ValueFromPipelineByPropertyName=$true, HelpMessage="Object")]
                [string]$Object = ""
        )
        Return New-Object psobject -Property @{
			
			DataSource1 = "WMI subscription"
			
            DataSource2 = "Get-WmiObject -Namespace root/subscription"
			
            Name = $Name
            Class = $Class

            Object = $Object

            Query = New-Object System.String([String]::Empty)

            CommandLineTemplate = New-Object System.String([String]::Empty)

            Filter = New-Object System.String([String]::Empty)
            Consumer = New-Object System.String([String]::Empty)
        }
    }

    #--------------------------------------------------------------------------------
    # WMI Provider/Trigger
    #--------------------------------------------------------------------------------
    Function Invoke-AuditWmi{
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$false, HelpMessage="Log file path.")]
                [string]$LogFile = "AuditWMIProvider.log"
        )
        Begin {
            $entries = New-Object System.Collections.Generic.List[System.Management.Automation.PSObject]
        } Process {
            Get-WmiObject -Namespace root/subscription -Class __EventFilter | 
            ForEach-Object {
                $Filter = Add-ObjectWMI -Name $_.Name -Class $_.__Class -Object $_
                $Filter.Query = $_.Query
                $entries.Add($Filter)
            }
            Get-WmiObject -Namespace root/subscription -Class __EventConsumer | 
            ForEach-Object {
                $Filter = Add-ObjectWMI -Name $_.Name -Class $_.__Class -Object $_
                $Filter.CommandLineTemplate = $_.CommandLineTemplate
                $entries.Add($Filter)
            }
            Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding | 
            ForEach-Object {
                $Filter = Add-ObjectWMI -Name $_.__RELPATH -Class $_.__Class -Object $_
                $Filter.Filter = $_.Filter
                $Filter.Consumer = $_.Consumer
                $entries.Add($Filter)
            }
        } End {
            $entries
        }
} 
;Invoke-AuditWmi;
