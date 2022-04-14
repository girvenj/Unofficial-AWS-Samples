<#
    .SYNOPSIS
    Set-WindowsTenancyToDh.ps1

    .DESCRIPTION
    This script will allow to convert an instances tenancy from DI or ST to DH.
        It will:
        * Stop the EC2 instance if it is running
        * Convert the tenancy to dedciated host
        * Start the EC2 instance

    This script requires the following AWS Powershell modules:
        * AWS.Tools.Common 
        * AWS.Tools.EC2
        * AWS.Tools.LicenseManager

    .EXAMPLE
    # Set Single Instance to DH Tenancy (Specific Host)
    .\Set-WindowsTenancyToDh.ps1 -HostId 'h-00980ea1875ea839d' -InstanceId 'i-017aaebcc4835bbad' -Region 'us-west-2'

    # Set Single Instance to DH Tenancy (Host Resource Group)
    .\Set-WindowsTenancyToDh.ps1  -HostId 'h-0eb7f07f1558b5dec' -HostResourceGroupName 'WindowsServer' -InstanceId 'i-0c29897cc49a77294' -LicenseConfigurationName 'WindowsServer' -Region 'us-west-2'

    .NOTES
    Author: Jeremy J Girven
    Author E-Mail: girvenj@amazon.com
    Author Company: Amazon Web Services
    Date: 04/4/2022
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)][String]$HostId,
    [Parameter(Mandatory = $false)][String]$HostResourceGroupName,
    [Parameter(Mandatory = $true)][String[]]$InstanceId,
    [Parameter(Mandatory = $false)][String]$LicenseConfigurationName,
    [Parameter(Mandatory = $true)][String]$Region
)

Foreach ($Instance in $InstanceId) {

    Write-Output "Getting instance information for $Instance"
    Try {
        $InstanceDetails = Get-EC2Instance -InstanceId $Instance -Region $Region -ErrorAction Stop
    } Catch [System.Exception] {
        Return "Unable to get instance information $_"
    }
    $InstanceFamily = ($InstanceDetails | Select-Object -ExpandProperty 'Instances' | Select-Object -ExpandProperty 'InstanceType' | Select-Object -ExpandProperty 'Value').Split('.')[0]

    if ($InstanceFamily -eq 't3') {
        Return 'For T3 instances, you cannot change the tenancy from dedicated to host, or from host to dedicated. Attempting to make one of these unsupported tenancy changes results in the InvalidTenancy error code.'
    }

    $Tenancy = $InstanceDetails | Select-Object -ExpandProperty 'Instances' | Select-Object -ExpandProperty 'Placement' | Select-Object -ExpandProperty 'Tenancy' | Select-Object -ExpandProperty 'Value'
    $State = $InstanceDetails | Select-Object -ExpandProperty 'Instances' | Select-Object -ExpandProperty 'State' | Select-Object -ExpandProperty 'Name' | Select-Object -ExpandProperty 'Value'
    $OwnerAccount = $InstanceDetails | Select-Object -ExpandProperty 'OwnerId'

    If ($Tenancy -ne 'host') {

        Write-Output "Checking if $Instance is in a stopped state, if not stopping the instance."
        If ($State -ne 'stopped') {
            Try {
                $Null = Stop-EC2Instance -InstanceId $Instance -Force -Region $Region -ErrorAction Stop
            } Catch [System.Exception] {
                Return "Failed to execute stop command on instance $Instance. $_"
            }
            Start-Sleep -Seconds 5
            $StopInstanceCounter = 0
            Do {
                $State = Get-EC2Instance -InstanceId $Instance -Region $Region -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'Instances' | Select-Object -ExpandProperty 'State' | Select-Object -ExpandProperty 'Name' | Select-Object -ExpandProperty 'Value'
                If ($State -ne 'Stopped') {
                    $StopInstanceCounter ++
                    Write-Output "Instance $Instance is still stopping, sleeping 5 seconds and will check again."
                    Start-Sleep -Seconds 5
                }
            } Until ($State -eq 'Stopped' -or $StopInstanceCounter -ge 120)
        }

        If ($StopInstanceCounter -ge 60) {
            Return "Instance $Instance failed to stop in a reasonable time." 
        }

        Write-Output "Setting instance $Instance tenancy to the desired value Host."
        If ($Null -eq $HostId) {
            Return 'HostId is missing, please add the parameter and try again'
        }

        Try {
            $Null = Edit-EC2InstancePlacement -InstanceId $Instance -Affinity 'host' -Tenancy 'host' -HostId $HostId -Force -Region $Region -ErrorAction Stop
        } Catch [System.Exception] {
            Return "Failed to set instance $Instance tenancy to the desired value host and host $HostId. $_"
        }

        If ($HostResourceGroupName -and $LicenseConfigurationName) {
            Try {
                $LicenseConfigurationArn = Get-LICMLicenseConfigurationList -Region $Region -ErrorAction Stop | Where-Object { $_.Name -eq $LicenseConfigurationName } | Select-Object -ExpandProperty 'LicenseConfigurationArn'
                $LicenseSpecification = New-Object -TypeName 'Amazon.LicenseManager.Model.LicenseSpecification'
                $LicenseSpecification.LicenseConfigurationArn = $LicenseConfigurationArn
                $Null = Update-LICMLicenseSpecificationsForResource -ResourceArn "arn:aws:ec2:$($Region):$($OwnerAccount):instance/$($Instance)" -AddLicenseSpecification $LicenseSpecification -Force -Region $Region -ErrorAction Stop   
                $HostResourceGroupArn = Get-RGGroupList -Region $Region -ErrorAction Stop | Where-Object { $_.GroupName -eq $HostResourceGroupName }  | Select-Object -ExpandProperty 'GroupArn'
                $Null = Edit-EC2InstancePlacement -InstanceId $Instance -Tenancy 'host' -HostResourceGroupArn $HostResourceGroupArn -Force -Region $Region -ErrorAction Stop
            } Catch [System.Exception] {
                Return "Failed to set instance $Instance tenancy to the desired value HRG $HostResourceGroupArn. $_"
            }
        }

        Write-Output "Starting instance $Instance"
        Try {
            $Null = Start-EC2Instance -InstanceId $Instance -Force -Region $Region -ErrorAction Stop
        } Catch [System.Exception] {
            Return "Failed to start instance $Instance $_"
        }        
    } Else {
        Write-Output 'Instance is already set to the desired affinity'
    }
}