<#
    .SYNOPSIS
    Set-WindowsTenancyandLicense.ps1

    .DESCRIPTION
    This script will allow to convert an instances tenancy and licensing type from DH to ST and BYOL and LI and vice versa
        It will:
        * Create an temporary inline IAM policy with the required permissions to convert the instance (https://docs.aws.amazon.com/license-manager/latest/userguide/conversion-prerequisites.html)
        * Stop the EC2 instance if it is running
        * Convert the license type from 0800 (Windows BYOL) to 0002 (Windows License Included) or vice versa
        * Convert the tenancy from dedicated to shared or to dedciated
        * Remove the temporary inline IAM policy
        * Start the EC2 instance

    This script requires the following AWS Powershell modules:
        * AWS.Tools.Common 
        * AWS.Tools.EC2 
        * AWS.Tools.IdentityManagement
        * AWS.Tools.LicenseManager

    .EXAMPLE
    # Set Single Instance to Shared Tenancy and LI
    .\Set-WindowsTenancyandLicense.ps1 -DesiredTenancy 'Default' -DesiredUsageOperation 'WindowsServer-LI' -InstanceId 'i-0cd4ae8dddbf98572' -Region 'us-west-2'

    # Set Single Instance to DH Tenancy (Specific Host) and BYOL
    .\Set-WindowsTenancyandLicense.ps1 -DesiredTenancy 'Host' -DesiredUsageOperation 'WindowsServer-BYOL' -HostId 'h-02bcfb106e8a7d696' -InstanceId 'i-0cd4ae8dddbf98572' -Region 'us-west-2'

    # Set Single Instance to DH Tenancy (Host Resource Group) and BYOL
    .\Set-WindowsTenancyandLicense.ps1 -DesiredTenancy 'Host' -DesiredUsageOperation 'WindowsServer-BYOL' -HostId 'h-0d66b2ac83db440be' -HostResourceGroupName 'WindowsServer' -InstanceId 'i-0cd4ae8dddbf98572' -LicenseConfigurationName 'WindowsServer' -Region 'us-west-2'

    # Set Multiple Instances to Shared Tenancy and LI
    .\Set-WindowsTenancyandLicense.ps1 -DesiredTenancy 'Default' -DesiredUsageOperation 'WindowsServer-LI' -InstanceId (Get-Content -Path 'C:\Temp\instances.csv') -Region 'us-west-2'

    .NOTES
    Author: Jeremy J Girven
    Author E-Mail: girvenj@amazon.com
    Author Company: Amazon Web Services
    Date: 03/10/2022
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][ValidateSet('default', 'host')][String]$DesiredTenancy,
    [Parameter(Mandatory = $true)][ValidateSet('WindowsServer-LI', 'WindowsServer-BYOL')][String]$DesiredUsageOperation,
    [Parameter(Mandatory = $false)][String]$HostId,
    [Parameter(Mandatory = $false)][String]$HostResourceGroupName,
    [Parameter(Mandatory = $true)][String[]]$InstanceId,
    [Parameter(Mandatory = $false)][String]$LicenseConfigurationName,
    [Parameter(Mandatory = $true)][String]$Region
)

Switch ($DesiredUsageOperation) {
    'WindowsServer-LI' { $DesiredUsageOperationValue = '0002' }
    'WindowsServer-BYOL' { $DesiredUsageOperationValue = '0800' }
    default { Return 'No valid values set' }
}

$DesiredTenancy = $DesiredTenancy.ToLower()

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
    $IamInstanceProfileArn = $InstanceDetails | Select-Object -ExpandProperty 'Instances' | Select-Object -ExpandProperty 'IamInstanceProfile' | Select-Object -ExpandProperty 'Arn'
    $CurrentUsageOperationValue = ($InstanceDetails | Select-Object -ExpandProperty 'Instances' | Select-Object -ExpandProperty 'UsageOperation').split(':')[1]
    $State = $InstanceDetails | Select-Object -ExpandProperty 'Instances' | Select-Object -ExpandProperty 'State' | Select-Object -ExpandProperty 'Name' | Select-Object -ExpandProperty 'Value'
    $OwnerAccount = $InstanceDetails | Select-Object -ExpandProperty 'OwnerId'

    Write-Output "Getting IAM role attached to $Instance"
    $RoleName = Get-IAMInstanceProfileList -ErrorAction SilentlyContinue | Where-Object { $_.Arn -eq $IamInstanceProfileArn } | Select-Object -ExpandProperty 'Roles' | Select-Object -ExpandProperty 'RoleName'
    If ($Null -eq $RoleName) {
        Return "Instance $Instance does not have a role attached. Please attach role and try again. $_"
    }

    Write-Output "Creating inline IAM policy and attaching it to the role $RoleName"
    Try {
        Write-IAMRolePolicy -RoleName $RoleName -PolicyName 'BYOL-LM-Conversion-Inline-Policy' -PolicyDocument (@{ Version = '2012-10-17'; Statement = @( @{ Effect = 'Allow'; Action = @('ssm:GetInventory', 'ssm:StartAutomationExecution', 'ssm:GetAutomationExecution', 'ssm:SendCommand', 'ssm:GetCommandInvocation', 'ssm:DescribeInstanceInformation', 'ec2:DescribeInstances', 'ec2:StartInstances', 'ec2:StopInstances', 'license-manager:CreateLicenseConversionTaskForResource', 'license-manager:GetLicenseConversionTask', 'license-manager:ListLicenseConversionTasks', 'license-manager:GetLicenseConfiguration', 'license-manager:ListUsageForLicenseConfiguration', 'license-manager:ListLicenseSpecificationsForResource', 'license-manager:ListAssociationsForLicenseConfiguration', 'license-manager:ListLicenseConfigurations'); Resource = @('*') }) } | ConvertTo-Json -Depth 3) -Force
    } Catch [System.Exception] {
        Return "Unable to create inline IAM policy and attach it to the instance. $_"
    }

    Start-Sleep -Seconds 2

    If ($DesiredUsageOperationValue -ne $CurrentUsageOperationValue) {
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

        Write-Output "Executing License Conversion Task to set instance $Instance to $DesiredUsageOperation."
        Try {
            $LicenseConversionTaskId = New-LICMLicenseConversionTaskForResource -ResourceArn "arn:aws:ec2:$($Region):$($OwnerAccount):instance/$($Instance)" -DestinationLicenseContext_UsageOperation "RunInstances:$DesiredUsageOperationValue" -SourceLicenseContext_UsageOperation "RunInstances:$CurrentUsageOperationValue" -Force -Region $Region -ErrorAction Stop
        } Catch [System.Exception] {
            Return "Failed to execute License Conversion Task for instance $Instance. $_"
        }

        Start-Sleep -Seconds 5

        $LicenseConversionTaskCounter = 0
        Do {
            $LicenseConversionTaskStatus = Get-LICMLicenseConversionTask -LicenseConversionTaskId $LicenseConversionTaskId -Region $Region -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'Status' | Select-Object -ExpandProperty 'Value'
            If ($LicenseConversionTaskStatus -eq 'IN_PROGRESS') {
                $LicenseConversionTaskCounter ++
                Write-Output 'Conversion task still running sleeping 10 seconds and will check again.'
                Start-Sleep -Seconds 10
            } Elseif ($LicenseConversionTaskStatus -eq 'FAILED') {
                Return "License Conversion Task to set instance $Instance to $DesiredUsageOperation failed."
            }
        } Until ($LicenseConversionTaskStatus -eq 'SUCCEEDED' -or $LicenseConversionTaskStatus -eq 'FAILED' -or $LicenseConversionTaskCounter -ge 60)

        If ($LicenseConversionTaskCounter -ge 30) {
            Return "License Conversion Task for instance $Instance failed to execute in a reasonable time." 
        }
    } Else {
        Write-Output "Instance $Instance UsageOperation already set to desired value"
    }

    If ($DesiredTenancy -ne $Tenancy) {
        Write-Output "Setting instance $Instance tenancy to the desired value $DesiredTenancy."
        Switch ($DesiredTenancy) {
            'host' {
                If ($Null -eq $HostId){
                    Return 'HostId is missing, please add the parameter and try again'
                }

                Try {
                    $Null = Edit-EC2InstancePlacement -InstanceId $Instance -Affinity 'host' -Tenancy $DesiredTenancy -HostId $HostId -Force -Region $Region -ErrorAction Stop
                } Catch [System.Exception] {
                    Return "Failed to set instance $Instance tenancy to the desired value $DesiredTenancy and host $HostId. $_"
                }
                If ($HostResourceGroupName -and $LicenseConfigurationName) {
                    Try {
                        $LicenseConfigurationArn = Get-LICMLicenseConfigurationList -Region $Region -ErrorAction Stop | Where-Object { $_.Name -eq $LicenseConfigurationName } | Select-Object -ExpandProperty 'LicenseConfigurationArn'
                        $LicenseSpecification = New-Object -TypeName 'Amazon.LicenseManager.Model.LicenseSpecification'
                        $LicenseSpecification.LicenseConfigurationArn = $LicenseConfigurationArn
                        $Null = Update-LICMLicenseSpecificationsForResource -ResourceArn "arn:aws:ec2:$($Region):$($OwnerAccount):instance/$($Instance)" AddLicenseSpecification $LicenseSpecification -Force -Region $Region -ErrorAction Stop   
                        $HostResourceGroupArn = Get-RGGroupList -Region $Region -ErrorAction Stop | Where-Object { $_.GroupName -eq $HostResourceGroupName }  | Select-Object -ExpandProperty 'GroupArn'
                        $Null = Edit-EC2InstancePlacement -InstanceId $Instance -Tenancy $DesiredTenancy -HostResourceGroupArn $HostResourceGroupArn -Force -Region $Region -ErrorAction Stop
                    } Catch [System.Exception] {
                        Return "Failed to set instance $Instance tenancy to the desired value HRG $HostResourceGroupArn. $_"
                    }
                } 
            }
            'default' {
                Try {
                    $LicenseConfigurationArn = Get-LICMLicenseSpecificationsForResourceList -ResourceArn "arn:aws:ec2:$($Region):$($OwnerAccount):instance/$($Instance)" -Region $Region | Select-Object -ExpandProperty 'LicenseConfigurationArn'
                    $LicenseSpecification = New-Object -TypeName 'Amazon.LicenseManager.Model.LicenseSpecification'
                    $LicenseSpecification.LicenseConfigurationArn = $LicenseConfigurationArn
                    $Null = Update-LICMLicenseSpecificationsForResource -ResourceArn "arn:aws:ec2:$($Region):$($OwnerAccount):instance/$($Instance)" -RemoveLicenseSpecification $LicenseSpecification -Force -Region $Region -ErrorAction Stop
                    $Null = Edit-EC2InstancePlacement -InstanceId $Instance -Tenancy $DesiredTenancy -Force -Region $Region -ErrorAction Stop
                } Catch [System.Exception] {
                    Return "Failed to set instance $Instance tenancy to the desired value $DesiredTenancy. $_"
                }
            }
        }
    } Else {
        Write-Output 'Instance is already set to the desired affinity'
    }

    Write-Output "Removing inline IAM policy attached to the role $RoleName"
    Try {
        Remove-IAMRolePolicy -RoleName $RoleName -PolicyName 'BYOL-LM-Conversion-Inline-Policy' -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Return "Failed to remove inline IAM policy attached to the role $RoleName $_"
    }

    Write-Output "Starting instance $Instance"
    Try {
        $Null = Start-EC2Instance -InstanceId $Instance -Force -Region $Region -ErrorAction Stop
    } Catch [System.Exception] {
        Return "Failed to start instance $Instance $_"
    }
}