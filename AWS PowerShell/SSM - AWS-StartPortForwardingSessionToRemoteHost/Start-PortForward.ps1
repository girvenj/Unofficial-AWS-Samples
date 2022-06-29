<#
    .SYNOPSIS
        Start-PortForward.ps1

    .DESCRIPTION
        This script creates an temporary port forwarding instance. 
        Launches the AWS CLI and calls AWS-StartPortForwardingSessionToRemoteHost in a new window.
        Once the AWS CLI window is closed it will then terminate the temporary port forwarding instance.
        
        This script requires the following:
         * The AWS CLI installed (https://aws.amazon.com/cli/)
         * The AWS Session Manager plugin for the AWS CLI installed (https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html)
         * Either Windows PowerShell 5.1 and newer for Windows OS or PowerShell Core 6.0 and newer for macOS and Linux (https://github.com/PowerShell/PowerShell)
         * The following AWS PowerShell Modules (https://docs.aws.amazon.com/powershell/latest/userguide/pstools-getting-set-up.html)
            *  AWS.Tools.Common
            *  AWS.Tools.EC2
            *  AWS.Tools.KeyManagementService
            *  AWS.Tools.SimpleSystemsManagement            

    .EXAMPLE
        .\Start-PortForward.ps1 -IamRole 'SSMCore' -InstanceType 't4g.small' -KeyName 'Baseline' -KmsKeyId 'alias/aws/ebs' -LocalPortNumber '55677' -Region 'us-west-2' -RemotePortNumber '5432' -SecurityGroupId 'sg-1234567890adbdefg' -SubnetId 'subnet-1234567890adbdefg' -TargetHost 'database.rds.amazonaws.com'

    .NOTES
        Author: Amazon Web Services
        Date: 06/29/2022
#>

#Requires -Modules 'AWS.Tools.Common', 'AWS.Tools.EC2', 'AWS.Tools.KeyManagementService', 'AWS.Tools.SimpleSystemsManagement'

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][String]$IamRole,
    [Parameter(Mandatory = $true)][String]$InstanceType,
    [Parameter(Mandatory = $true)][String]$KeyName,
    [Parameter(Mandatory = $false)][String]$KmsKeyId = 'alias/aws/ebs',
    [Parameter(Mandatory = $true)][String]$LocalPortNumber,
    [Parameter(Mandatory = $true)][String]$Region,
    [Parameter(Mandatory = $true)][String]$RemotePortNumber,
    [Parameter(Mandatory = $true)][String[]]$SecurityGroupId,
    [Parameter(Mandatory = $true)][String]$SubnetId,
    [Parameter(Mandatory = $true)][String]$TargetHost
)

#==================================================
# Variables
#==================================================

[System.Collections.ArrayList]$TagSpecifications = @()
$NameTagKp = @{ Key = 'Name'; Value = 'SessionManagerTempInstance' }

$TagSpecInstance = New-Object -TypeName 'Amazon.EC2.Model.TagSpecification'
$TagSpecInstance.ResourceType = 'Instance'
$TagSpecInstance.Tags.Add($NameTagKp)
[void]$TagSpecifications.Add($TagSpecInstance)

$TagSpecVolume = New-Object -TypeName 'Amazon.EC2.Model.TagSpecification'
$TagSpecVolume.ResourceType = 'Volume'
$TagSpecVolume.Tags.Add($NameTagKp)
[void]$TagSpecifications.Add($TagSpecVolume)

$EbsSettings = New-Object -TypeName 'Amazon.EC2.Model.EbsBlockDevice'
$EbsSettings.VolumeSize = '30'
$EbsSettings.Iops = '3000'
$EbsSettings.Throughput = '125'
$EbsSettings.VolumeType = 'gp3'
$EbsSettings.DeleteOnTermination = 'True'
Try {
    $KmsKeyId = Get-KMSAliasList -Region $Region -ErrorAction Stop | Where-Object { $_.AliasName -eq $KmsKeyId } | Select-Object -ExpandProperty 'TargetKeyId'
} Catch [System.Exception] {
    Write-Output "Failed to get KMS Key ID to encrypt EBS volume $_"
    Return
}
$EbsSettings.Encrypted = 'True'
$EbsSettings.KmsKeyId = $KmsKeyId
$EbsInfo = New-Object -TypeName 'Amazon.EC2.Model.BlockDeviceMapping'
$EbsInfo.DeviceName = '/dev/sda1'
$EbsInfo.Ebs = $EbsSettings

#==================================================
# Main
#==================================================

Try {
    $ImageId = Get-SSMLatestEC2Image -Path 'ami-amazon-linux-latest' -ImageName 'amzn2-ami-kernel-5.10-hvm-arm64-gp2' -Region $Region -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to get latest AL2 AMI ID $_"
    Return
}

Try {
    $InstanceId = New-EC2Instance -BlockDeviceMapping $EbsInfo -ImageId $ImageId -KeyName $KeyName -InstanceType $InstanceType -SecurityGroupId $SecurityGroupId -SubnetId $SubnetId -TagSpecification $TagSpecifications -InstanceProfile_Name $IamRole -Region $Region -EncodeUserData -UserData "#!/bin/bash `r`ncd /tmp `r`nsudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_arm64/amazon-ssm-agent.rpm `r`nsudo start amazon-ssm-agent" -ErrorAction Stop | Select-Object -ExpandProperty 'Instances' | Select-Object -ExpandProperty 'InstanceId'
} Catch [System.Exception] {
    Write-Output "Failed to get latest AL2 AMI ID $_"
    Return
}

Start-Sleep -Seconds 10

Try {
    $EniId = Get-EC2Instance -InstanceId $InstanceId -Region $Region -ErrorAction Stop | Select-Object -ExpandProperty 'Instances' | Select-Object -ExpandProperty 'NetworkInterfaces' | Select-Object -ExpandProperty 'NetworkInterfaceId'
} Catch [System.Exception] {
    Write-Output "Failed to get Instance ID of temporary port forwarding instance $_"
}

$EniTagVal = New-Object -TypeName 'Amazon.EC2.Model.Tag'
$ENITagVal.Key = 'Name'
$EniTagVal.Value = $NameTagValue
Try {
    New-EC2Tag -Resource $EniId -Tag $EniTagVal -Region $Region -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to set tag on temporary port forwarding instance ENI $_"
}

$Counter = 0
Do {
    Try {
        $InstanceStatus = Get-EC2InstanceStatus -InstanceId $InstanceId -Region $Region -ErrorAction SilentlyContinue
    } Catch [System.Exception] {
        Write-Output "Failed to get Instance Status $_"
    }
    $Status = $InstanceStatus | Select-Object -ExpandProperty 'Status' | Select-Object -ExpandProperty 'Status' | Select-Object -ExpandProperty 'Value'
    $SystemStatus = $InstanceStatus | Select-Object -ExpandProperty 'SystemStatus' | Select-Object -ExpandProperty 'Status' | Select-Object -ExpandProperty 'Value'

    If ($Status -ne 'ok' -or $SystemStatus -ne 'ok') {
        $Counter ++
        If ($Counter -gt '1') {
            Write-Output 'Launch and configuration of port forwarding instance not yet complete, sleeping 10 seconds.'
            Start-Sleep -Seconds 10
        }
    }
} Until ($Counter -ge 30 -or $Status -eq 'ok' -or $SystemStatus -eq 'ok')

If ($Counter -ge 30) {
    Write-Output 'Launch and configuration of port forwarding instance failed.'
    Break
}

$ArgumentList = "ssm start-session --target $InstanceId --document-name AWS-StartPortForwardingSessionToRemoteHost --parameters `"host=$TargetHost.,localPortNumber=$LocalPortNumber,portNumber=$RemotePortNumber`""

Write-Output 'Launching AWS CLI and calling AWS-StartPortForwardingSessionToRemoteHost in a new window, close the new window when finished to terminate the port forwarding instance.'
Try {
    Start-Process aws -ArgumentList $ArgumentList -Wait -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to launch AWS CLI and / or call AWS-StartPortForwardingSessionToRemoteHost in a new Window $_"
    Return
}

Try {
    $Null = Remove-EC2Instance -InstanceId $InstanceId  -Force -Region $Region -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to terminate Port Forwarding instance $InstanceId $_"
    Return
}