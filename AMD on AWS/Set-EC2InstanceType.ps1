<#
    .SYNOPSIS
    Set-EC2InstanceType.ps1

    .DESCRIPTION
    This script will convert an EC2 instance from its existing type into a new type and optimize the vCPU count.
    It will first check to see if the EC2 instance is already set to the desired EC2 instance type.
    If the EC2 instance is not set to the desired type it will:
        1. Backup EC2 instance
        2. Stop EC2 instance
        3. Update EC2 instance to the desired EC2 instance type
        4. Optionally update EC2 instance CPU Options
        5. Start EC2 instance and wait for EC2 health checks to go green

    .EXAMPLE
    .\Set-EC2InstanceType.ps1 -DesiredInstanceType 'r8a.4xlarge' -CoreCount 8 -ThreadsPerCore 1 -InstanceId 'i-0eb1fe19212a66c5c' -Region 'us-west-2'
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][String]$DesiredInstanceType,
    [Parameter(Mandatory = $true)][String]$CoreCount = 999,
    [Parameter(Mandatory = $true)][String]$ThreadsPerCore = 999,
    [Parameter(Mandatory = $true)][String]$InstanceId,
    [Parameter(Mandatory = $true)][String]$Region
)

Write-Output "Getting EC2 instance information for $InstanceId"
Try {
    $InstanceDetails = Get-EC2Instance -InstanceId $InstanceId -Region $Region -ErrorAction Stop
} Catch [System.Exception] {
    Return "Unable to get EC2 instance information $_"
}

$State = $InstanceDetails | Select-Object -ExpandProperty 'Instances' | Select-Object -ExpandProperty 'State' | Select-Object -ExpandProperty 'Name' | Select-Object -ExpandProperty 'Value'
$InstanceType = $InstanceDetails | Select-Object -ExpandProperty 'Instances' | Select-Object -ExpandProperty 'InstanceType' | Select-Object -ExpandProperty 'Value'

If ($InstanceType | Where-Object { $_ -like "*g.*" }) {
    Return "EC2 instance is a Graviton (ARM) Instance, switching between ARM and x86 is not supported and will fail to launch."
}

If ($InstanceType -ne $DesiredInstanceType) {
    Try {
        $Random = Get-Random
        $Null = New-EC2Image -InstanceId $InstanceId -Name "instance-conversion-$InstanceId-$Random" -Description "Instance conversion backup" -NoReboot $true -Region $Region -ErrorAction Stop
    } Catch [System.Exception] {
        Return "Failed to execute image backup on EC2 instance $InstanceId. $_"
    }

    If ($State -ne 'stopped') {
        Write-Output "EC2 instance $InstanceId is currently running, stopping the EC2 instance to change it's type."
        Try {
            $Null = Stop-EC2Instance -InstanceId $InstanceId -Force -Region $Region -ErrorAction Stop
        } Catch [System.Exception] {
            Return "Failed to execute stop command on EC2 instance $InstanceId. $_"
        }

        Start-Sleep -Seconds 5
        $StopInstanceCounter = 0
        
        Do {
            $State = Get-EC2Instance -InstanceId $InstanceId -Region $Region -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'Instances' | Select-Object -ExpandProperty 'State' | Select-Object -ExpandProperty 'Name' | Select-Object -ExpandProperty 'Value'
            If ($State -ne 'Stopped') {
                $StopInstanceCounter ++
                Write-Output "EC2 instance $InstanceId is still stopping, sleeping 5 seconds and will check again."
                Start-Sleep -Seconds 5
            }
        } Until ($State -eq 'Stopped' -or $StopInstanceCounter -ge 120)
    }

    If ($StopInstanceCounter -ge 120) {
        Return "Instance $InstanceId failed to stop in a reasonable time."
    }

    Write-Output "Updating the EC2 instance $InstanceId instance type from $InstanceType to $DesiredInstanceType."
    Try {
        $Null = Edit-EC2InstanceAttribute -InstanceId $InstanceId -Attribute "instanceType" -Value $DesiredInstanceType -Region $Region -ErrorAction Stop
    } Catch [System.Exception] {
        Return "Failed to update EC2 instance $InstanceId to $DesiredInstanceType instance type $_"
    }

    If ($CoreCount -ne 999 -and $ThreadsPerCore -ne 999) {
        Write-Output "Updating the EC2 instance $InstanceId CPU Options."
        Try {
            $Null = Edit-EC2InstanceCpuOption -InstanceId $InstanceId -CoreCount $CoreCount -ThreadsPerCore $ThreadsPerCore -Region $Region -Force -ErrorAction Stop
        } Catch [System.Exception] {
            Return "Failed to update EC2 instance $InstanceId CPU Options $_"
        }
    }

    Write-Output "Starting EC2 instance $InstanceId"
    Try {
        $Null = Start-EC2Instance -InstanceId $InstanceId -Force -Region $Region -ErrorAction Stop
    } Catch [System.Exception] {
        Return "Failed to start EC2 instance $InstanceId $_"
    }

    Start-Sleep -Seconds 5
    
    $StartInstanceCounter = 0
    Do {
        $State = Get-EC2Instance -InstanceId $InstanceId -Region $Region -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'Instances' | Select-Object -ExpandProperty 'State' | Select-Object -ExpandProperty 'Name' | Select-Object -ExpandProperty 'Value'
        If ($State -ne 'Running') {
            $StartInstanceCounter ++
            Write-Output "EC2 instance $InstanceId is still starting, sleeping 5 seconds and will check again."
            Start-Sleep -Seconds 5
        }
    } Until ($State -eq 'Running' -or $StartInstanceCounter -ge 120)
    
    If ($StartInstanceCounter -ge 60) {
        Return "Instance $InstanceId failed to start in a reasonable time."
    }
} Else {
    Write-Output "EC2 instance $InstanceId instance already set to the desired EC2 instance type."
}
