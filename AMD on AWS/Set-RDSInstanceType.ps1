<#
    .SYNOPSIS
    Set-RDSInstanceType.ps1

    .DESCRIPTION
    This script will convert an RDS instance from its existing type to a new type and optimize the vCPU count.
    It will first check to see if the RDS instance is already set to the desired EC2 instance type.
    If the RDS instance is not set to the desired type it will:
        1. Backup RDS instance
        2. Update EC2 instance to the desired EC2 instance type
        3. Optionally update EC2 instance CPU Options

    .EXAMPLE
    .\Set-RDSInstanceType.ps1 -DesiredInstanceType 'db.r8a.4xlarge' -CoreCount '8' -ThreadsPerCore '1' -DBInstanceIdentifier 'database-1' -Region 'us-west-2'#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][String]$DesiredInstanceType,
    [Parameter(Mandatory = $true)][String]$CoreCount = 999,
    [Parameter(Mandatory = $true)][String]$ThreadsPerCore = 999,
    [Parameter(Mandatory = $true)][String]$DBInstanceIdentifier,
    [Parameter(Mandatory = $true)][String]$Region
)
#$ValidProcessorFeatures = Get-RDSValidDBInstanceModification -DBInstanceIdentifier $DBInstanceIdentifier -Region $Region -ErrorAction Stop | Select-Object -ExpandProperty 'ValidProcessorFeatures'
#$DefaultCoreCount = $ValidProcessorFeatures | Where-Object { $_.Name -eq 'coreCount' } | Select-Object -ExpandProperty 'DefaultValue'
#$DefaultThreadCount = $ValidProcessorFeatures | Where-Object { $_.Name -eq 'threadsPerCore' } | Select-Object -ExpandProperty 'DefaultValue'
$CurrentInstanceType = Get-RDSDBInstance -DBInstanceIdentifier $DBInstanceIdentifier -Region $Region -ErrorAction Stop | Select-Object -ExpandProperty 'DBInstanceClass'

If ($CurrentInstanceType -ne $DesiredInstanceType) {
    Try {
        $Random = Get-Random
        $Null = New-RDSDBSnapshot -DBSnapshotIdentifier "instance-conversion-$DBInstanceIdentifier-$Random" -DBInstanceIdentifier $DBInstanceIdentifier -Region $Region -ErrorAction Stop
    } Catch [System.Exception] {
        Return "Failed to execute image backup on RDS instance $DBInstanceIdentifier. $_"
    }

    If ($CoreCount -ne 999 -and $ThreadsPerCore -ne 999) {
        $CoreFeature = New-Object 'Amazon.RDS.Model.ProcessorFeature'
        $CoreFeature.Name = 'coreCount'
        $CoreFeature.Value = $CoreCount
        $ThreadFeature = New-Object 'Amazon.RDS.Model.ProcessorFeature'
        $ThreadFeature.Name = 'threadsPerCore'
        $ThreadFeature.Value = $ThreadsPerCore
        Edit-RDSDBInstance -DBInstanceIdentifier $DBInstanceIdentifier -DBInstanceClass $DesiredInstanceType -ProcessorFeature $CoreFeature, $ThreadFeature -ApplyImmediately $true -Region $Region -ErrorAction Stop
    } Else {
        Edit-RDSDBInstance -DBInstanceIdentifier $DBInstanceIdentifier -DBInstanceClass $DesiredInstanceType -ApplyImmediately $true -Region $Region -ErrorAction Stop
    }
}

