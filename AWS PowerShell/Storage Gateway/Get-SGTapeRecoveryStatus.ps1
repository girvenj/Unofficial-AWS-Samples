<#
    .SYNOPSIS
    Get-SGTapeRecoveryStatus.ps1

    .DESCRIPTION
    This script will return the status of tape(s) and out put the tape status and ARN.  

    .EXAMPLE
    # Manually add ARNS
    .\Get-SGTapeRecoveryStatus.ps1 -TapeARN 'ARN1', 'ARN2' -Region 'us-east-2'

    # Pull barcodes from a list
    .\Get-SGTapeRecoveryStatus.ps1 -TapeARN (Get-Content -Path 'C:\Temp\RetrievalOutput2021-06-01-T12.txt') -Region 'us-east-2'
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][String[]]$TapeARN,
    [Parameter(Mandatory = $true)][String]$Region
)

#==================================================
# Main
#==================================================

[System.Collections.ArrayList]$Output = @()
Write-Output 'INFO: Getting tape status'
Foreach ($Ta in $TapeARN) {
    $TapeStatus = Get-SGTapeArchiveList -TapeARN $Ta -Region $Region | Select-Object -ExpandProperty 'TapeStatus' -ErrorAction SilentlyContinue
    $StatusOutput = [PSCustomObject][Ordered]@{
        'Tape ARN'    = $Ta
        'Tape Status' = $TapeStatus
    }
    [void]$Output.Add($StatusOutput)
}

Return $Output