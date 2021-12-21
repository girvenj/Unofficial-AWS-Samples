<#
    .SYNOPSIS
    Invoke-SGTapeRecoveryFromBarcode.ps1

    .DESCRIPTION
    This script will get the SGW ARN from it's name, enumerate all Archived tapes, and retrieve all Archived tapes.  

    .EXAMPLE
    # Manually add barcodes
    .\Invoke-SGTapeRecoveryFromBarcode.ps1 -Barcode 'bc1', 'bc2' -GatewayName 'aws-tgw-useast2-02' -Region 'us-east-2' -ReportPath 'C:\Temp'

    # Pull barcodes from a list
    .\Invoke-SGTapeRecoveryFromBarcode.ps1 -Barcode (Get-Content -Path 'C:\Temp\Barcodes.csv') -GatewayName 'aws-tgw-useast2-02' -Region 'us-east-2' -ReportPath 'C:\Temp'
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][String[]]$Barcode,
    [Parameter(Mandatory = $true)][String]$GatewayName,
    [Parameter(Mandatory = $true)][String]$Region,
    [Parameter(Mandatory = $true)][String]$ReportPath
)

#==================================================
# Variables
#==================================================

$FilePath = Join-Path -Path $ReportPath -ChildPath "RetrievalOutput$(Get-Date -Format 'yyyy-MM-dd-THH').txt"

#==================================================
# Functions
#==================================================

Function Get-PSModule {

    $CurrentPSVersion = $PSVersionTable.PSVersion
    [version]$DesiredPSVersion = '5.1.0.0'

    If ($CurrentPSVersion -lt $DesiredPSVersion) {
        Write-Output 'ERROR: WMF5.1 Not installed, see here for the installation file: https://www.microsoft.com/en-us/download/details.aspx?id=54616'
        Exit 1
    }

    $PPPresent = Get-PackageProvider -Name 'Nuget' -Force -ErrorAction SilentlyContinue
    If (-not $PPPresent) {
        Write-Output 'INFO: Installing the NuGet package provider'
        Try {
            $Null = Install-PackageProvider -Name 'NuGet' -MinimumVersion '2.8.5' -Force -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "ERROR: Failed to install NuGet package provider $_"
            Exit 1
        }
    }

    $PsRepPresent = Get-PSRepository -Name 'PSGallery' | Select-Object -ExpandProperty 'InstallationPolicy' -ErrorAction SilentlyContinue
    If ($PsRepPresent -ne 'Trusted') {
        Write-Output 'INFO: Setting PSGallery respository to trusted'
        Try {
            Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "ERROR: Failed to set PSGallery respository to trusted $_"
            Exit 1
        }
    }

    $ModPresent = Get-Module -Name 'AWS.Tools.StorageGateway' -ListAvailable
    If (-not $ModPresent) {
        Write-Output 'INFO: Downloading and installing the required PowerShell module'
        Try {
            Install-Module 'AWS.Tools.StorageGateway' -AllowClobber -Force -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "ERROR: Failed to download and install the required PowerShell module $_"
            Exit 1
        }
    }
}

#==================================================
# Main
#==================================================

Write-Output 'INFO: Ensuring Proper PS Module is present'
Get-PSModule

Write-Output 'INFO: Getting Storage Gateway ARN'
Try {
    $Gateway = Get-SGGateway -Region $Region | Where-Object { $_.GatewayName -eq $GatewayName -and $_.GatewayType -eq 'VTL' } | Select-Object -ExpandProperty 'GatewayARN'
} Catch [System.Exception] {
    Write-Output "ERROR: Failed to retrieve $GatewayName ARN $_"
    Exit 1
}

If ($Null -eq $Gateway) {
    Write-Output "ERROR: No Gateway with name of $GatewayName present, exiting"
    Exit 1
}

Write-Output 'INFO: Enumerating all tapes in the region to parse them by thier barcode'
Try {
    $Tapes = Get-SGTape -Limit '30000' -Region $Region -ErrorAction Stop | Where-Object { $_.TapeStatus -eq 'ARCHIVED' }
} Catch [System.Exception] {
    Write-Output "ERROR: Failed to enumerate tapes $_"
    Exit 1
}

If ($Null -eq $Tapes) {
    Write-Output 'ERROR: No Tapes found, exiting'
    Exit 1
}

Write-Output 'INFO: Adding tapes that match barcode(s) to array for retrieval'
[System.Collections.ArrayList]$RetrieveTapes = @()
Foreach ($Bc in $Barcode) {
    $Match = $Tapes | Where-Object { $_.TapeBarcode -eq $Bc } | Select-Object -ExpandProperty 'TapeARN'
    If ($Match) {
        [void]$RetrieveTapes.Add($Match)
    }
}

Write-Output 'INFO: Starting tape retrieval(s)'
Foreach ($RetrieveTape in $RetrieveTapes) {
    Write-Output "INFO: Starting tape retrieval for $RetrieveTape"
    Try {
        $Null = Get-SGTapeArchive -GatewayARN $Gateway -TapeARN $RetrieveTape -Region $Region -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "ERROR: Failed to retrieve $RetrieveTape $_"
        Exit 1
    }
}

$RetrieveTapes | Out-File $FilePath

$FileOutput = [PSCustomObject][Ordered]@{
    'Retrieved Tape ARN File'    = $FilePath
}

Return $FileOutput