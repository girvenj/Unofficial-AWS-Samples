<#
    .SYNOPSIS
        New-WIndowsServerLMConfig.ps1

    .DESCRIPTION
        This script will create a new License Manager configuration for Windows Server and associate it the a Dedicated Host Resource Group. Note this script will not create SQL License Manager configs.

    .EXAMPLE

        .\New-WIndowsServerLMConfig.ps1 -AmiId 'ami-05a2f04bafd5b7854' -HostFamily 'c5', 'r5', 'm5' -LicenseCount '1024' -Name 'Windows-Server-Datacenter' -ProductInformationFilterValue 'Microsoft Windows Server 2019 Datacenter', 'Microsoft Windows Server 2016 Datacenter' -Region 'us-west-2'

    .NOTES
        Author: Jeremy J Girven
        Author E-Mail: girvenj@amazon.com
        Author Company: Amazon Web Services
        Date: 07/02/2021
#>


[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][String]$AmiId,
    [Parameter(Mandatory = $true)][String[]]$HostFamily,
    [Parameter(Mandatory = $true)][String]$LicenseCount,
    [Parameter(Mandatory = $true)][String]$Name,
    [Parameter(Mandatory = $true)][String[]]$ProductInformationFilterValue,
    [Parameter(Mandatory = $true)][String]$Region
)

Try {
    Import-Module -Name 'AWS.Tools.LicenseManager', 'AWS.Tools.ResourceGroups' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to import License Manager Powershell module $_"
    Exit 1
}

[System.Collections.ArrayList]$ProductInformationFilters = @()
$ProductInformationFilter = New-Object -TypeName 'Amazon.LicenseManager.Model.ProductInformationFilter'
$ProductInformationFilter.ProductInformationFilterComparator = 'EQUALS'
$ProductInformationFilter.ProductInformationFilterName = 'Platform Name'
Foreach ($PIFilterValue in $ProductInformationFilterValue) {
    $ProductInformationFilter.ProductInformationFilterValue.Add($PIFilterValue)
}
$ProductInformationFilters.Add($ProductInformationFilter)

$ProductInformationFilter1 = New-Object -TypeName 'Amazon.LicenseManager.Model.ProductInformationFilter'
$ProductInformationFilter1.ProductInformationFilterComparator = 'NOT_EQUALS'
$ProductInformationFilter1.ProductInformationFilterName = 'License Included'
$ProductInformationFilter1.ProductInformationFilterValue.Add('windows-server-datacenter')
$ProductInformationFilters.Add($ProductInformationFilter1)

$ProductInformation = New-Object -TypeName 'Amazon.LicenseManager.Model.ProductInformation'
$ProductInformation.ProductInformationFilterList.Add($ProductInformationFilter)
$ProductInformation.ProductInformationFilterList.Add($ProductInformationFilter1)
$ProductInformation.ResourceType = 'SSM_MANAGED'

Write-Output 'Creating License Manager License Configuration'
Try {
    $LicenseConfigurationArn = New-LICMLicenseConfiguration -Name $Name -DisassociateWhenNotFound $False -LicenseCount $LicenseCount -LicenseCountHardLimit $True -LicenseCountingType 'Core' -LicenseRule '#allowedTenancy=EC2-DedicatedHost', '#licenseAffinityToHost=90' -ProductInformationList $ProductInformation -Region $Region -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to create License Manager License Configuration $_"
    Exit 1
}

$LicenseSpecification = New-Object -TypeName 'Amazon.LicenseManager.Model.LicenseSpecification'
$LicenseSpecification.LicenseConfigurationArn = $LicenseConfigurationArn

Write-Output 'Associating AMI with License Manager License Configuration'
Try {
    Update-LICMLicenseSpecificationsForResource -ResourceArn "arn:aws:ec2:$region::image/$AmiId" -AddLicenseSpecification $LicenseSpecification -Region $Region -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to associate AMI with License Manager License Configuration $_"
    Exit 1
}

$HostManagement = @(
    @{ 
        Name   = 'allowed-host-based-license-configurations'
        Values = $LicenseConfigurationArn 
    },
    @{
        Name   = 'allowed-host-families'
        Values = $HostFamily 
    }, 
    @{
        Name   = 'any-host-based-license-configuration'
        Values = 'false'
    }, 
    @{
        Name   = 'auto-allocate-host'
        Values = 'true'
    },
    @{
        Name   = 'auto-host-recovery'
        Values = 'true'
    },
    @{
        Name   = 'auto-release-host'
        Values = 'true'
    }
)

$Generic = @(
    @{
        Name   = 'allowed-resource-types'
        Values = 'AWS::EC2::Host'
    },
    @{
        Name   = 'deletion-protection'
        Values = 'UNLESS_EMPTY'
    }
)

[System.Collections.ArrayList]$Configuration = @()

$GenericGroupConfigurationItem = New-Object -TypeName 'Amazon.ResourceGroups.Model.GroupConfigurationItem'
$GenericGroupConfigurationItem.Type = 'AWS::ResourceGroups::Generic'
$GenericGroupConfigurationItem.Parameters = $Generic
$Configuration.Add($GenericGroupConfigurationItem)

$HostManagementGroupConfigurationItem = New-Object -TypeName 'Amazon.ResourceGroups.Model.GroupConfigurationItem'
$HostManagementGroupConfigurationItem.Type = 'AWS::EC2::HostManagement'
$HostManagementGroupConfigurationItem.Parameters = $HostManagement
$Configuration.Add($HostManagementGroupConfigurationItem)

Write-Output 'Creating Host Resource Group'
Try {
    $ResourceGroup = New-RGGroup -Configuration $Configuration -Description $Name -Name $Name -Force -Region $Region -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to create Host Resource Group $_"
    Exit 1
}

Return $ResourceGroup, $LicenseConfigurationArn