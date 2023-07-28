<#
    .SYNOPSIS
    Set-RdsAdObjects.ps1

    .DESCRIPTION
    This script will create:
    a.	(1) Amazon RDS for SQL Server OU
    b.	(1) Amazon RDS for SQL Server service account with proper permissions required for self-managed AD support

    This script requires the ActiveDirectory PowerShell Module and WMF5.1 to be installed.

    .EXAMPLE
    $RDSDeployment = @{
        RdsOUBaseDn       = 'DC=corp,DC=example,DC=com'
        RdsOUName         = 'RDS-MSSQL'
        RdsSvcAccountName = 'RdsServiceAccount'
        RdsSvcAccountPw   = Get-Credential -Message 'Please provide a password for the RDS Service Account RdsServiceAccount' -User 'RdsServiceAccount' -ErrorAction Stop | Select-Object -ExpandProperty 'Password'
    }

    .\Set-RDSAdObjects.ps1 @RDSDeployment
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][String]$RdsOUBaseDn,
    [Parameter(Mandatory = $true)][String]$RdsOUName,
    [Parameter(Mandatory = $true)][String]$RdsSvcAccountName,
    [Parameter(Mandatory = $true)][SecureString]$RdsSvcAccountPw
)

#==================================================
# Variables
#==================================================

$NullGuid = [System.Guid]::empty

#==================================================
# Functions
#==================================================

Function Add-RdsOuAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$AclPath,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$IdentityReference,
        [Parameter(Mandatory = $true)][System.DirectoryServices.ActiveDirectoryRights]$ActiveDirectoryRights,
        [Parameter(Mandatory = $true)][System.Security.AccessControl.AccessControlType]$AccessControlType,
        [Parameter(Mandatory = $false)][Guid]$ObjectGuid,
        [Parameter(Mandatory = $false)][System.DirectoryServices.ActiveDirectorySecurityInheritance]$ActiveDirectorySecurityInheritance,
        [Parameter(Mandatory = $false)][Guid]$InheritedObjectGuid
    )

    Try {
        Import-Module -Name 'ActiveDirectory' -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to import AD module, please ensure it is installed. $_"
        Exit 1
    }

    [Security.Principal.SecurityIdentifier]$IdentityReference = $IdentityReference | Select-Object -ExpandProperty 'Value'

    $ArgumentList = $IdentityReference, $ActiveDirectoryRights, $AccessControlType, $ObjectGuid, $ActiveDirectorySecurityInheritance, $InheritedObjectGuid
    $ArgumentList = $ArgumentList.Where( { $_ -ne $Null })

    Write-Output "Creating ACL object $ArgumentList."
    Try {
        $Rule = New-Object -TypeName 'System.DirectoryServices.ActiveDirectoryAccessRule' -ArgumentList $ArgumentList -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failled to create ACL object $ArgumentList. $_"
        Exit 1
    }

    Write-Output "Getting ACL for $AclPath and adding new rule."
    Try {
        $ObjectAcl = Get-Acl -Path "AD:\$AclPath" -ErrorAction Stop
        $ObjectAcl.AddAccessRule($Rule)
    } Catch [System.Exception] {
        Write-Output "Failed to get ACL or add new rule for $AclPath. $_"
        Exit 1
    }

    Write-Output "Setting ACL for $AclPath."
    Try {
        Set-Acl -AclObject $ObjectAcl -Path "AD:\$AclPath" -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to set ACL for $AclPath. $_"
        Exit 1
    }
}

#==================================================
# Main
#==================================================

Try {
    Import-Module -Name 'ActiveDirectory' -Force -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to import AD module, please ensure it is installed. $_"
    Exit 1
}

Write-Output 'Getting AD domain information.'
Try {
    $Domain = Get-ADDomain -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to get domain information. $_"
    Exit 1
}

$FQDN = $Domain | Select-Object -ExpandProperty 'DNSRoot'

Write-Output 'Getting RootDSE information.'
Try {
    $RootDse = Get-ADRootDSE -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to get RootDSE information. $_"
    Exit 1
}

Write-Output 'Getting computer SchemaNamingContext.'
Try {
    [System.GUID]$ComputerNameGuid = (Get-ADObject -SearchBase $RootDse.SchemaNamingContext -Filter { lDAPDisplayName -eq 'computer' } -Properties 'schemaIDGUID' -ErrorAction Stop).schemaIDGUID
} Catch [System.Exception] {
    Write-Output "Failed to get computer SchemaNamingContext. $_"
    Exit 1
}

Write-Output 'Getting ExtendedRightsMap.'
$ExtendedRightsMap = @{ }
Try {
    $ErNamingContexts = Get-ADObject -SearchBase $RootDse.ConfigurationNamingContext -LDAPFilter '(&(objectclass=controlAccessRight)(rightsguid=*))' -Properties displayName, rightsGuid -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to get ExtendedRightsMap. $_"
    Exit 1
}

ForEach ($ErNamingContext in $ErNamingContexts) {
    $ExtendedRightsMap[$ErNamingContext.displayName] = [System.GUID]$ErNamingContext.rightsGuid
}

$AclRules = @(
    @{
        ActiveDirectoryRights              = 'CreateChild, DeleteChild'
        AccessControlType                  = 'Allow'
        ObjectGUID                         = $ComputerNameGuid
        ActiveDirectorySecurityInheritance = 'All'
        InheritedObjectGuid                = $NullGuid
    },
    @{
        ActiveDirectoryRights              = 'Self'
        AccessControlType                  = 'Allow'
        ObjectGUID                         = $ExtendedRightsMap['Validated write to service principal name']
        ActiveDirectorySecurityInheritance = 'Descendents'
        InheritedObjectGuid                = $ComputerNameGuid
    },
    @{
        ActiveDirectoryRights              = 'Self'
        AccessControlType                  = 'Allow'
        ObjectGUID                         = $ExtendedRightsMap['Validated write to DNS host name']
        ActiveDirectorySecurityInheritance = 'Descendents'
        InheritedObjectGuid                = $ComputerNameGuid
    }
)

Try {
    $OuPresent = Get-ADOrganizationalUnit -Identity "OU=$RdsOUName,$RdsOUBaseDn" -ErrorAction SilentlyContinue
} Catch {
    $OuPresent = $Null
}
If ($Null -eq $OuPresent) {
    Write-Output "Creating OU $RdsOUName."
    Try {
        New-ADOrganizationalUnit -Name $RdsOUName -Path $RdsOUBaseDn -ProtectedFromAccidentalDeletion $True -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create OU $RdsOUName. $_"
        Exit 1
    }
}

Try {
    $UserPresent = Get-ADUser -Identity $RdsSvcAccountName -ErrorAction SilentlyContinue
} Catch {
    $OuPresent = $Null
}
If ($Null -eq $UserPresent) {
    $User = @{
        AccountPassword      = $RdsSvcAccountPw
        Name                 = $RdsSvcAccountName
        DisplayName          = $RdsSvcAccountName
        SamAccountName       = $RdsSvcAccountName
        UserPrincipalName    = "$RdsSvcAccountName@$FQDN"
        PasswordNeverExpires = $True
        Enabled              = $True
        Path                 = "OU=$RdsOUName,$RdsOUBaseDn"
    }

    Write-Output "Creating RDS service account $RdsSvcAccountName."
    Try {
        New-ADUser @User -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create RDS service account $RdsSvcAccountName. $_"
        Exit 1
    }
}

Write-Output "Getting $RdsSvcAccountName SID."
Try {
    $IdentityReference = Get-ADUser -Identity $RdsSvcAccountName -ErrorAction Stop | Select-Object -ExpandProperty 'SID'
} Catch [System.Exception] {
    Write-Output "Failed to get $RdsSvcAccountName SID. $_"
    Exit 1
}

Foreach ($AclRule in $AclRules) {
    Add-RdsOuAcl -AclPath "OU=$RdsOUName,$RdsOUBaseDn" -IdentityReference $IdentityReference -ActiveDirectoryRights $AclRule.ActiveDirectoryRights -AccessControlType $AclRule.AccessControlType -ObjectGUID $AclRule.ObjectGUID -ActiveDirectorySecurityInheritance $AclRule.ActiveDirectorySecurityInheritance -InheritedObjectGuid $AclRule.InheritedObjectGuid
}