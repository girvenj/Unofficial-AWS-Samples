<#
    .SYNOPSIS
    Set-FSxAdObjects.ps1

    .DESCRIPTION
    This script will create:
    a.	(1) Amazon FSx for Windows File Server OU
    b.	(1) Amazon FSx for Windows File Server service account with proper permissions
    c.	(1) Amazon FSx for Windows File Server administrative group

    It requires the ActiveDirectory PowerShell Module and WMF5.1 to be installed.
      
    .EXAMPLE
    $FSxDeployments = @(
        @{
            AdminGroupName = 'FSxAdmins-A'
            OUName         = 'FSx-A'
            SvcAccountName = 'FSxServiceAccount-A'
            SvcAccountPw   = Get-Credential -Message 'Please provide a password for the FSx Service Account FSxServiceAccount-A' -User 'FSxServiceAccount-A' -ErrorAction Stop | Select-Object -ExpandProperty 'Password'
        },
        @{
            AdminGroupName = 'FSxAdmins-B'
            OUName         = 'FSx-B'
            SvcAccountName = 'FSxServiceAccount-B'
            SvcAccountPw   = Get-Credential -Message 'Please provide a password for the FSx Service Account FSxServiceAccount-B' -User 'FSxServiceAccount-B' -ErrorAction Stop | Select-Object -ExpandProperty 'Password'
        }
    )

    Foreach ($FSxDeployment in $FSxDeployments) {
        .\Set-FSxAdObjects.ps1 -FSxAdminGroupName $FSxDeployment.AdminGroupName -FSxOUName $FSxDeployment.OUName -FSxSvcAccountName $FSxDeployment.SvcAccountName -FSxSvcAccountPw $FSxDeployment.SvcAccountPw
    }
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][String]$FSxAdminGroupName = 'FSxAdmins-A',
    [Parameter(Mandatory = $true)][String]$FSxOUName = 'FSx-A',
    [Parameter(Mandatory = $true)][String]$FSxSvcAccountName = 'FSxServiceAccount-A',
    [Parameter(Mandatory = $true)][SecureString]$FSxSvcAccountPw
)

#==================================================
# Variables
#==================================================

$NullGuid = [guid]'00000000-0000-0000-0000-000000000000'

#==================================================
# Functions
#==================================================

Function Add-FSxOuAcl {
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
        Write-Output "Failed to import AD module $_"
        Exit 1
    }

    [Security.Principal.SecurityIdentifier]$IdentityReference = $IdentityReference | Select-Object -ExpandProperty 'Value'

    $ArgumentList = $IdentityReference, $ActiveDirectoryRights, $AccessControlType, $ObjectGuid, $ActiveDirectorySecurityInheritance, $InheritedObjectGuid
    $ArgumentList = $ArgumentList.Where( { $_ -ne $Null })

    Write-Output "Creating ACL object $ArgumentList"
    Try {
        $Rule = New-Object -TypeName 'System.DirectoryServices.ActiveDirectoryAccessRule' -ArgumentList $ArgumentList -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Creating ACL object $ArgumentList $_"
        Exit 1
    }

    Write-Output "Getting ACL for $AclPath and adding new rule"
    Try {
        $ObjectAcl = Get-Acl -Path "AD:\$AclPath" -ErrorAction Stop
        $ObjectAcl.AddAccessRule($Rule) 
    } Catch [System.Exception] {
        Write-Output "Failed to get ACL for $AclPath or add new rule $_"
        Exit 1
    }

    Write-Output "Setting ACL for $AclPath"
    Try {
        Set-Acl -AclObject $ObjectAcl -Path "AD:\$AclPath" -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to set ACL for $AclPath $_"
        Exit 1
    }
}

#==================================================
# Main
#==================================================

Try {
    Import-Module -Name 'ActiveDirectory' -Force -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to import AD module $_"
    Exit 1
}

Write-Output 'Getting AD domain information'
Try {
    $Domain = Get-ADDomain -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to get domain information $_"
    Exit 1
}
$BaseDn = $Domain | Select-Object -ExpandProperty 'DistinguishedName'
$Netbios = $Domain | Select-Object -ExpandProperty 'NetBIOSName'
$FQDN = $Domain | Select-Object -ExpandProperty 'DNSRoot'

Write-Output 'Getting RootDSE information'
Try {
    $RootDse = Get-ADRootDSE -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to get Root DSE infoormation $_"
    Exit 1
}

Write-Output 'Getting computer SchemaNamingContext'
Try {
    [System.GUID]$ComputerNameGuid = (Get-ADObject -SearchBase $RootDse.SchemaNamingContext -Filter { lDAPDisplayName -eq 'computer' } -Properties 'schemaIDGUID' -ErrorAction Stop).schemaIDGUID
} Catch [System.Exception] {
    Write-Output "Failed to get computer SchemaNamingContext $_"
    Exit 1
}

Write-Output 'Getting ExtendedRightsMap'
$ExtendedRightsMap = @{ }
Try {
    $ErNamingContexts = Get-ADObject -SearchBase $RootDse.ConfigurationNamingContext -LDAPFilter '(&(objectclass=controlAccessRight)(rightsguid=*))' -Properties displayName, rightsGuid -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to get ExtendedRightsMap $_"
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
        ActiveDirectoryRights              = 'ExtendedRight'
        AccessControlType                  = 'Allow'
        ObjectGUID                         = $ExtendedRightsMap['Validated write to service principal name']
        ActiveDirectorySecurityInheritance = 'Descendents'
        InheritedObjectGuid                = $ComputerNameGuid
    },
    @{
        ActiveDirectoryRights              = 'ExtendedRight'
        AccessControlType                  = 'Allow'
        ObjectGUID                         = $ExtendedRightsMap['Account Restrictions']
        ActiveDirectorySecurityInheritance = 'Descendents'
        InheritedObjectGuid                = $ComputerNameGuid
    },
    @{
        ActiveDirectoryRights              = 'ExtendedRight'
        AccessControlType                  = 'Allow'
        ObjectGUID                         = $ExtendedRightsMap['Reset Password']
        ActiveDirectorySecurityInheritance = 'Descendents'
        InheritedObjectGuid                = $ComputerNameGuid
    },
    @{
        ActiveDirectoryRights              = 'ExtendedRight'
        AccessControlType                  = 'Allow'
        ObjectGUID                         = $ExtendedRightsMap['Validated write to DNS host name']
        ActiveDirectorySecurityInheritance = 'Descendents'
        InheritedObjectGuid                = $ComputerNameGuid
    }
)

Try {
    $OuPresent = Get-ADOrganizationalUnit -Identity "OU=$FSxOUName,OU=$Netbios,$BaseDn" -ErrorAction SilentlyContinue
} Catch {}
If ($Null -eq $OuPresent) {
    Write-Output "Creating OU $FSxOUName"
    Try {
        New-ADOrganizationalUnit -Name $FSxOUName -Path "OU=$Netbios,$BaseDn" -ProtectedFromAccidentalDeletion $True -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create new OU $FSxOUName $_"
        Exit 1
    }
}

Try {
    $UserPresent = Get-ADUser -Identity $FSxSvcAccountName -ErrorAction SilentlyContinue
} Catch {}
If ($Null -eq $UserPresent) {
    $User = @{
        AccountPassword        = $FSxSvcAccountPw
        Name                   = $FSxSvcAccountName
        DisplayName            = $FSxSvcAccountName
        SamAccountName         = $FSxSvcAccountName
        UserPrincipalName      = "$FSxSvcAccountName@$FQDN"
        KerberosEncryptionType = 'AES128', 'AES256'
        PasswordNeverExpires   = $True
        Enabled                = $True
        Path                   = "OU=$FSxOUName,OU=$Netbios,$BaseDn"
    }

    Write-Output "Creating FSx Service Account $FSxSvcAccountName"
    Try {
        New-ADUser @User -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create FSx Service Account $FSxSvcAccountName $_"
        Exit 1
    }
}

Try {
    $GroupPresent = Get-ADGroup -Identity $FSxAdminGroupName -ErrorAction SilentlyContinue
} Catch {}
If ($Null -eq $GroupPresent) {
    Write-Output "Creating FSx Administrators Group $FSxAdminGroupName"
    Try {
        New-ADGroup -DisplayName $FSxAdminGroupName -GroupCategory 'Security' -GroupScope 'DomainLocal' -Name $FSxAdminGroupName -Path "OU=$FSxOUName,OU=$Netbios,$BaseDn" -SamAccountName $FSxAdminGroupName -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create FSx Administrators Group $FSxAdminGroupName $_"
        Exit 1
    }
}

Write-Output 'Getting FSxServiceAccount SID'
$IdentityReference = Get-ADUser -Identity $FSxSvcAccountName -ErrorAction Stop | Select-Object -ExpandProperty 'SID'

Foreach ($AclRule in $AclRules) {
    Add-FSxOuAcl -AclPath "OU=$FSxOUName,OU=$Netbios,$BaseDn" -IdentityReference $IdentityReference -ActiveDirectoryRights $AclRule.ActiveDirectoryRights -AccessControlType $AclRule.AccessControlType -ObjectGUID $AclRule.ObjectGUID -ActiveDirectorySecurityInheritance $AclRule.ActiveDirectorySecurityInheritance -InheritedObjectGuid $AclRule.InheritedObjectGuid
}