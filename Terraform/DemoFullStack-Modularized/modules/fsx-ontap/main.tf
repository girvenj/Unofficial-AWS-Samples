terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.9"
    }
  }
}

locals {
  fsx_ontap_ports = [
    {
      from_port   = 22
      to_port     = 22
      description = "SSH"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 111
      to_port     = 111
      description = "NFS RPC"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 135
      to_port     = 135
      description = "CIFS RPC"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 139
      to_port     = 139
      description = "CIFS NetBIOS"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 161
      to_port     = 162
      description = "SNMP"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 443
      to_port     = 443
      description = "ONTAP REST API"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 445
      to_port     = 445
      description = "CIFS"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 635
      to_port     = 635
      description = "NFS"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 749
      to_port     = 749
      description = "Kerberos"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 2049
      to_port     = 2049
      description = "NFS Daemon"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 3260
      to_port     = 3260
      description = "iSCSI"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 4045
      to_port     = 4046
      description = "NFS Lock Daemon and Status"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 10000
      to_port     = 10000
      description = "NDMP and SnapMirror Intercluster Communication"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 11104
      to_port     = 11105
      description = "SnapMirror Intercluster Communication"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 111
      to_port     = 111
      description = "NFS RPC"
      protocol    = "UDP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 135
      to_port     = 135
      description = "CIFS RPC"
      protocol    = "UDP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 137
      to_port     = 137
      description = "CIFS NetBIOS"
      protocol    = "UDP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 139
      to_port     = 139
      description = "CIFS NetBIOS"
      protocol    = "UDP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 161
      to_port     = 162
      description = "SNMP"
      protocol    = "UDP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 635
      to_port     = 635
      description = "NFS"
      protocol    = "UDP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 2049
      to_port     = 2049
      description = "NFS Daemon"
      protocol    = "UDP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 4045
      to_port     = 4046
      description = "NFS Lock Daemon and Status"
      protocol    = "UDP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 4049
      to_port     = 4049
      description = "NFS Quota"
      protocol    = "UDP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    }
  ]
}

data "aws_vpc" "main" {
  id = var.fsx_ontap_vpc_id
}

data "aws_iam_role" "main" {
  name = var.setup_ec2_iam_role
}

module "kms_key" {
  source                          = "../kms"
  kms_key_description             = "KMS key for FSx Ontap encryption"
  kms_key_usage                   = "ENCRYPT_DECRYPT"
  kms_customer_master_key_spec    = "SYMMETRIC_DEFAULT"
  kms_key_deletion_window_in_days = 7
  kms_enable_key_rotation         = true
  kms_key_alias_name              = "fsx-onprem-secret-kms-key"
  kms_multi_region                = false
  kms_random_string               = var.fsx_ontap_random_string
}

resource "aws_kms_grant" "fsx_ontap_svc_account" {
  name              = "kms-decrypt-fsx-ontap-service-account-secret-grant"
  key_id            = module.kms_key.kms_key_id
  grantee_principal = data.aws_iam_role.main.arn
  operations        = ["Decrypt"]
}

resource "aws_kms_grant" "fsx_ontap_setup_account" {
  name              = "kms-decrypt-fsx-ontap-setup-account-secret-grant"
  key_id            = var.setup_secret_kms_key_arn
  grantee_principal = data.aws_iam_role.main.arn
  operations        = ["Decrypt"]
}

resource "random_password" "main" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

module "store_secret_fsx_ontap_svc" {
  source                  = "../secret"
  name                    = "FSx-OnTap-Svc-Secret-${var.fsx_ontap_random_string}"
  username                = var.fsx_ontap_username
  password                = random_password.main.result
  recovery_window_in_days = 0
  secret_kms_key          = module.kms_key.kms_alias_name
}

resource "aws_iam_role_policy" "main" {
  name = "fsx-ontap-svc-policy"
  role = var.setup_ec2_iam_role
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Effect = "Allow"
        Resource = [
          module.store_secret_fsx_ontap_svc.secret_arn,
          var.setup_secret_kms_key_arn
        ]
      },
      {
        Action = [
          "kms:Decrypt"
        ]
        Effect = "Allow"
        Resource = [
          var.setup_secret_kms_key_arn
        ]
      }
    ]
  })
}

resource "aws_ssm_document" "ssm_fsx_ontap_setup" {
  name            = "SSM-FSx-OnTap-Setup-${var.fsx_ontap_random_string}"
  document_format = "YAML"
  document_type   = "Command"
  content         = <<DOC
    schemaVersion: '2.2'
    description: Create FSx Service Account
    parameters:
      FSxAdminGroupName:
        description: (Required)
        type: String
      FSxOuParentDn:
        description: (Required)
        type: String
      FSxSvcSecretArn:
        description: (Required)
        type: String
      DomainNetBIOSName:
        description: (Required)
        type: String
      SetupSecretArn:
        description: (Required)
        type: String
    mainSteps:
      - action: aws:runPowerShellScript
        name: createAlias
        inputs:
          runCommand:
            - |
              Function Set-CredSSP {
                  [CmdletBinding()]
                  param(
                      [Parameter(Mandatory = $true)][ValidateSet('Enable', 'Disable')][string]$Action
                  )

                  $RootKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows'
                  $CredDelKey = 'CredentialsDelegation'
                  $FreshCredKey = 'AllowFreshCredentials'
                  $FreshCredKeyNTLM = 'AllowFreshCredentialsWhenNTLMOnly'

                  Switch ($Action) {
                      'Enable' {
                          Write-Output 'Enabling CredSSP'
                          $CredDelKeyPresent = Test-Path -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -ErrorAction SilentlyContinue
                          If (-not $CredDelKeyPresent) {
                              Write-Output "Setting CredSSP registry entry $CredDelKey"
                              Try {
                                  $CredDelPath = New-Item -Path "Registry::$RootKey" -Name $CredDelKey -ErrorAction Stop | Select-Object -ExpandProperty 'Name'
                              } Catch [System.Exception] {
                                  Write-Output "Failed to create CredSSP registry entry $CredDelKey $_"
                                  Remove-Item -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -Force -Recurse
                                  Exit 1
                              }
                          } Else {
                              $CredDelPath = Join-Path -Path $RootKey -ChildPath $CredDelKey
                          }

                          $FreshCredKeyPresent = Test-Path -Path (Join-Path -Path "Registry::$CredDelPath" -ChildPath $FreshCredKey) -ErrorAction SilentlyContinue
                          If (-not $FreshCredKeyPresent) {
                              Write-Output "Setting CredSSP registry entry $FreshCredKey"
                              Try {
                                  $FreshCredKeyPath = New-Item -Path "Registry::$CredDelPath" -Name $FreshCredKey -ErrorAction Stop | Select-Object -ExpandProperty 'Name'
                              } Catch [System.Exception] {
                                  Write-Output "Failed to create CredSSP registry entry $FreshCredKey $_"
                                  Remove-Item -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -Force -Recurse
                                  Exit 1
                              }
                          } Else {
                              $FreshCredKeyPath = Join-Path -Path $CredDelPath -ChildPath $FreshCredKey
                          }

                          $FreshCredKeyNTLMPresent = Test-Path -Path (Join-Path -Path "Registry::$CredDelPath" -ChildPath $FreshCredKeyNTLM) -ErrorAction SilentlyContinue
                          If (-not $FreshCredKeyNTLMPresent) {
                              Write-Output "Setting CredSSP registry entry $FreshCredKeyNTLM"
                              Try {
                                  $FreshCredKeyNTLMPath = New-Item -Path "Registry::$CredDelPath" -Name $FreshCredKeyNTLM -ErrorAction Stop | Select-Object -ExpandProperty 'Name'
                              } Catch [System.Exception] {
                                  Write-Output "Failed to create CredSSP registry entry $FreshCredKeyNTLM $_"
                                  Remove-Item -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -Force -Recurse
                                  Exit 1
                              }
                          } Else {
                              $FreshCredKeyNTLMPath = Join-Path -Path $CredDelPath -ChildPath $FreshCredKeyNTLM
                          }

                          Try {
                              $Null = Set-ItemProperty -Path "Registry::$CredDelPath" -Name 'AllowFreshCredentials' -Value '1' -Type 'Dword' -Force -ErrorAction Stop
                              $Null = Set-ItemProperty -Path "Registry::$CredDelPath" -Name 'ConcatenateDefaults_AllowFresh' -Value '1' -Type 'Dword' -Force -ErrorAction Stop
                              $Null = Set-ItemProperty -Path "Registry::$CredDelPath" -Name 'AllowFreshCredentialsWhenNTLMOnly' -Value '1' -Type 'Dword' -Force -ErrorAction Stop
                              $Null = Set-ItemProperty -Path "Registry::$CredDelPath" -Name 'ConcatenateDefaults_AllowFreshNTLMOnly' -Value '1' -Type 'Dword' -Force -ErrorAction Stop
                              $Null = Set-ItemProperty -Path "Registry::$FreshCredKeyPath" -Name '1' -Value 'WSMAN/*' -Type 'String' -Force -ErrorAction Stop
                              $Null = Set-ItemProperty -Path "Registry::$FreshCredKeyNTLMPath" -Name '1' -Value 'WSMAN/*' -Type 'String' -Force -ErrorAction Stop
                          } Catch [System.Exception] {
                              Write-Output "Failed to create CredSSP registry properties $_"
                              Remove-Item -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -Force -Recurse
                              Exit 1
                          }

                          Try {
                              $Null = Enable-WSManCredSSP -Role 'Client' -DelegateComputer '*' -Force -ErrorAction Stop
                              $Null = Enable-WSManCredSSP -Role 'Server' -Force -ErrorAction Stop
                          } Catch [System.Exception] {
                              Write-Output "Failed to enable CredSSP $_"
                              $Null = Disable-WSManCredSSP -Role 'Client' -ErrorAction SilentlyContinue
                              $Null = Disable-WSManCredSSP -Role 'Server' -ErrorAction SilentlyContinue
                              Exit 1
                          }
                      }
                      'Disable' {
                          Write-Output 'Disabling CredSSP'
                          Try {
                              Disable-WSManCredSSP -Role 'Client' -ErrorAction Continue
                              Disable-WSManCredSSP -Role 'Server' -ErrorAction Stop
                          } Catch [System.Exception] {
                              Write-Output "Failed to disable CredSSP $_"
                              Exit 1
                          }

                          Write-Output 'Removing CredSSP registry entries'
                          Try {
                              Remove-Item -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -Force -Recurse -ErrorAction Stop
                          } Catch [System.Exception] {
                              Write-Output "Failed to remove CredSSP registry entries $_"
                              Exit 1
                          }
                      }
                      Default { 
                          Write-Output 'InvalidArgument: Invalid value is passed for parameter Action'
                          Exit 1
                      }
                  }
              }

              Function Get-SecretInfo {
                  [CmdletBinding()]
                  Param (
                      [Parameter(Mandatory = $True)][String]$Domain,
                      [Parameter(Mandatory = $True)][String]$SecretArn
                  )
                  Try {
                      $SecretContent = Get-SECSecretValue -SecretId $SecretArn -ErrorAction Stop | Select-Object -ExpandProperty 'SecretString' | ConvertFrom-Json -ErrorAction Stop
                  } Catch [System.Exception] {
                      Write-Output "Failed to get $SecretArn Secret $_"
                      Exit 1
                  }
                  $Username = $SecretContent.username
                  $UserPassword = ConvertTo-SecureString ($SecretContent.password) -AsPlainText -Force
                  $DomainCredentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ("$Domain\$Username", $UserPassword)
                  $Credentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ($Username, $UserPassword)
                  $Output = [PSCustomObject][Ordered]@{
                      'Credentials'       = $Credentials
                      'DomainCredentials' = $DomainCredentials
                      'Username'          = $Username
                      'UserPassword'      = $UserPassword
                  }
                  Return $Output
              }

              $Secret = Get-SecretInfo -Domain '{{DomainNetBIOSName}}' -SecretArn '{{SetupSecretArn}}'
              Try {
                  $Domain = Get-ADDomain -Credential $Secret.DomainCredentials -ErrorAction Stop
              } Catch [System.Exception] {
                  Write-Output "Failed to get domain information $_"
                  Exit 1
              }

              $FQDN = $Domain | Select-Object -ExpandProperty 'DNSRoot'
              $FSxOuDn = "OU=FSx-Ontap,{{FSxOuParentDn}}"

              Try {
                  $OuPresent = Get-ADOrganizationalUnit -Identity $FSxOuDn -Credential $Secret.DomainCredentials -ErrorAction Stop
              } Catch [System.Exception] {
                  If ($_ -like 'Directory object not found') {
                      $OuPresent = $Null
                  } Else {
                      Write-Output "Failed to query AD $_"
                  }
              }

              If (-Not $OuPresent) {
                  Try {
                      New-ADOrganizationalUnit -Name 'FSx-Ontap' -Path '{{FSxOuParentDn}}' -ProtectedFromAccidentalDeletion $True -Credential $Secret.DomainCredentials -ErrorAction Stop
                  } Catch [System.Exception] {
                      Write-Output "Failed to create OU FSx $_"
                      Exit 1
                  }
              }

              $FsxSecretInfo = Get-SecretInfo -Domain '{{DomainNetBIOSName}}' -SecretArn '{{FSxSvcSecretArn}}'
              $FsxUsername = $FsxSecretInfo.Username
              $FsxUserPassword = $FsxSecretInfo.UserPassword

              Try {
                  $UserPresent = Get-ADUser -Identity $FsxUsername -Credential $Secret.DomainCredentials -ErrorAction Stop
              } Catch [System.Exception] {
                  If ($_ -like 'Cannot find an object with identity:*') {
                      $UserPresent = $Null
                  } Else {
                      Write-Output "Failed to query AD $_"
                  }
              }

              If (-Not $UserPresent) {
                  $User = @{
                      AccountPassword      = $FsxUserPassword
                      Name                 = $FsxUsername
                      DisplayName          = $FsxUsername
                      SamAccountName       = $FsxUsername
                      UserPrincipalName    = "$FsxUsername@$FQDN"
                      PasswordNeverExpires = $True
                      Enabled              = $True
                      Path                 = $FSxOuDn
                      Credential           = $Secret.DomainCredentials
                  }

                  Try {
                      New-ADUser @User 
                  } Catch [System.Exception] {
                      Write-Output "Failed to create $FsxUsername $_"
                      Exit 1
                  }
              }

              Try {
                  $GroupPresent = Get-ADGroup -Identity '{{FSxAdminGroupName}}' -Credential $Secret.DomainCredentials -ErrorAction Stop
              } Catch [System.Exception] {
                  If ($_ -like 'Cannot find an object with identity:*') {
                      $GroupPresent = $Null
                  } Else {
                      Write-Output "Failed to query AD $_"
                  }
              }

              If (-Not $GroupPresent) {
                  Try {
                      New-ADGroup -DisplayName '{{FSxAdminGroupName}}' -GroupCategory 'Security' -GroupScope 'DomainLocal' -Name '{{FSxAdminGroupName}}' -Path $FSxOuDn -SamAccountName '{{FSxAdminGroupName}}' -Credential $Secret.DomainCredentials  -ErrorAction Stop
                  } Catch [System.Exception] {
                      Write-Output "Failed to create '{{FSxAdminGroupName}}' $_"
                      Exit 1
                  }
              }

              Set-CredSSP -Action 'Enable'

              Invoke-Command -Authentication 'Credssp' -ComputerName $env:COMPUTERNAME -Credential $Secret.DomainCredentials -ScriptBlock {
                  Function Add-OuAcl {
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
                      Import-Module -Name 'ActiveDirectory' -Force
                      [Security.Principal.SecurityIdentifier]$IdentityReference = $IdentityReference | Select-Object -ExpandProperty 'Value'
                      $ArgumentList = $IdentityReference, $ActiveDirectoryRights, $AccessControlType, $ObjectGuid, $ActiveDirectorySecurityInheritance, $InheritedObjectGuid
                      $ArgumentList = $ArgumentList.Where({ $_ -ne $Null })
                      Try {
                          $Rule = New-Object -TypeName 'System.DirectoryServices.ActiveDirectoryAccessRule' -ArgumentList $ArgumentList -ErrorAction Stop
                      } Catch [System.Exception] {
                          Write-Output "Failed to create ACL object $_"
                          Exit 1
                      }
                      Try {
                          $ObjectAcl = Get-Acl -Path "AD:\$AclPath" -ErrorAction Stop
                      } Catch [System.Exception] {
                          Write-Output "Failed to get ACL for $AclPath $_"
                          Exit 1
                      }
                      $ObjectAcl.AddAccessRule($Rule) 
                      Try {
                          Set-Acl -AclObject $ObjectAcl -Path "AD:\$AclPath" -ErrorAction Stop
                      } Catch [System.Exception] {
                          Write-Output "Failed to set ACL for $AclPath $_"
                          Exit 1
                      }
                  }

                  Try {
                      $RootDse = Get-ADRootDSE -ErrorAction Stop
                  } Catch [System.Exception] {
                      Write-Output "Failed to get RootDSE information $_"
                      Exit 1
                  }

                  Try {
                      [System.GUID]$ComputerNameGuid = (Get-ADObject -SearchBase $RootDse.SchemaNamingContext -Filter { lDAPDisplayName -eq 'computer' } -Properties 'schemaIDGUID' -ErrorAction Stop).schemaIDGUID
                  } Catch [System.Exception] {
                      Write-Output "Failed to get computer SchemaNamingContext $_"
                      Exit 1
                  }

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

                  Try {
                      $IdentityReference = Get-ADUser -Identity $Using:FsxUsername -ErrorAction Stop | Select-Object -ExpandProperty 'SID'
                  } Catch [System.Exception] {
                      Write-Output "Failed to get $Using:FsxUsername $_"
                      Exit 1
                  }

                  $NullGuid = [System.Guid]::empty
                  $AclRules = @(
                      @{
                          Path = $Using:FSxOuDn
                          Acl  = @{
                              ActiveDirectoryRights              = 'CreateChild, DeleteChild'
                              AccessControlType                  = 'Allow'
                              ObjectGUID                         = $ComputerNameGuid
                              ActiveDirectorySecurityInheritance = 'All'
                              InheritedObjectGuid                = $NullGuid
                          }
                      },
                      @{
                          Path = $Using:FSxOuDn
                          Acl  = @{
                              ActiveDirectoryRights              = 'ListChildren, ReadProperty'
                              AccessControlType                  = 'Allow'
                              ObjectGUID                         = $NullGuid
                              ActiveDirectorySecurityInheritance = 'None'
                              InheritedObjectGuid                = $NullGuid
                          }
                      },
                      @{
                          Path = $Using:FSxOuDn
                          Acl  = @{
                              ActiveDirectoryRights              = 'ReadProperty, WriteProperty'
                              AccessControlType                  = 'Allow'
                              ObjectGUID                         = $ExtendedRightsMap['Account Restrictions']
                              ActiveDirectorySecurityInheritance = 'Descendents'
                              InheritedObjectGuid                = $ComputerNameGuid
                          }
                      },
                      @{
                          Path = $Using:FSxOuDn
                          Acl  = @{
                              ActiveDirectoryRights              = 'Self'
                              AccessControlType                  = 'Allow'
                              ObjectGUID                         = $ExtendedRightsMap['Validated write to service principal name']
                              ActiveDirectorySecurityInheritance = 'Descendents'
                              InheritedObjectGuid                = $ComputerNameGuid
                          }
                      },
                      @{
                          Path = $Using:FSxOuDn
                          Acl  = @{
                              ActiveDirectoryRights              = 'Self'
                              AccessControlType                  = 'Allow'
                              ObjectGUID                         = $ExtendedRightsMap['Validated write to DNS host name']
                              ActiveDirectorySecurityInheritance = 'Descendents'
                              InheritedObjectGuid                = $ComputerNameGuid
                          }
                      },
                      @{
                          Path = $Using:FSxOuDn
                          Acl  = @{
                              ActiveDirectoryRights              = 'ExtendedRight'
                              AccessControlType                  = 'Allow'
                              ObjectGUID                         = $ExtendedRightsMap['Reset Password']
                              ActiveDirectorySecurityInheritance = 'Descendents'
                              InheritedObjectGuid                = $ComputerNameGuid
                          }
                      }
                  )

                  Foreach ($AclRule in $AclRules) {
                      Add-OuAcl -AclPath $AclRule.Path -IdentityReference $IdentityReference -ActiveDirectoryRights $AclRule.Acl.ActiveDirectoryRights -AccessControlType $AclRule.Acl.AccessControlType -ObjectGUID $AclRule.Acl.ObjectGUID -ActiveDirectorySecurityInheritance $AclRule.Acl.ActiveDirectorySecurityInheritance -InheritedObjectGuid $AclRule.Acl.InheritedObjectGuid
                  }
              }
              Set-CredSSP -Action 'Disable'
DOC
}

resource "aws_ssm_association" "ssm_fsx_ontap_setup" {
  name             = "SSM-FSx-OnTap-Setup-${var.fsx_ontap_random_string}"
  association_name = "SSM-FSx-OnTap-Setup-${var.fsx_ontap_random_string}"
  parameters = {
    FSxAdminGroupName = var.fsx_ontap_file_system_administrators_group
    FSxOuParentDn     = var.fsx_ontap_parent_ou_dn
    FSxSvcSecretArn   = module.store_secret_fsx_ontap_svc.secret_arn
    DomainNetBIOSName = var.fsx_ontap_domain_netbios_name
    SetupSecretArn    = var.setup_secret_arn
  }
  targets {
    key    = "InstanceIds"
    values = [var.setup_ssm_target_instance_id]
  }
  depends_on = [
    aws_kms_grant.fsx_ontap_svc_account,
    aws_iam_role_policy.main
  ]
}

resource "time_sleep" "wait" {
  depends_on      = [aws_ssm_association.ssm_fsx_ontap_setup]
  create_duration = "3m"
}

module "fsx_ontap_security_group" {
  source      = "../vpc-security-group-ingress"
  name        = "${var.fsx_ontap_alias}-FSx-OnTap-${var.fsx_ontap_domain_fqdn}-Security-Group-${var.fsx_ontap_random_string}"
  description = "${var.fsx_ontap_alias} FSx OnTap ${var.fsx_ontap_domain_fqdn} Security Group"
  vpc_id      = var.fsx_ontap_vpc_id
  ports       = local.fsx_ontap_ports
}

resource "aws_fsx_ontap_file_system" "main" {
  automatic_backup_retention_days = var.fsx_ontap_automatic_backup_retention_days
  deployment_type                 = var.fsx_ontap_deployment_type
  kms_key_id                      = module.kms_key.kms_key_arn
  preferred_subnet_id             = var.fsx_ontap_subnet_ids[0]
  security_group_ids              = [module.fsx_ontap_security_group.sg_id]
  storage_capacity                = var.fsx_ontap_storage_capacity
  storage_type                    = var.fsx_ontap_storage_type
  subnet_ids                      = var.fsx_ontap_subnet_ids
  throughput_capacity             = var.fsx_ontap_throughput_capacity
  tags = {
    Name = "${var.fsx_ontap_alias}-FSx-OnTap-${var.fsx_ontap_domain_fqdn}-${var.fsx_ontap_random_string}"
  }
}

resource "aws_fsx_ontap_storage_virtual_machine" "main" {
  file_system_id = aws_fsx_ontap_file_system.main.id
  name           = var.fsx_ontap_alias
  root_volume_security_style = var.fsx_ontap_root_volume_security_style
  active_directory_configuration {
    netbios_name = var.fsx_ontap_alias
    self_managed_active_directory_configuration {
      dns_ips                                = var.fsx_ontap_dns_ips
      domain_name                            = var.fsx_ontap_domain_fqdn
      file_system_administrators_group       = var.fsx_ontap_file_system_administrators_group
      organizational_unit_distinguished_name = "OU=FSx-Ontap,${var.fsx_ontap_parent_ou_dn}"
      password                               = random_password.main.result
      username                               = var.fsx_ontap_username
    }
  }
  tags = {
    Name = "${var.fsx_ontap_alias}-FSx-OnTap-${var.fsx_ontap_domain_fqdn}-${var.fsx_ontap_random_string}"
  }
  depends_on = [time_sleep.wait]
}

resource "aws_ssm_document" "ssm_fsx_ontap_alias" {
  name            = "SSM-FSx-OnTap-Alias-${var.fsx_ontap_random_string}"
  document_format = "YAML"
  document_type   = "Command"
  content         = <<DOC
    schemaVersion: '2.2'
    description: Create FSx Alias DNS Record
    parameters:
      Alias:
        description: (Required)
        type: String
      ARecord:
        description: (Required)
        type: String
      DomainNetBIOSName:
        default: ' '
        description: (Required)
        type: String
      RunLocation:
        description: (Required)
        type: String
      SecretArn:
        default: ' '
        description: (Required)
        type: String
    mainSteps:
      - action: aws:runPowerShellScript
        name: createAlias
        inputs:
          runCommand:
            - |
              Function Set-CredSSP {
                  [CmdletBinding()]
                  param(
                      [Parameter(Mandatory = $true)][ValidateSet('Enable', 'Disable')][string]$Action
                  )

                  $RootKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows'
                  $CredDelKey = 'CredentialsDelegation'
                  $FreshCredKey = 'AllowFreshCredentials'
                  $FreshCredKeyNTLM = 'AllowFreshCredentialsWhenNTLMOnly'

                  Switch ($Action) {
                      'Enable' {
                          Write-Output 'Enabling CredSSP'
                          $CredDelKeyPresent = Test-Path -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -ErrorAction SilentlyContinue
                          If (-not $CredDelKeyPresent) {
                              Write-Output "Setting CredSSP registry entry $CredDelKey"
                              Try {
                                  $CredDelPath = New-Item -Path "Registry::$RootKey" -Name $CredDelKey -ErrorAction Stop | Select-Object -ExpandProperty 'Name'
                              } Catch [System.Exception] {
                                  Write-Output "Failed to create CredSSP registry entry $CredDelKey $_"
                                  Remove-Item -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -Force -Recurse
                                  Exit 1
                              }
                          } Else {
                              $CredDelPath = Join-Path -Path $RootKey -ChildPath $CredDelKey
                          }

                          $FreshCredKeyPresent = Test-Path -Path (Join-Path -Path "Registry::$CredDelPath" -ChildPath $FreshCredKey) -ErrorAction SilentlyContinue
                          If (-not $FreshCredKeyPresent) {
                              Write-Output "Setting CredSSP registry entry $FreshCredKey"
                              Try {
                                  $FreshCredKeyPath = New-Item -Path "Registry::$CredDelPath" -Name $FreshCredKey -ErrorAction Stop | Select-Object -ExpandProperty 'Name'
                              } Catch [System.Exception] {
                                  Write-Output "Failed to create CredSSP registry entry $FreshCredKey $_"
                                  Remove-Item -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -Force -Recurse
                                  Exit 1
                              }
                          } Else {
                              $FreshCredKeyPath = Join-Path -Path $CredDelPath -ChildPath $FreshCredKey
                          }

                          $FreshCredKeyNTLMPresent = Test-Path -Path (Join-Path -Path "Registry::$CredDelPath" -ChildPath $FreshCredKeyNTLM) -ErrorAction SilentlyContinue
                          If (-not $FreshCredKeyNTLMPresent) {
                              Write-Output "Setting CredSSP registry entry $FreshCredKeyNTLM"
                              Try {
                                  $FreshCredKeyNTLMPath = New-Item -Path "Registry::$CredDelPath" -Name $FreshCredKeyNTLM -ErrorAction Stop | Select-Object -ExpandProperty 'Name'
                              } Catch [System.Exception] {
                                  Write-Output "Failed to create CredSSP registry entry $FreshCredKeyNTLM $_"
                                  Remove-Item -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -Force -Recurse
                                  Exit 1
                              }
                          } Else {
                              $FreshCredKeyNTLMPath = Join-Path -Path $CredDelPath -ChildPath $FreshCredKeyNTLM
                          }

                          Try {
                              $Null = Set-ItemProperty -Path "Registry::$CredDelPath" -Name 'AllowFreshCredentials' -Value '1' -Type 'Dword' -Force -ErrorAction Stop
                              $Null = Set-ItemProperty -Path "Registry::$CredDelPath" -Name 'ConcatenateDefaults_AllowFresh' -Value '1' -Type 'Dword' -Force -ErrorAction Stop
                              $Null = Set-ItemProperty -Path "Registry::$CredDelPath" -Name 'AllowFreshCredentialsWhenNTLMOnly' -Value '1' -Type 'Dword' -Force -ErrorAction Stop
                              $Null = Set-ItemProperty -Path "Registry::$CredDelPath" -Name 'ConcatenateDefaults_AllowFreshNTLMOnly' -Value '1' -Type 'Dword' -Force -ErrorAction Stop
                              $Null = Set-ItemProperty -Path "Registry::$FreshCredKeyPath" -Name '1' -Value 'WSMAN/*' -Type 'String' -Force -ErrorAction Stop
                              $Null = Set-ItemProperty -Path "Registry::$FreshCredKeyNTLMPath" -Name '1' -Value 'WSMAN/*' -Type 'String' -Force -ErrorAction Stop
                          } Catch [System.Exception] {
                              Write-Output "Failed to create CredSSP registry properties $_"
                              Remove-Item -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -Force -Recurse
                              Exit 1
                          }

                          Try {
                              $Null = Enable-WSManCredSSP -Role 'Client' -DelegateComputer '*' -Force -ErrorAction Stop
                              $Null = Enable-WSManCredSSP -Role 'Server' -Force -ErrorAction Stop
                          } Catch [System.Exception] {
                              Write-Output "Failed to enable CredSSP $_"
                              $Null = Disable-WSManCredSSP -Role 'Client' -ErrorAction SilentlyContinue
                              $Null = Disable-WSManCredSSP -Role 'Server' -ErrorAction SilentlyContinue
                              Exit 1
                          }
                      }
                      'Disable' {
                          Write-Output 'Disabling CredSSP'
                          Try {
                              Disable-WSManCredSSP -Role 'Client' -ErrorAction Continue
                              Disable-WSManCredSSP -Role 'Server' -ErrorAction Stop
                          } Catch [System.Exception] {
                              Write-Output "Failed to disable CredSSP $_"
                              Exit 1
                          }

                          Write-Output 'Removing CredSSP registry entries'
                          Try {
                              Remove-Item -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -Force -Recurse -ErrorAction Stop
                          } Catch [System.Exception] {
                              Write-Output "Failed to remove CredSSP registry entries $_"
                              Exit 1
                          }
                      }
                      Default {
                          Write-Output 'InvalidArgument: Invalid value is passed for parameter Action'
                          Exit 1
                      }
                  }
              }

              Function Get-SecretInfo {
                  [CmdletBinding()]
                  Param (
                      [Parameter(Mandatory = $True)][String]$Domain,
                      [Parameter(Mandatory = $True)][String]$SecretArn
                  )

                  Write-Output "Getting $SecretArn Secret"
                  Try {
                      $SecretContent = Get-SECSecretValue -SecretId $SecretArn -ErrorAction Stop | Select-Object -ExpandProperty 'SecretString' | ConvertFrom-Json -ErrorAction Stop
                  } Catch [System.Exception] {
                      Write-Output "Failed to get $SecretArn Secret $_"
                      Exit 1
                  }

                  Write-Output 'Creating PSCredential object from Secret'
                  $Username = $SecretContent.username
                  $UserPassword = ConvertTo-SecureString ($SecretContent.password) -AsPlainText -Force
                  $DomainCredentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ("$Domain\$Username", $UserPassword)
                  $Credentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ($Username, $UserPassword)

                  $Output = [PSCustomObject][Ordered]@{
                      'Credentials'       = $Credentials
                      'DomainCredentials' = $DomainCredentials
                      'Username'          = $Username
                      'UserPassword'      = $UserPassword
                  }

                  Return $Output
              }

              Write-Output 'Getting a domain controller to perform actions against'
              Try {
                  $DC = Get-ADDomainController -Discover -ForceDiscover -ErrorAction Stop | Select-Object -ExpandProperty 'HostName'
              } Catch [System.Exception] {
                  Write-Output "Failed to get a domain controller $_"
                  Exit 1
              }

              If ('{{RunLocation}}' -eq 'MemberServer') { $DomainCreds = (Get-SecretInfo -Domain '{{DomainNetBIOSName}}' -SecretArn '{{SecretArn}}').DomainCredentials }

              Write-Output 'Getting AD domain'
              Try { 
                  If ('{{RunLocation}}' -eq 'MemberServer') { $Domain = Get-ADDomain -Credential $DomainCreds -ErrorAction Stop } Else { $Domain = Get-ADDomain }
              } Catch [System.Exception] {
                  Write-Output "Failed to get AD domain $_" Exit 1
              }

              $FQDN = $Domain | Select-Object -ExpandProperty 'DNSRoot'

              $Alias = '{{Alias}}'
              $Cname = "{{Alias}}.$FQDN"
              $ARecord = '{{ARecord}}'

              If ('{{RunLocation}}' -eq 'MemberServer') { Set-CredSSP -Action 'Enable' }

              $Counter = 0
              Do {
                  $CnameRecordPresent = Resolve-DnsName -Name $Cname -DnsOnly -Server $DC -ErrorAction SilentlyContinue
                  If (-not $CnameRecordPresent) {
                      $Counter ++
                      Write-Output 'CNAME record missing, creating it'
                      If ('{{RunLocation}}' -eq 'MemberServer') { Invoke-Command -Authentication 'CredSSP' -ComputerName $env:COMPUTERNAME -Credential $DomainCreds -ScriptBlock { Add-DnsServerResourceRecordCName -Name $using:Alias -ComputerName $using:DC -HostNameAlias $using:ARecord -ZoneName $using:FQDN } } Else { Add-DnsServerResourceRecordCName -Name $Alias -ComputerName $DC -HostNameAlias $ARecord -ZoneName $FQDN }
                      If ($Counter -gt '1') {
                          Start-Sleep -Seconds 10
                      }
                  }
              } Until ($CnameRecordPresent -or $Counter -eq 12)

              If ($Counter -ge 12) {
                  Write-Output 'CNAME record never created'
                  Exit 1
              }

              If ('{{RunLocation}}' -eq 'MemberServer') { Set-CredSSP -Action 'Disable' }
DOC
}

resource "aws_ssm_association" "fsx_ontap_alias" {
  name             = "SSM-FSx-OnTap-Alias-${var.fsx_ontap_random_string}"
  association_name = "SSM-FSx-OnTap-Alias-${var.fsx_ontap_random_string}"
  parameters = {
    Alias       = var.fsx_ontap_alias
    ARecord     = aws_fsx_ontap_storage_virtual_machine.main.name
    RunLocation = var.fsx_ontap_run_location
    SecretArn   = var.setup_secret_arn
  }
  targets {
    key    = "InstanceIds"
    values = [var.setup_ssm_target_instance_id]
  }
  depends_on = [
    aws_kms_grant.fsx_ontap_setup_account,
    aws_ssm_association.ssm_fsx_ontap_setup
  ]
}
