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
  fsx_ports = [
    {
      from_port   = 445
      to_port     = 445
      description = "SMB"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 5985
      to_port     = 5986
      description = "WinRM"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    }
  ]
}

data "aws_vpc" "main" {
  id = var.fsx_self_vpc_id
}

data "aws_iam_role" "main" {
  name = var.setup_ec2_iam_role
}

module "kms_key" {
  source                          = "../kms"
  kms_key_description             = "KMS key for Onprem FSx encryption"
  kms_key_usage                   = "ENCRYPT_DECRYPT"
  kms_customer_master_key_spec    = "SYMMETRIC_DEFAULT"
  kms_key_deletion_window_in_days = 7
  kms_enable_key_rotation         = true
  kms_key_alias_name              = "fsx-onprem-secret-kms-key"
  kms_multi_region                = false
  kms_random_string               = var.fsx_self_random_string
}

resource "aws_kms_grant" "fsx_svc_account" {
  name              = "kms-decrypt-fsx-onprem-service-account-secret-grant"
  key_id            = module.kms_key.kms_key_id
  grantee_principal = data.aws_iam_role.main.arn
  operations        = ["Decrypt"]
}

resource "aws_kms_grant" "fsx_setup_account" {
  name              = "kms-decrypt-fsx-onprem-setup-account-secret-grant"
  key_id            = var.setup_secret_kms_key_arn
  grantee_principal = data.aws_iam_role.main.arn
  operations        = ["Decrypt"]
}

resource "random_password" "main" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

module "store_secret_fsx_svc" {
  source                  = "../secret"
  name                    = "FSx-Onprem-Svc-Secret-${var.fsx_self_random_string}"
  username                = "${var.fsx_self_username}-${var.fsx_self_random_string}"
  username_key            = "username"
  password                = random_password.main.result
  password_key            = "password"
  recovery_window_in_days = 0
  secret_kms_key          = module.kms_key.kms_alias_name
}

resource "aws_iam_role_policy" "main" {
  name = "fsx-onprem-svc-policy"
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
          module.store_secret_fsx_svc.secret_arn,
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

resource "aws_ssm_document" "ssm_fsx_setup" {
  name            = "SSM-FSx-Onprem-Setup-${var.fsx_self_random_string}"
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
      RandomString:
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

                          If (Test-Path -Path $(Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey)) {
                              Write-Output 'Removing CredSSP registry entries'
                              Try {
                                  Remove-Item -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -Force -Recurse -ErrorAction Stop
                              } Catch [System.Exception] {
                                  Write-Output "Failed to remove CredSSP registry entries $_"
                                  #Exit 1
                              }
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
              $FSxOuDn = "OU=FSx-{{RandomString}},{{FSxOuParentDn}}"

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
                      New-ADOrganizationalUnit -Name 'FSx-{{RandomString}}' -Path '{{FSxOuParentDn}}' -ProtectedFromAccidentalDeletion $True -Credential $Secret.DomainCredentials -ErrorAction Stop
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

resource "aws_ssm_association" "ssm_fsx_setup" {
  name             = "SSM-FSx-Onprem-Setup-${var.fsx_self_random_string}"
  association_name = "SSM-FSx-Onprem-Setup-${var.fsx_self_random_string}"
  parameters = {
    FSxAdminGroupName = "${var.fsx_self_file_system_administrators_group}-${var.fsx_self_random_string}"
    FSxOuParentDn     = var.fsx_self_parent_ou_dn
    FSxSvcSecretArn   = module.store_secret_fsx_svc.secret_arn
    DomainNetBIOSName = var.fsx_self_domain_netbios_name
    RandomString      = var.fsx_self_random_string
    SetupSecretArn    = var.setup_secret_arn
  }
  targets {
    key    = "InstanceIds"
    values = [var.setup_ssm_target_instance_id]
  }
  depends_on = [
    aws_kms_grant.fsx_svc_account,
    aws_iam_role_policy.main
  ]
}

resource "time_sleep" "wait" {
  depends_on      = [aws_ssm_association.ssm_fsx_setup]
  create_duration = "3m"
}

module "fsx_security_group" {
  source      = "../vpc-security-group-ingress"
  name        = "${var.fsx_self_alias}-FSx-Onprem-${var.fsx_self_domain_fqdn}-Security-Group-${var.fsx_self_random_string}"
  description = "${var.fsx_self_alias} FSx Onprem ${var.fsx_self_domain_fqdn} Security Group"
  vpc_id      = var.fsx_self_vpc_id
  ports       = local.fsx_ports
}

resource "aws_fsx_windows_file_system" "main" {
  aliases                         = ["${var.fsx_self_alias}.${var.fsx_self_domain_fqdn}"]
  automatic_backup_retention_days = var.fsx_self_automatic_backup_retention_days
  deployment_type                 = var.fsx_self_deployment_type
  kms_key_id                      = module.kms_key.kms_key_arn
  preferred_subnet_id             = var.fsx_self_subnet_ids[0]
  security_group_ids              = [module.fsx_security_group.sg_id]
  skip_final_backup               = true
  storage_capacity                = var.fsx_self_storage_capacity
  storage_type                    = var.fsx_self_storage_type
  subnet_ids                      = var.fsx_self_subnet_ids
  throughput_capacity             = var.fsx_self_throughput_capacity
  tags = {
    Name = "${var.fsx_self_alias}-FSx-Onprem-${var.fsx_self_domain_fqdn}-${var.fsx_self_random_string}"
  }
  self_managed_active_directory {
    dns_ips                                = var.fsx_self_dns_ips
    domain_name                            = var.fsx_self_domain_fqdn
    file_system_administrators_group       = "${var.fsx_self_file_system_administrators_group}-${var.fsx_self_random_string}"
    organizational_unit_distinguished_name = "OU=FSx-${var.fsx_self_random_string},${var.fsx_self_parent_ou_dn}"
    password                               = random_password.main.result
    username                               = "${var.fsx_self_username}-${var.fsx_self_random_string}"
  }
  depends_on = [time_sleep.wait]
}

#resource "aws_ec2_tag" "eni" {
#  for_each    = aws_fsx_windows_file_system.main.network_interface_ids
#  resource_id = each.value
#  key         = "Name"
#  value       = "${var.fsx_self_alias}-FSx-Onprem-${var.fsx_self_domain_fqdn}-${var.fsx_self_random_string}"
#}

resource "aws_ssm_document" "ssm_fsx_alias" {
  name            = "SSM-FSx-Onprem-Alias-${var.fsx_self_random_string}"
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

                          If (Test-Path -Path $(Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey)) {
                              Write-Output 'Removing CredSSP registry entries'
                              Try {
                                  Remove-Item -Path (Join-Path -Path "Registry::$RootKey" -ChildPath $CredDelKey) -Force -Recurse -ErrorAction Stop
                              } Catch [System.Exception] {
                                  Write-Output "Failed to remove CredSSP registry entries $_"
                                  #Exit 1
                              }
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

resource "aws_ssm_association" "fsx_self_alias" {
  name             = "SSM-FSx-Onprem-Alias-${var.fsx_self_random_string}"
  association_name = "SSM-FSx-Onprem-Alias-${var.fsx_self_random_string}"
  parameters = {
    Alias       = var.fsx_self_alias
    ARecord     = aws_fsx_windows_file_system.main.dns_name
    RunLocation = var.fsx_self_run_location
    SecretArn   = var.setup_secret_arn
  }
  targets {
    key    = "InstanceIds"
    values = [var.setup_ssm_target_instance_id]
  }
  depends_on = [
    aws_kms_grant.fsx_setup_account,
    aws_ssm_association.ssm_fsx_setup
  ]
}
