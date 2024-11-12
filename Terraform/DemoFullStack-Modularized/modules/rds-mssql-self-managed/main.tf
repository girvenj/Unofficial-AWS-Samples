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
  }
}

locals {
  rds_ports = [
    {
      from_port   = var.rds_self_port_number
      to_port     = var.rds_self_port_number
      description = "SQL"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    }
  ]
}

data "aws_iam_policy_document" "rds_instance_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "rds_monitoring_role_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

data "aws_partition" "main" {}

data "aws_region" "main" {}

data "aws_caller_identity" "main" {}

data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_vpc" "main" {
  id = var.rds_self_vpc_id
}

resource "random_password" "main" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

module "kms_key" {
  source                          = "../kms"
  kms_key_description             = "KMS key for RDS self-managed AD encryption"
  kms_key_usage                   = "ENCRYPT_DECRYPT"
  kms_customer_master_key_spec    = "SYMMETRIC_DEFAULT"
  kms_key_deletion_window_in_days = 7
  kms_enable_key_rotation         = true
  kms_key_alias_name              = "rds-onprem-kms-key"
  kms_multi_region                = false
  kms_random_string               = var.rds_self_random_string
}

module "store_secret" {
  source                  = "../secret"
  name                    = "RDS-Onprem-${var.rds_self_identifier}-Admin-Secret-${var.rds_self_random_string}"
  username                = var.rds_self_username
  username_key            = "username"
  password                = random_password.main.result
  password_key            = "password"
  recovery_window_in_days = 0
  secret_kms_key          = module.kms_key.kms_alias_name
}

resource "aws_iam_role" "rds_monitoring_role" {
  name               = "RDS-Onprem-${var.rds_self_identifier}-Enhanced-Monitoring-Role-${var.rds_self_random_string}"
  assume_role_policy = data.aws_iam_policy_document.rds_monitoring_role_assume_role_policy.json
  tags = {
    Name = "RDS-Onprem-${var.rds_self_identifier}-Enhanced-Monitoring-Role-${var.rds_self_random_string}"
  }
}

resource "aws_iam_role_policy_attachments_exclusive" "rds_monitoring_role" {
  role_name   = aws_iam_role.rds_monitoring_role.name
  policy_arns = [
    "arn:${data.aws_partition.main.partition}:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
  ]
}

resource "aws_db_subnet_group" "rds" {
  name       = "rds-onprem-${var.rds_self_identifier}-subnet-group-${var.rds_self_random_string}"
  subnet_ids = var.rds_self_subnet_ids
  tags = {
    Name = "RDS-Onprem-${var.rds_self_identifier}-Subnet-Group-${var.rds_self_random_string}"
  }
}

module "rds_security_group" {
  source      = "../vpc-security-group-ingress"
  name        = "RDS-Onprem-${var.rds_self_identifier}-Security-Group-${var.rds_self_random_string}"
  description = "RDS Onprem ${var.rds_self_identifier} Security Group ${var.rds_self_random_string}"
  vpc_id      = var.rds_self_vpc_id
  ports       = local.rds_ports
}

resource "aws_db_instance" "rds" {
  allocated_storage                     = var.rds_self_allocated_storage
  apply_immediately                     = true
  auto_minor_version_upgrade            = true
  availability_zone                     = data.aws_availability_zones.available.names[0]
  backup_retention_period               = 1
  db_subnet_group_name                  = aws_db_subnet_group.rds.id
  delete_automated_backups              = true
  deletion_protection                   = false
  domain_auth_secret_arn                = module.store_secret_rds_svc.secret_arn
  domain_dns_ips                        = var.rds_self_dns_ips
  domain_fqdn                           = var.rds_self_domain_fqdn
  domain_ou                             = "OU=RDS-${var.rds_self_random_string},${var.rds_self_parent_ou_dn}"
  enabled_cloudwatch_logs_exports       = ["agent", "error"]
  engine                                = var.rds_self_engine
  engine_version                        = var.rds_self_engine_version
  identifier                            = var.rds_self_identifier
  instance_class                        = var.rds_self_instance_class
  kms_key_id                            = module.kms_key.kms_key_arn
  license_model                         = "license-included"
  monitoring_interval                   = 5
  monitoring_role_arn                   = aws_iam_role.rds_monitoring_role.arn
  multi_az                              = false
  password                              = random_password.main.result
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = module.kms_key.kms_key_arn
  performance_insights_retention_period = 7
  port                                  = var.rds_self_port_number
  publicly_accessible                   = false
  skip_final_snapshot                   = true
  storage_encrypted                     = true
  storage_type                          = var.rds_self_storage_type
  tags = {
    Name = "RDS-Onprem-${var.rds_self_identifier}-${var.rds_self_random_string}"
  }
  vpc_security_group_ids = [module.rds_security_group.sg_id]
  username               = var.rds_self_username
  timeouts {
    create = "3h"
    delete = "3h"
    update = "3h"
  }
}

data "aws_iam_role" "main" {
  name = var.setup_ec2_iam_role
}

resource "aws_kms_grant" "rds_setup_account" {
  name              = "kms-decrypt-rds-onprem-setup-account-secret-grant"
  key_id            = var.setup_secret_kms_key_arn
  grantee_principal = data.aws_iam_role.main.arn
  operations        = ["Decrypt"]
}

resource "random_password" "rds_svc_account" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

module "store_secret_rds_svc" {
  source                  = "../secret"
  name                    = "RDS-Onprem-Svc-Secret-${var.rds_self_random_string}"
  username                = "${var.rds_self_svc_account_username}-${var.rds_self_random_string}"
  username_key            = "CUSTOMER_MANAGED_ACTIVE_DIRECTORY_USERNAME"
  password                = random_password.rds_svc_account.result
  password_key            = "CUSTOMER_MANAGED_ACTIVE_DIRECTORY_PASSWORD"
  recovery_window_in_days = 0
  secret_kms_key          = module.kms_key.kms_alias_name
}

resource "aws_kms_grant" "rds_svc_account_setup" {
  name              = "kms-decrypt-rds-onprem-svc-account-secret-grant-setup"
  key_id            = module.kms_key.kms_key_arn
  grantee_principal = data.aws_iam_role.main.arn
  operations        = ["Decrypt"]
}

resource "aws_kms_key_policy" "rds_svc" {
  key_id = module.kms_key.kms_key_id
  policy = jsonencode({
    Id = "RDS-Self-AD-${var.rds_self_random_string}"
    Statement = [
      {
        Action = "kms:*"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.main.partition}:iam::${data.aws_caller_identity.main.account_id}:root"
        }
        Resource = "*"
        Sid      = "Enable IAM User Permissions"
      },
      {
        Action = "kms:Decrypt"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
        Resource = "*"
        Sid      = "Allow RDS Access to KMS Key"
      }
    ]
    Version = "2012-10-17"
  })
}

data "aws_iam_policy_document" "rds_svc" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:sourceAccount"
      values   = ["${data.aws_caller_identity.main.account_id}"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:sourceArn"
      values   = ["arn:${data.aws_partition.main.partition}:rds:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:db:*"]
    }
  }
}

resource "aws_secretsmanager_secret_policy" "rds_svc" {
  secret_arn = module.store_secret_rds_svc.secret_arn
  policy     = data.aws_iam_policy_document.rds_svc.json
}

resource "aws_iam_role_policy" "main" {
  name = "rds-onprem-svc-policy"
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
          module.store_secret_rds_svc.secret_arn,
          var.setup_secret_arn
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

resource "aws_ssm_document" "ssm_rds_setup" {
  name            = "SSM-RDS-Onprem-Setup-${var.rds_self_random_string}"
  document_format = "YAML"
  document_type   = "Command"
  content         = <<DOC
    schemaVersion: '2.2'
    description: Create RDS Service Account
    parameters:
      RDSAdminGroupName:
        description: (Required)
        type: String
      RDSOuParentDn:
        description: (Required)
        type: String
      RDSSvcSecretArn:
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
                      [Parameter(Mandatory = $True)][String]$SecretArn,
                      [Parameter(Mandatory = $False)][String]$Service
                  )
                  Try {
                      $SecretContent = Get-SECSecretValue -SecretId $SecretArn -ErrorAction Stop | Select-Object -ExpandProperty 'SecretString' | ConvertFrom-Json -ErrorAction Stop
                  } Catch [System.Exception] {
                      Write-Output "Failed to get $SecretArn Secret $_"
                      Exit 1
                  }
                  If ($Service -eq 'RDS') {
                      $Username = $SecretContent.CUSTOMER_MANAGED_ACTIVE_DIRECTORY_USERNAME
                      $UserPassword = ConvertTo-SecureString ($SecretContent.CUSTOMER_MANAGED_ACTIVE_DIRECTORY_PASSWORD) -AsPlainText -Force
                  } Else {
                      $Username = $SecretContent.username
                      $UserPassword = ConvertTo-SecureString ($SecretContent.password) -AsPlainText -Force
                  }

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
              $RDSOuDn = "OU=RDS-{{RandomString}},{{RDSOuParentDn}}"

              Try {
                  $OuPresent = Get-ADOrganizationalUnit -Identity $RDSOuDn -Credential $Secret.DomainCredentials -ErrorAction Stop
              } Catch [System.Exception] {
                  If ($_ -like 'Directory object not found') {
                      $OuPresent = $Null
                  } Else {
                      Write-Output "Failed to query AD $_"
                  }
              }

              If (-Not $OuPresent) {
                  Try {
                      New-ADOrganizationalUnit -Name 'RDS-{{RandomString}}' -Path '{{RDSOuParentDn}}' -ProtectedFromAccidentalDeletion $True -Credential $Secret.DomainCredentials -ErrorAction Stop
                  } Catch [System.Exception] {
                      Write-Output "Failed to create OU RDS $_"
                      Exit 1
                  }
              }

              $RDSSecretInfo = Get-SecretInfo -Domain '{{DomainNetBIOSName}}' -SecretArn '{{RDSSvcSecretArn}}' -Service 'RDS'
              $RDSUsername = $RDSSecretInfo.Username
              $RDSUserPassword = $RDSSecretInfo.UserPassword

              Try {
                  $UserPresent = Get-ADUser -Identity $RDSUsername -Credential $Secret.DomainCredentials -ErrorAction Stop
              } Catch [System.Exception] {
                  If ($_ -like 'Cannot find an object with identity:*') {
                      $UserPresent = $Null
                  } Else {
                      Write-Output "Failed to query AD $_"
                  }
              }

              If (-Not $UserPresent) {
                  $User = @{
                      AccountPassword      = $RDSUserPassword
                      Name                 = $RDSUsername
                      DisplayName          = $RDSUsername
                      SamAccountName       = $RDSUsername
                      UserPrincipalName    = "$RDSUsername@$FQDN"
                      PasswordNeverExpires = $True
                      Enabled              = $True
                      Path                 = $RDSOuDn
                      Credential           = $Secret.DomainCredentials
                  }

                  Try {
                      New-ADUser @User 
                  } Catch [System.Exception] {
                      Write-Output "Failed to create $RDSUsername $_"
                      Exit 1
                  }
              }

              Try {
                  $GroupPresent = Get-ADGroup -Identity '{{RDSAdminGroupName}}' -Credential $Secret.DomainCredentials -ErrorAction Stop
              } Catch [System.Exception] {
                  If ($_ -like 'Cannot find an object with identity:*') {
                      $GroupPresent = $Null
                  } Else {
                      Write-Output "Failed to query AD $_"
                  }
              }

              If (-Not $GroupPresent) {
                  Try {
                      New-ADGroup -DisplayName '{{RDSAdminGroupName}}' -GroupCategory 'Security' -GroupScope 'DomainLocal' -Name '{{RDSAdminGroupName}}' -Path $RDSOuDn -SamAccountName '{{RDSAdminGroupName}}' -Credential $Secret.DomainCredentials  -ErrorAction Stop
                  } Catch [System.Exception] {
                      Write-Output "Failed to create '{{RDSAdminGroupName}}' $_"
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
                      $IdentityReference = Get-ADUser -Identity $Using:RDSUsername -ErrorAction Stop | Select-Object -ExpandProperty 'SID'
                  } Catch [System.Exception] {
                      Write-Output "Failed to get $Using:RDSUsername $_"
                      Exit 1
                  }

                  $NullGuid = [System.Guid]::empty
                  $AclRules = @(
                      @{
                          Path = $Using:RDSOuDn
                          Acl  = @{
                              ActiveDirectoryRights              = 'CreateChild, DeleteChild'
                              AccessControlType                  = 'Allow'
                              ObjectGUID                         = $ComputerNameGuid
                              ActiveDirectorySecurityInheritance = 'All'
                              InheritedObjectGuid                = $NullGuid
                          }
                      },
                      @{
                          Path = $Using:RDSOuDn
                          Acl  = @{
                              ActiveDirectoryRights              = 'Self'
                              AccessControlType                  = 'Allow'
                              ObjectGUID                         = $ExtendedRightsMap['Validated write to service principal name']
                              ActiveDirectorySecurityInheritance = 'Descendents'
                              InheritedObjectGuid                = $ComputerNameGuid
                          }
                      },
                      @{
                          Path = $Using:RDSOuDn
                          Acl  = @{
                              ActiveDirectoryRights              = 'Self'
                              AccessControlType                  = 'Allow'
                              ObjectGUID                         = $ExtendedRightsMap['Validated write to DNS host name']
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

resource "aws_ssm_association" "ssm_rds_setup" {
  name             = "SSM-RDS-Onprem-Setup-${var.rds_self_random_string}"
  association_name = "SSM-RDS-Onprem-Setup-${var.rds_self_random_string}"
  parameters = {
    RDSAdminGroupName = "${var.rds_self_administrators_group}-${var.rds_self_random_string}"
    RDSOuParentDn     = var.rds_self_parent_ou_dn
    RDSSvcSecretArn   = module.store_secret_rds_svc.secret_arn
    DomainNetBIOSName = var.rds_self_domain_netbios_name
    RandomString      = var.rds_self_random_string
    SetupSecretArn    = var.setup_secret_arn
  }
  targets {
    key    = "InstanceIds"
    values = [var.setup_ssm_target_instance_id]
  }
  depends_on = [
    aws_kms_grant.rds_setup_account,
    aws_iam_role_policy.main
  ]
}

resource "time_sleep" "wait" {
  depends_on      = [aws_ssm_association.ssm_rds_setup]
  create_duration = "3m"
}
