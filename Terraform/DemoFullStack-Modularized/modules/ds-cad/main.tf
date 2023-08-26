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

data "aws_iam_role" "main" {
  name = var.setup_ec2_iam_role
}

module "kms_secret_key" {
  source                          = "../kms"
  kms_key_description             = "KMS key for CAD Secret encryption"
  kms_key_usage                   = "ENCRYPT_DECRYPT"
  kms_customer_master_key_spec    = "SYMMETRIC_DEFAULT"
  kms_key_deletion_window_in_days = 7
  kms_enable_key_rotation         = true
  kms_key_alias_name              = "cad-secret-kms-key"
  kms_multi_region                = false
  kms_random_string               = var.cad_random_string
}

resource "aws_kms_grant" "cad_service_account" {
  name              = "kms-decrypt-cad-service-account-secret-grant"
  key_id            = module.kms_secret_key.kms_key_id
  grantee_principal = data.aws_iam_role.main.arn
  operations        = ["Decrypt"]
}

resource "aws_kms_grant" "cad_setup_account" {
  name              = "kms-decrypt-cad-setup-account-secret-grant"
  key_id            = var.setup_secret_kms_key_arn
  grantee_principal = data.aws_iam_role.main.arn
  operations        = ["Decrypt"]
}

resource "random_password" "main" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

module "store_secret_cad_svc" {
  source                  = "../secret"
  name                    = "CAD-Svc-Secret-${var.cad_random_string}"
  username                = var.cad_svc_username
  password                = random_password.main.result
  recovery_window_in_days = 0
  secret_kms_key          = module.kms_secret_key.kms_alias_name
}

resource "aws_iam_role_policy" "main" {
  name = "cad-svc-policy"
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
          module.store_secret_cad_svc.secret_arn,
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

resource "aws_ssm_document" "main" {
  name            = "SSM-CAD-Setup-${var.cad_random_string}"
  document_format = "YAML"
  document_type   = "Command"
  content         = <<DOC
    schemaVersion: '2.2'
    description: Create CAD Service Account
    parameters:
      AdConnectorOuParentDn:
        description: (Required)
        type: String
      AdConnectorSvcSecretArn:
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
              $BaseDn = $Domain | Select-Object -ExpandProperty 'DistinguishedName'
              $AdcOU = "OU=AD Connector,{{AdConnectorOuParentDn}}"

              Try {
                  $OuPresent = Get-ADOrganizationalUnit -Identity $AdcOU -Credential $Secret.DomainCredentials -ErrorAction Stop
              } Catch [System.Exception] {
                  If ($_ -like 'Directory object not found') {
                      $OuPresent = $Null
                  } Else {
                      Write-Output "Failed to query AD $_"
                  }
              }

              If (-Not $OuPresent) {
                  Try {
                      New-ADOrganizationalUnit -Name 'AD Connector' -Path '{{AdConnectorOuParentDn}}' -ProtectedFromAccidentalDeletion $True -Credential $Secret.DomainCredentials -ErrorAction Stop
                  } Catch [System.Exception] {
                      Write-Output "Failed to create OU AD Connector $_"
                      Exit 1
                  }
              }

              $AdcSecretInfo = Get-SecretInfo -Domain '{{DomainNetBIOSName}}' -SecretArn '{{AdConnectorSvcSecretArn}}'
              $AdcUsername = $AdcSecretInfo.Username
              $AdcUserPassword = $AdcSecretInfo.UserPassword

              Try {
                  $UserPresent = Get-ADUser -Identity $AdcUsername -Credential $Secret.DomainCredentials -ErrorAction Stop
              } Catch [System.Exception] {
                  If ($_ -like 'Cannot find an object with identity:*') {
                      $UserPresent = $Null
                  } Else {
                      Write-Output "Failed to query AD $_"
                  }
              }

              If (-Not $UserPresent) {
                  $User = @{
                      AccountPassword      = $AdcUserPassword
                      Name                 = $AdcUsername
                      DisplayName          = $AdcUsername
                      SamAccountName       = $AdcUsername
                      UserPrincipalName    = "$AdcUsername@$FQDN"
                      PasswordNeverExpires = $True
                      Enabled              = $True
                      Path                 = $AdcOU
                      Credential           = $Secret.DomainCredentials
                  }

                  Try {
                      New-ADUser @User 
                  } Catch [System.Exception] {
                      Write-Output "Failed to create $AdcUsername $_"
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
                      [System.GUID]$ServicePrincipalNameGuid = (Get-ADObject -SearchBase $RootDse.SchemaNamingContext -Filter { lDAPDisplayName -eq 'servicePrincipalName' } -Properties 'schemaIDGUID' -ErrorAction Stop).schemaIDGUID
                      [System.GUID]$ComputerNameGuid = (Get-ADObject -SearchBase $RootDse.SchemaNamingContext -Filter { lDAPDisplayName -eq 'computer' } -Properties 'schemaIDGUID' -ErrorAction Stop).schemaIDGUID
                  } Catch [System.Exception] {
                      Write-Output "Failed to get Schema GUIDs $_"
                      Exit 1
                  }

                  Try {
                      $User = Get-ADUser -Identity $Using:AdcUsername -ErrorAction Stop
                  } Catch [System.Exception] {
                      Write-Output "Failed to get $Using:AdcUsername $_"
                      Exit 1
                  }

                  Try {
                       $CompContainerDN = Get-ADDomain -ErrorAction Stop | Select-Object -ExpandProperty 'ComputersContainer'
                  } Catch [System.Exception] {
                        Write-Output "Failed to get default computer object container $_"
                        Exit 1
                  }

                  $IdentityReference = $User | Select-Object -ExpandProperty 'SID'
                  $AccountDn = $User | Select-Object -ExpandProperty 'DistinguishedName'

                  $AclRules = @(
                      @{
                          Path = $AccountDn
                          Acl  = @{
                              ActiveDirectoryRights              = 'WriteProperty'
                              AccessControlType                  = 'Allow'
                              ObjectGUID                         = $ServicePrincipalNameGuid
                              ActiveDirectorySecurityInheritance = 'None'
                          }
                      },
                      @{
                          Path = $CompContainerDN
                          Acl  = @{
                              ActiveDirectoryRights              = 'CreateChild'
                              AccessControlType                  = 'Allow'
                              ObjectGUID                         = $ComputerNameGuid
                              ActiveDirectorySecurityInheritance = 'All'
                          }
                      }
                  )

                  Foreach ($AclRule in $AclRules) {
                      Add-OuAcl -AclPath $AclRule.Path -IdentityReference $IdentityReference -ActiveDirectoryRights $AclRule.Acl.ActiveDirectoryRights -AccessControlType $AclRule.Acl.AccessControlType -ObjectGUID $AclRule.Acl.ObjectGUID -ActiveDirectorySecurityInheritance $AclRule.Acl.ActiveDirectorySecurityInheritance
                  }
              }
              Set-CredSSP -Action 'Disable'
DOC
}

resource "aws_ssm_association" "main" {
  name             = "SSM-CAD-Setup-${var.cad_random_string}"
  association_name = "SSM-CAD-Setup-${var.cad_random_string}"
  parameters = {
    AdConnectorOuParentDn   = var.cad_parent_ou_dn
    AdConnectorSvcSecretArn = module.store_secret_cad_svc.secret_arn
    DomainNetBIOSName       = var.cad_domain_netbios_name
    SetupSecretArn          = var.setup_secret_arn
  }
  targets {
    key    = "InstanceIds"
    values = [var.setup_ssm_target_instance_id]
  }
  depends_on = [
    aws_kms_grant.cad_service_account,
    aws_iam_role_policy.main
  ]
}

resource "time_sleep" "wait" {
  depends_on      = [aws_ssm_association.main]
  create_duration = "3m"
}

resource "aws_directory_service_directory" "main" {
  name       = var.cad_domain_fqdn
  password   = random_password.main.result
  short_name = var.cad_domain_netbios_name
  size       = var.cad_size
  type       = "ADConnector"
  tags = {
    Name = "CAD-${var.cad_domain_fqdn}-${var.cad_random_string}"
  }
  connect_settings {
    customer_dns_ips  = var.cad_dns_ips
    customer_username = var.cad_svc_username
    subnet_ids        = var.cad_subnet_ids
    vpc_id            = var.cad_vpc_id
  }
  depends_on = [time_sleep.wait]
}
