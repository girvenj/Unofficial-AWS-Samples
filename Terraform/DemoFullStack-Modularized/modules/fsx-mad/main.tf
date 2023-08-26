terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
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

data "aws_directory_service_directory" "main" {
  directory_id = var.fsx_mad_directory_id
}

data "aws_iam_role" "main" {
  name = var.setup_ec2_iam_role
}

data "aws_vpc" "main" {
  id = var.fsx_mad_vpc_id
}

module "kms_key" {
  source                          = "../kms"
  kms_key_description             = "KMS key for FSx encryption"
  kms_key_usage                   = "ENCRYPT_DECRYPT"
  kms_customer_master_key_spec    = "SYMMETRIC_DEFAULT"
  kms_key_deletion_window_in_days = 7
  kms_enable_key_rotation         = true
  kms_key_alias_name              = "fsx-mad-secret-kms-key"
  kms_multi_region                = false
  kms_random_string               = var.fsx_mad_random_string
}

resource "aws_iam_role_policy" "main" {
  name = "fsx-svc-policy"
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

resource "aws_kms_grant" "main" {
  name              = "kms-decrypt-fsx-setup-account-secret-grant"
  key_id            = var.setup_secret_kms_key_arn
  grantee_principal = data.aws_iam_role.main.arn
  operations        = ["Decrypt"]
}

resource "aws_ssm_document" "main" {
  name            = "SSM-FSx-MAD-Alias-${var.fsx_mad_random_string}"
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

              $DomainCreds = (Get-SecretInfo -Domain '{{DomainNetBIOSName}}' -SecretArn '{{SecretArn}}').DomainCredentials

              Write-Output 'Getting AD domain'
              Try { 
                   $Domain = Get-ADDomain -Credential $DomainCreds -ErrorAction Stop
              } Catch [System.Exception] {
                  Write-Output "Failed to get AD domain $_" Exit 1
              }

              $FQDN = $Domain | Select-Object -ExpandProperty 'DNSRoot'

              $Alias = '{{Alias}}'
              $Cname = "{{Alias}}.$FQDN"
              $ARecord = '{{ARecord}}'

              Set-CredSSP -Action 'Enable'

              $Counter = 0
              Do {
                  $CnameRecordPresent = Resolve-DnsName -Name $Cname -DnsOnly -Server $DC -ErrorAction SilentlyContinue
                  If (-not $CnameRecordPresent) {
                      $Counter ++
                      Write-Output 'CNAME record missing, creating it'
                      Invoke-Command -Authentication 'CredSSP' -ComputerName $env:COMPUTERNAME -Credential $DomainCreds -ScriptBlock { Add-DnsServerResourceRecordCName -Name $using:Alias -ComputerName $using:DC -HostNameAlias $using:ARecord -ZoneName $using:FQDN }
                      If ($Counter -gt '1') {
                          Start-Sleep -Seconds 10
                      }
                  }
              } Until ($CnameRecordPresent -or $Counter -eq 12)

              If ($Counter -ge 12) {
                  Write-Output 'CNAME record never created'
                  Exit 1
              }

              Set-CredSSP -Action 'Disable'
DOC
}

resource "aws_ssm_association" "main" {
  name             = "SSM-FSx-MAD-Alias-${var.fsx_mad_random_string}"
  association_name = "SSM-FSx-MAD-Alias-${var.fsx_mad_random_string}"
  parameters = {
    Alias             = var.fsx_mad_alias
    ARecord           = aws_fsx_windows_file_system.main.dns_name
    DomainNetBIOSName = var.fsx_mad_directory_netbios_name
    SecretArn         = var.fsx_mad_setup_secret_arn
  }
  targets {
    key    = "InstanceIds"
    values = [var.setup_ssm_target_instance_id]
  }
}

module "fsx_security_group" {
  source      = "../vpc-security-group-ingress"
  name        = "FSx-MAD-${var.fsx_mad_alias}-Security-Group-${var.fsx_mad_random_string}"
  description = "FSx MAD ${var.fsx_mad_alias} Security Group"
  vpc_id      = var.fsx_mad_vpc_id
  ports       = local.fsx_ports
}

resource "aws_fsx_windows_file_system" "main" {
  active_directory_id             = var.fsx_mad_directory_id
  aliases                         = ["${var.fsx_mad_alias}.${data.aws_directory_service_directory.main.name}"]
  automatic_backup_retention_days = var.fsx_mad_automatic_backup_retention_days
  deployment_type                 = var.fsx_mad_deployment_type
  kms_key_id                      = module.kms_key.kms_key_arn
  preferred_subnet_id             = var.fsx_mad_subnet_ids[0]
  security_group_ids              = [module.fsx_security_group.sg_id]
  skip_final_backup               = true
  storage_capacity                = var.fsx_mad_storage_capacity
  storage_type                    = var.fsx_mad_storage_type
  subnet_ids                      = var.fsx_mad_subnet_ids
  throughput_capacity             = var.fsx_mad_throughput_capacity
  tags = {
    Name = "FSx-MAD-${var.fsx_mad_alias}-${var.fsx_mad_random_string}"
  }
}

#resource "aws_ec2_tag" "eni" {
#  for_each    = aws_fsx_windows_file_system.main.network_interface_ids
#  resource_id = each.value
#  key         = "Name"
#  value       = "FSx-MAD-${var.fsx_mad_alias}-${var.fsx_mad_random_string}"
#}
