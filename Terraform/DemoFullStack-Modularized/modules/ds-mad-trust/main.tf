terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

data "aws_iam_role" "main" {
  name = var.mad_trust_ssm_target_iam_role
}

resource "aws_kms_grant" "mad_trust_account" {
  name              = "kms-decrypt-mad-admin-account-secret-grant"
  key_id            = var.mad_trust_secret_kms_key_arn
  grantee_principal = data.aws_iam_role.main.arn
  operations        = ["Decrypt"]
}

resource "aws_kms_grant" "onpremises_administrator_account" {
  name              = "kms-decrypt-onpremises-administrator-account-secret-grant"
  key_id            = var.mad_trust_onpremises_administrator_secret_kms_key_arn
  grantee_principal = data.aws_iam_role.main.arn
  operations        = ["Decrypt"]
}

resource "aws_iam_role_policy" "main" {
  name = "mad-trust-policy"
  role = var.mad_trust_ssm_target_iam_role
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
          var.mad_trust_secret_arn,
          var.mad_trust_onpremises_administrator_secret_arn
        ]
      },
      {
        Action = [
          "ds:CreateConditionalForwarder",
          "ds:CreateTrust",
          "ds:DescribeTrusts",
          "ds:VerifyTrust"
        ]
        Effect   = "Allow"
        Resource = ["*"]
      },
      {
        Action = [
          "kms:Decrypt"
        ]
        Effect = "Allow"
        Resource = [
          var.mad_trust_secret_kms_key_arn,
          var.mad_trust_onpremises_administrator_secret_kms_key_arn
        ]
      }
    ]
  })
}

resource "aws_ssm_document" "main" {
  name            = "SSM-MAD-Trust-Setup-${var.mad_trust_random_string}"
  document_format = "YAML"
  document_type   = "Command"
  content         = <<DOC
    schemaVersion: '2.2'
    description: Create MAD Trust with self-managed AD domain.
    parameters:
      MadDirectoryID:
        description: (Required)
        type: String
      MadDomainDNSName:
        description: (Required)
        type: String
      MadDomainResolver:
        description: (Required)
        type: String
      OnpremisesAdministratorSecret:
        description: (Required)
        type: String
      OnpremisesDomainDNSName:
        description: (Required)
        type: String
      OnpremisesDomainNetBIOSName:
        description: (Required)
        type: String
      OnpremisesDomainResolver:
        description: (Required)
        type: String
      TrustDirection:
        description: (Required)
        type: String
      TrustSecretArn:
        description: (Required)
        type: String
    mainSteps:
      - action: aws:runPowerShellScript
        name: createAlias
        inputs:
          runCommand:
            - |
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
                      'Credentials' = $Credentials
                      'DomainCredentials' = $DomainCredentials
                      'Username' = $Username
                      'UserPassword' = $UserPassword
                  }
                  Return $Output
              }

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

              $Secret = Get-SecretInfo -Domain '{{OnpremisesDomainNetBIOSName}}' -SecretArn '{{OnpremisesAdministratorSecret}}'
              $TrustSecretPassword = (Get-SecretInfo -Domain '{{MadDomainDNSName}}' -SecretArn '{{TrustSecretArn}}').UserPassword
              $MadDomainResolver = '{{MadDomainResolver}}'
              $OnpremisesDomainResolver = '{{OnpremisesDomainResolver}}'
              $TrustDirection = '{{TrustDirection}}'
              Switch ($TrustDirection) {
                  'Two-Way' { 
                      $TrustDirOnprem = 'Bidirectional'
                      $TrustDirMAD = 'Two-Way'
                  }
                  'One-Way: Outgoing' { 
                      $TrustDirOnprem = 'Inbound'
                      $TrustDirMAD = 'One-Way: Outgoing' 
                  }
                  'One-Way: Incoming' { 
                      $TrustDirOnprem = 'Outbound'
                      $TrustDirMAD = 'One-Way: Incoming'
                  }
                  Default { Throw 'InvalidArgument: Invalid value is passed for parameter -TrustDirection' }
              }

              Set-CredSSP -Action 'Enable'
              Invoke-Command -Authentication 'Credssp' -ComputerName $env:COMPUTERNAME -Credential $Secret.DomainCredentials -ScriptBlock {
                  Function Invoke-TrustAction {
                      [CmdletBinding()]
                      Param(
                          [parameter(Mandatory = $true)][String]$RemoteFQDN,
                          [parameter(Mandatory = $true)][String]$TrustDirection,
                          [parameter(Mandatory = $true)][String]$TrustPassword
                      )
                      $LocalForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest() 
                      $AdTrustDir = [System.DirectoryServices.ActiveDirectory.TrustDirection]::$TrustDirection
                      $Null = Clear-DnsServerCache -Force -ErrorAction SilentlyContinue
                      $Null = Clear-DnsClientCache -ErrorAction SilentlyContinue
                      $LocalForest.CreateLocalSideOfTrustRelationship($RemoteFQDN, $AdTrustDir, $TrustPassword)
                      $LocalForest.VerifyOutboundTrustRelationship($RemoteFQDN)
                      & ksetup.exe /SetEncTypeAttr $RemoteFQDN 'RC4-HMAC-MD5' 'AES128-CTS-HMAC-SHA1-96' 'AES256-CTS-HMAC-SHA1-96'
                  }

                  Try {
                      Add-DnsServerConditionalForwarderZone -Name '{{MadDomainDNSName}}' -ReplicationScope 'Forest' -MasterServers $($Using:MadDomainResolver).Split(",")
                  } Catch [System.Exception] {
                      Write-Output "Failed to create conditional fowarder MAD domain $_"
                      Exit 1
                  }
                  $TrustPassword = $Using:TrustSecretPassword
                  Invoke-TrustAction -RemoteFQDN '{{MadDomainDNSName}}' -TrustPassword $TrustPassword -TrustDirection $Using:TrustDirOnprem
              }

              $TrustTypeForest = New-Object -TypeName 'Amazon.DirectoryService.TrustType' -ArgumentList 'Forest'
              $TrustDir = New-Object -TypeName 'Amazon.DirectoryService.TrustDirection' -ArgumentList $TrustDirMAD
              $SelectiveAuthDis = New-Object -TypeName 'Amazon.DirectoryService.SelectiveAuth' -ArgumentList 'Disabled'
              
              Try {
                  $Trust = New-DSTrust -DirectoryId '{{MadDirectoryID}}' -ConditionalForwarderIpAddr $OnpremisesDomainResolver.Split(",") -RemoteDomainName '{{OnpremisesDomainDNSName}}' -SelectiveAuth $SelectiveAuthDis -TrustDirection $TrustDir -TrustType $TrustTypeForest -TrustPassword $TrustSecretPassword
              } Catch [System.Exception] {
                  Write-Output "Failed to create trust between MAD and Onprem $_"
                  Exit 1
              }
              $Counter = 0
              Do {
                  Try {
                      $Truststate = Get-DSTrust -DirectoryId '{{MadDirectoryID}}' -TrustId $Trust -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'TrustState' | Select-Object -ExpandProperty 'Value'
                  } Catch [System.Exception] {
                      Write-Output "Failed to get trust state $_"
                      $Truststate = $Null
                  }
                  If ($Truststate -ne 'Verified' -or $Truststate -eq 'Failed') {
                      $Counter ++
                      Write-Output 'Trust not verified, sleeping 10 seconds and will try again'
                      Start-Sleep -Seconds 10
                  }
              } Until ($Truststate -eq 'Verified' -or $Truststate -eq 'Failed' -or $Counter -eq 30)
              If ($Truststate -eq 'Failed' -or $Counter -eq 30) {
                  Write-Output 'Trust failed to create or never went verified in 5 minutes'
                  Exit 1
              }
DOC
}

resource "aws_ssm_association" "main" {
  name             = "SSM-MAD-Trust-Setup-${var.mad_trust_random_string}"
  association_name = "SSM-MAD-Trust-Setup-${var.mad_trust_random_string}"
  parameters = {
    MadDirectoryID                = var.mad_trust_directory_id
    MadDomainDNSName              = var.mad_trust_mad_domain_dns_name
    MadDomainResolver             = join(",", var.mad_trust_mad_domain_resolver)
    OnpremisesAdministratorSecret = var.mad_trust_onpremises_administrator_secret_arn
    OnpremisesDomainDNSName       = var.mad_trust_onpremises_domain_dns_name
    OnpremisesDomainNetBIOSName   = var.mad_trust_onpremises_domain_netbios_name
    OnpremisesDomainResolver      = join(",", var.mad_trust_onpremises_domain_resolver)
    TrustDirection                = var.mad_trust_direction
    TrustSecretArn                = var.mad_trust_secret_arn
  }
  targets {
    key    = "InstanceIds"
    values = [var.mad_trust_ssm_target_instance_id]
  }
  depends_on = [
    aws_kms_grant.mad_trust_account,
    aws_kms_grant.onpremises_administrator_account,
    aws_iam_role_policy.main
  ]
}
