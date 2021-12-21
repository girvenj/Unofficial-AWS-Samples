Function Set-LabInstance {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)][String]$ComputerName,
        [Parameter(Mandatory = $False)][String[]]$ExistingDcIp,
        [Parameter(Mandatory = $True)][SecureString]$Password,
        [Parameter(Mandatory = $True)][String][ValidateSet('FirstRootDomainController', 'AdditionalDomainController', 'Standalone', 'MemberServer')][String]$Role
    )

    #==================================================
    # Variables
    #==================================================

    $LoopBackAddress = '127.0.0.1'
    $ServiceName = $MyInvocation.MyCommand.Name

    #==================================================
    # Main
    #==================================================

    If ($ComputerName -ne $env:COMPUTERNAME) {
        Write-ToLog -InvocationName $ServiceName -LogData 'Renaming computer' -Severity 'INFO'
        Try {
            Rename-Computer -NewName $ComputerName -Force -ErrorAction Stop
            Exit 3010
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to rename computer $_" -Severity 'ERROR'
            Exit 1
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting appsettings.json content' -Severity 'INFO'
    Try {
        $KenesisAgentSettings = Get-Content 'C:\ConfigFiles\Baseline\appsettings.json' -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Unable to get appsettings.json content $_" -Severity 'ERROR'
        Exit 1
    }

    $KenesisAgentSettings.Sinks | Where-Object { $_.Region -eq 'ReplaceMe' } | ForEach-Object { $_.Region = 'us-west-2' }

    Write-ToLog -InvocationName $ServiceName -LogData 'Exporting appsettings.json content' -Severity 'INFO'
    Try {
        $KenesisAgentSettings | ConvertTo-Json -Depth 5 -ErrorAction Stop | Out-File 'C:\Program Files\Amazon\AWSKinesisTap\appsettings.json' -Encoding 'ascii' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Unable to export appsettings.json $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Restarting AWSKinesisTap service' -Severity 'INFO'
    Try {
        Restart-Service 'AWSKinesisTap' -Force
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Unable to restart AWSKinesisTap $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting OS installation type' -Severity 'INFO'
    Try {
        $InstallationType = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' -Name 'InstallationType' -ErrorAction Stop | Select-Object -ExpandProperty 'InstallationType'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Unable to get OS installation type $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting InterfaceAlias' -Severity 'INFO'
    Try {
        $InterfaceAlias = Get-NetAdapter -ErrorAction Stop | Select-Object -ExpandProperty 'InterfaceAlias' 
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Unable to get InterfaceAlias $_" -Severity 'ERROR'
        Exit 1
    }
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Checking if more than 1 NIC present' -Severity 'INFO'
    If ($InterfaceAlias.Count -gt 1) {
        Write-ToLog -InvocationName $ServiceName -LogData 'More than 1 NIC present' -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting IP configuration' -Severity 'INFO'
    Try {
        $IpInfo = Get-NetIPConfiguration -InterfaceAlias $InterfaceAlias -ErrorAction Stop 
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Unable to get IP configuration $_" -Severity 'ERROR'
        Exit 1
    }
    
    $IpGw = $IpInfo | Select-Object -ExpandProperty 'IPv4DefaultGateway' | Select-Object -ExpandProperty 'NextHop'
    
    $IpAdd = $IpInfo | Select-Object -ExpandProperty 'IPv4Address' | Select-Object -ExpandProperty 'IPv4Address'
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Getting subnet prefix' -Severity 'INFO'
    Try {
        $Prefix = Get-NetIPAddress -ErrorAction Stop | Where-Object { $_.InterfaceAlias -like $InterfaceAlias -and $_.AddressFamily -eq 'IPv4' } | Select-Object -ExpandProperty 'PrefixLength'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Unable to get subnet prefix $_" -Severity 'ERROR'
        Exit 1
    }

    $DhcpStatus = Get-NetIPInterface -InterfaceAlias $InterfaceAlias -AddressFamily 'IPv4' | Select-Object -ExpandProperty 'DHCP'
    If ($DhcpStatus -eq 'Enabled') {
        Write-ToLog -InvocationName $ServiceName -LogData 'Disabling DHCP' -Severity 'INFO'
        Try {
            Set-NetIPInterface -InterfaceAlias $InterfaceAlias -Dhcp 'Disabled' -ErrorAction Stop 
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Unable to disable DHCP $_" -Severity 'ERROR'
            Exit 1
        }
    }

    $CurrentIp = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily 'IPv4' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'IPAddress' 
    If ($CurrentIp -ne $IpAdd) {
        Try {
            Write-ToLog -InvocationName $ServiceName -LogData 'Setting static IP' -Severity 'INFO'
            $Null = New-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $IpAdd -AddressFamily 'IPv4' -PrefixLength $Prefix -DefaultGateway $IpGw -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Unable to set static IP $_" -Severity 'ERROR'
            Exit 1
        }
    }
    Write-ToLog -InvocationName $ServiceName -LogData 'Installing Windows features and setting DNS client IP' -Severity 'INFO'
    Switch ($Role) {  
        'FirstRootDomainController' {
            If ($InstallationType -eq 'Server') {
                Try {
                    $Null = Install-WindowsFeature -Name 'AD-Domain-Services', 'DNS', 'RSAT-DFS-Mgmt-Con' -IncludeManagementTools -ErrorAction Stop
                } Catch [System.Exception] {
                    Write-ToLog -InvocationName $ServiceName -LogData "Failed to install Windows features $_" -Severity 'ERROR'
                    Exit 1
                }
            } Else {
                Try {
                    $Null = Install-WindowsFeature -Name 'AD-Domain-Services', 'DNS' -IncludeManagementTools -ErrorAction Stop
                } Catch [System.Exception] {
                    Write-ToLog -InvocationName $ServiceName -LogData "Failed to install Windows Features $_" -Severity 'ERROR'
                    Exit 1
                }
            }
            Try {
                Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses ('169.254.169.253', $IpAdd, $LoopBackAddress) -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to set DNS client information $_" -Severity 'ERROR'
                Exit 1
            }
        }
        'AdditionalDomainController' { 
            If ($InstallationType -eq 'Server') {
                Try {
                    $Null = Install-WindowsFeature -Name 'AD-Domain-Services', 'DNS', 'RSAT-DFS-Mgmt-Con' -IncludeManagementTools -ErrorAction Stop
                } Catch [System.Exception] {
                    Write-ToLog -InvocationName $ServiceName -LogData "Failed to install Windows features $_" -Severity 'ERROR'
                    Exit 1
                }
            } Else {
                Try {
                    $Null = Install-WindowsFeature -Name 'AD-Domain-Services', 'DNS' -IncludeManagementTools -ErrorAction Stop
                } Catch [System.Exception] {
                    Write-ToLog -InvocationName $ServiceName -LogData "Failed to install Windows features $_" -Severity 'ERROR'
                    Exit 1
                }
            }
            Try {
                Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses ($ExistingDcIp, $IpAdd, $LoopBackAddress) -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to set DNS client information $_" -Severity 'ERROR'
                Exit 1
            }
        }
        'MemberServer' {
            Try {
                $Null = Install-WindowsFeature -Name 'GPMC', 'RSAT-AD-Tools', 'RSAT-DFS-Mgmt-Con', 'RSAT-DNS-Server' -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to install Windows features $_" -Severity 'ERROR'
                Exit 1
            }
            Try {
                Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses ($ExistingDcIp) -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to set DNS client information $_" -Severity 'ERROR'
                Exit 1
            }
        }
        'Standalone' {
            Try {
                Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses ('169.254.169.253') -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to set DNS client information $_" -Severity 'ERROR'
                Exit 1
            }
        }
        Default { Throw 'InvalidArgument: Invalid value is passed for parameter Type' }
    } 

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting local Administrator password' -Severity 'INFO'
    Try {
        Set-LocalUser -Name 'Administrator' -Password $Password -AccountNeverExpires:$true -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set local Administrator password $_" -Severity 'ERROR'
        Exit 1
    }
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Getting certificate AutoEnrollment policy' -Severity 'INFO'
    Try {
        $CertEnrollmentActive = Get-CertificateAutoEnrollmentPolicy -context 'Machine' -Scope 'Local' | Select-Object -ExpandProperty 'PolicyState' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get certificate AutoEnrollment policy $_" -Severity 'ERROR'
        Exit 1
    }
    If ($CertEnrollmentActive -ne 'Enabled') {
        Write-ToLog -InvocationName $ServiceName -LogData 'Setting certificate AutoEnrollment policy' -Severity 'INFO'
        Try {
            Set-CertificateAutoEnrollmentPolicy -ExpirationPercentage 10 -PolicyState 'Enabled' -EnableTemplateCheck -EnableMyStoreManagement -StoreName 'MY' -context 'Machine' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to set certificate AutoEnrollment policy $_" -Severity 'ERROR'
            Exit 1
        }
    }

    New-VolumeFromRawDisk

    $Null = & C:\Scripts\Set-DscConfiguration.ps1 -RebootNodeIfNeeded $False
   
    Invoke-DscStatusCheck
}

Function Invoke-JoinDomain {
    Param (
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory = $True)][String]$FQDN
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name

    #==================================================
    # Main
    #==================================================

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting interface alias' -Severity 'INFO'
    Try {
        $InterfaceAlias = Get-NetAdapter -ErrorAction Stop | Select-Object -ExpandProperty 'InterfaceAlias'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get interface alias $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting connection suffix' -Severity 'INFO'
    Try {
        Set-DnsClient -InterfaceAlias $InterfaceAlias -ConnectionSpecificSuffix $FQDN -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set connection suffix $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting suffix search list' -Severity 'INFO'
    Try {
        Set-DnsClientGlobalSetting -SuffixSearchList @($FQDN) -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set suffix search list $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting domain membership status' -Severity 'INFO'
    Try {
        $DomainMember = Get-CimInstance -ClassName 'Win32_ComputerSystem' -ErrorAction Stop | Select-Object -ExpandProperty 'Domain'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get domain membership status $_" -Severity 'ERROR'
        Exit 1
    }

    If ($DomainMember -eq 'WORKGROUP') {
        Write-ToLog -InvocationName $ServiceName -LogData 'Adding computer to domain' -Severity 'INFO'
        Try {
            Add-Computer -DomainName $FQDN -Credential $Credentials -ErrorAction Stop
            Exit 3010 
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to get add computer domain $_" -Severity 'ERROR'
            Exit 1
        }
    }

    & w32tm.exe /config /syncfromflags:domhier /reliable:no /update
    & w32tm.exe /resync
}

Function Get-PsModules {
    #==================================================
    # Variables
    #==================================================

    $Modules = @(
        'AWS.Tools.CloudWatch',
        'AWS.Tools.CloudWatchLogs',
        'AWS.Tools.EC2',
        'AWS.Tools.EBS',
        'AWS.Tools.S3',
        'AWS.Tools.SecretsManager',
        'AWS.Tools.Common',
        'NetworkingDsc', 
        'ComputerManagementDsc',
        'PSDscResources',
        'SChannelDsc'
    )

    $ServiceName = $MyInvocation.MyCommand.Name

    #==================================================
    # Main
    #==================================================

    $InstalledModules = Get-Module -ListAvailable -ErrorAction SilentlyContinue

    Foreach ($Module in $Modules) { 
        $ModulePresent = $InstalledModules | Where-Object { $_.Name -eq $Module }
        If (-not $ModulePresent) {
            Write-ToLog -InvocationName $ServiceName -LogData "$Module missing installing it" -Severity 'INFO'
            Try {
                Install-Module -Name $Module -Force -SkipPublisherCheck -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to install module $Module $_" -Severity 'ERROR'
                Exit 1
            }
        } Else {
            Write-ToLog -InvocationName $ServiceName -LogData "$Module already installed, checking version" -Severity 'INFO'
            Try {
                $DesiredVersion = Find-Module -Name $Module -ErrorAction Stop | Select-Object -ExpandProperty 'Version'
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to get latest version of module $Module $_" -Severity 'ERROR'
                Exit 1
            }

            $OldModule = $ModulePresent | Where-Object { [version]($_.Version) -lt [version]($DesiredVersion) }
            If ($OldModule) {
                Write-ToLog -InvocationName $ServiceName -LogData "$Module has and old version uninstalling it and installing current version" -Severity 'INFO'
                Try {
                    Uninstall-Module -Name $OldModule.Name -MaximumVersion $OldModule.Version -Force -ErrorAction Stop
                } Catch [System.Exception] {
                    Write-ToLog -InvocationName $ServiceName -LogData "Failed to uninstall module $Module $_" -Severity 'ERROR'
                    Exit 1
                }

                Try {
                    Install-Module -Name $Module -Force -SkipPublisherCheck -ErrorAction Stop
                } Catch [System.Exception] {
                    Write-ToLog -InvocationName $ServiceName -LogData "Failed to install module $Module $_" -Severity 'ERROR'
                    Exit 1
                }
            } Else {
                Write-ToLog -InvocationName $ServiceName -LogData "$Module current version installed" -Severity 'INFO'
            }
        }
    }
}

Function Write-ToLog {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)][String]$InvocationName,
        [Parameter(Mandatory = $True)][String]$LogData,
        [Parameter(Mandatory = $False)][String]$Severity
    )

    #==================================================
    # Variables
    #==================================================
    Switch ($Severity) {
        'ERROR' { $Color = 'Red' }
        'WARN' { $Color = 'Yellow' }
        'INFO' { $Color = 'Green' }
        default { $Color = 'Gray' }
    }
    $Severity = $Severity.ToUpper()
    #==================================================
    # Main
    #==================================================
    $Output ="[$(Get-Date -Format 'yyyy-MM-dd-THH:mm:ss')][$Severity][$InvocationName]$LogData"
    Write-Output $Output
    $Logs = Join-Path -Path 'C:\' -ChildPath 'Logs'
    If (-not (Test-Path -Path $Logs)) { 
        Try {
            $Null = New-Item -Path $Logs -ItemType 'Directory' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to create $Logs $_"
            Exit 1
        }
    }
    $Output | Out-File -FilePath "C:\Logs\PowerShellOutput-$(Get-Date -Format 'yyyy-MM-dd-THH').log" -Append -Encoding utf8 -ErrorAction Continue
    Write-Host -ForegroundColor $Color $Output
}

Function Get-SecretCreds {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)][String]$DomainNetBIOSName,
        [Parameter(Mandatory = $True)][String]$SecretArn
    )
    
    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name

    #==================================================
    # Main
    #==================================================

    Write-ToLog -InvocationName $ServiceName -LogData "Getting $SecretArn Secret" -Severity 'INFO'
    Try {
        $SecretContent = Get-SECSecretValue -SecretId $SecretArn -ErrorAction Stop | Select-Object -ExpandProperty 'SecretString' | ConvertFrom-Json -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get $SecretArn Secret $_" -Severity 'ERROR'
        Exit 1
    }
       
    Write-ToLog -InvocationName $ServiceName -LogData 'Creating credential object' -Severity 'INFO'
    $Username = $SecretContent.Username
    $UserPW = ConvertTo-SecureString ($SecretContent.Password) -AsPlainText -Force
    $Credentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ("$DomainNetBIOSName\$Username", $UserPW)

    $Output = [PSCustomObject][Ordered]@{
        'Credentials' = $Credentials
        'UserName'    = $Username
        'UserPW'      = $UserPW
    }

    Return $Output
}

Function New-VolumeFromRawDisk {

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name

    #==================================================
    # Main
    #==================================================

    Write-ToLog -InvocationName $ServiceName -LogData 'Finding Raw disk' -Severity 'INFO'
    $Counter = 0
    Do {
        Try {
            $BlankDisks = Get-Disk -ErrorAction Stop | Where-Object { $_.PartitionStyle -eq 'RAW' } | Select-Object -ExpandProperty 'Number'
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to get disk $_" -Severity 'ERROR'
            $BlankDisks = $Null
        }    
        If (-not $BlankDisks) {
            $Counter ++
            Write-ToLog -InvocationName $ServiceName -LogData 'Raw disk not found sleeping 10 seconds and will try again.' -Severity 'INFO'
            Start-Sleep -Seconds 10
        }
    } Until ($BlankDisks -or $Counter -eq 12)

    If ($Counter -ge 12) {
        Write-ToLog -InvocationName $ServiceName -LogData 'Raw disk not found exiting' -Severity 'INFO'
        Return
    }

    Foreach ($BlankDisk in $BlankDisks) {
        Write-ToLog -InvocationName $ServiceName -LogData 'Data volume not initialized attempting to bring online' -Severity 'INFO'
        Try {
            Initialize-Disk -Number $BlankDisk -PartitionStyle 'GPT' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed attempting to bring online data volume $_" -Severity 'ERROR'
            Exit 1
        }

        Start-Sleep -Seconds 5

        Write-ToLog -InvocationName $ServiceName -LogData 'Data volume creating new partition' -Severity 'INFO'
        Try {
            $DriveLetter = New-Partition -DiskNumber $BlankDisk -AssignDriveLetter -UseMaximumSize -ErrorAction Stop | Select-Object -ExpandProperty 'DriveLetter'
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed creating new partition $_" -Severity 'ERROR'
            Exit 1
        }

        Start-Sleep -Seconds 5

        Write-ToLog -InvocationName $ServiceName -LogData 'Formatting partition on Data volume' -Severity 'INFO'
        Try {
            $Null = Format-Volume -DriveLetter $DriveLetter -FileSystem 'NTFS' -NewFileSystemLabel 'Data' -Confirm:$false -Force -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed formatting partition $_" -Severity 'ERROR'
            Exit 1
        }

        Try {
            $Null = Get-CimInstance -ClassName 'Win32_Volume' -Filter "DriveLetter='$($DriveLetter):'" -ErrorAction Stop | Set-CimInstance -Arguments @{ IndexingEnabled = $False }
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to turn off indexing $_" -Severity 'ERROR'
            Exit 1
        }
    }
}

Function Invoke-DscStatusCheck {

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name

    #==================================================
    # Main
    #==================================================

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting DSC configuration status' -Severity 'INFO'
    $LCMState = Get-DscLocalConfigurationManager -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'LCMState'
    If ($LCMState -eq 'PendingConfiguration' -Or $LCMState -eq 'PendingReboot') {
        Write-ToLog -InvocationName $ServiceName -LogData 'Reboot Needed, Exit 3010' -Severity 'INFO'
        Exit 3010
    } Else {
        Write-ToLog -InvocationName $ServiceName -LogData 'DSC configuration completed' -Severity 'INFO'
    }
}

Function Invoke-ConfigureTemplate {
    [CmdletBinding()]
    Param (
        [SecureString]$AdministratorPassword
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name
    $Paths = @(
        'C:\Program Files\Amazon\EC2Launch',
        'C:\ProgramData\Amazon\EC2Launch'
    )
    
    #==================================================
    # Main
    #==================================================

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting local Administrator password' -Severity 'INFO'
    Try {
        Set-LocalUser -Name 'Administrator' -Password $AdministratorPassword -AccountNeverExpires:$true -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set local Administrator password $_" -Severity 'ERROR'
        Exit 1
    }
    
    Remove-Item -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Force -Recurse -ErrorAction SilentlyContinue
    
    $Products = @(
        'AWS Tools for Windows'
    )
    Foreach ($Product in $Products) {
        Write-ToLog -InvocationName $ServiceName -LogData "Uninstalling $Product" -Severity 'INFO'
        Try {
            $Null = Get-CimInstance -ClassName 'Win32_Product' -ErrorAction Stop | Where-Object { $_.Name -match $Product } | Invoke-CimMethod -Name 'Uninstall' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to uninstall $Product $_" -Severity 'ERROR'
            Exit 1
        }
    }
    
    $Prods = @(
        'aws-cfn-bootstrap',
        'Microsoft Visual C++ 2015-2019 Redistributable (x64)*'
    )
    Foreach ($Prod in $Prods) {
        $UninstallString = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object { $_.DisplayName -like $Prod } | Select-Object -ExpandProperty 'UninstallString'
        If ($UninstallString) {
            Write-ToLog -InvocationName $ServiceName -LogData "Uninstalling $Prod" -Severity 'INFO'
            $Null = & cmd.exe /c $UninstallString /quiet /norestart
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Turning off volume indexing' -Severity 'INFO'
    Try {
        $Null = Get-CimInstance -ClassName 'Win32_Volume' -Filter "DriveLetter='C:'" -ErrorAction Stop | Set-CimInstance -Arguments @{ IndexingEnabled = $False }
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to turn off volume indexing $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Cleaning up OS updates' -Severity 'INFO'
    $Null = & Dism.exe /online /cleanup-image /StartComponentCleanup /ResetBase

    Write-ToLog -InvocationName $ServiceName -LogData 'Starting StartComponentCleanup scheduled task' -Severity 'INFO'
    Try {
        Start-ScheduledTask -TaskName '\Microsoft\Windows\Servicing\StartComponentCleanup' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to start StartComponentCleanup scheduled task $_" -Severity 'ERROR'
        Exit 1
    }

    $PPPresent = Get-PackageProvider -Name 'Nuget' -Force -ErrorAction SilentlyContinue
    If (-not $PPPresent) {
        Write-ToLog -InvocationName $ServiceName -LogData 'Install Nuget' -Severity 'INFO'
        Try {
            Install-PackageProvider -Name 'NuGet' -MinimumVersion 2.8.5.208 -Force -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to install Nuget $_" -Severity 'ERROR'
            Exit 1
        }
    }
    
    $PsRepPresent = Get-PSRepository -Name 'PSGallery' | Select-Object -ExpandProperty 'InstallationPolicy' -ErrorAction SilentlyContinue
    If ($PsRepPresent -ne 'Trusted') {
        Write-ToLog -InvocationName $ServiceName -LogData 'Setting PSGallery as trusted' -Severity 'INFO'
        Try {
            Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to set PSGallery as trusted $_" -Severity 'ERROR'
            Exit 1
        }
    }
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Adding envrionment variables for EC2 Launch' -Severity 'INFO'   
    Foreach ($Path in $Paths) {
        $PathContent = [System.Environment]::GetEnvironmentVariable('PATH', 'machine')
        If (-not $PathContent.Contains($Path)) {
            $UpdatePath = $PathContent + ";$Path"
            [Environment]::SetEnvironmentVariable('PATH', $UpdatePath, 'Machine')   
        }
    }
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Installing required PowerShell modules' -Severity 'INFO'   
    Get-PsModules
}

Function Set-CredSSP {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Enable', 'Disable')][string]$Action
    )

    #==================================================
    # Variables
    #==================================================

    $RootKey = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows'
    $CredDelKey = 'CredentialsDelegation'
    $FreshCredKey = 'AllowFreshCredentials'
    $FreshCredKeyNTLM = 'AllowFreshCredentialsWhenNTLMOnly'
    $ServiceName = $MyInvocation.MyCommand.Name

    #==================================================
    # Main
    #==================================================

    Switch ($Action) {
        'Enable' {
            Write-ToLog -InvocationName $ServiceName -LogData 'Enabling CredSSP' -Severity 'INFO'
            Try {
                $Null = Enable-WSManCredSSP -Role 'Client' -DelegateComputer '*' -Force -ErrorAction Stop
                $Null = Enable-WSManCredSSP -Role 'Server' -Force -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to enable CredSSP $_" -Severity 'ERROR'
                $Null = Disable-WSManCredSSP -Role 'Client' -ErrorAction SilentlyContinue
                $Null = Disable-WSManCredSSP -Role 'Server' -ErrorAction SilentlyContinue
                Exit 1
            }
       
            Write-ToLog -InvocationName $ServiceName -LogData 'Setting CredSSP registry entries' -Severity 'INFO'
            $CredDelKeyPresent = Test-Path -Path (Join-Path -Path $RootKey -ChildPath $CredDelKey) -ErrorAction SilentlyContinue
            If (-not $CredDelKeyPresent) {
                Try {
                    $CredDelPath = New-Item -Path $RootKey -Name $CredDelKey -ErrorAction Stop | Select-Object -ExpandProperty 'Name'

                    $FreshCredKeyPresent = Test-Path -Path (Join-Path -Path "Registry::$CredDelPath" -ChildPath $FreshCredKey) -ErrorAction SilentlyContinue
                    If (-not $FreshCredKeyPresent) {
                        $FreshCredKeyPath = New-Item -Path "Registry::$CredDelPath" -Name $FreshCredKey -ErrorAction Stop | Select-Object -ExpandProperty 'Name'
                    }

                    $FreshCredKeyNTLMPresent = Test-Path -Path (Join-Path -Path "Registry::$CredDelPath" -ChildPath $FreshCredKeyNTLM) -ErrorAction SilentlyContinue
                    If (-not $FreshCredKeyNTLMPresent) {
                        $FreshCredKeyNTLMPath = New-Item -Path "Registry::$CredDelPath" -Name $FreshCredKeyNTLM -ErrorAction Stop | Select-Object -ExpandProperty 'Name'
                    }

                    $Null = New-ItemProperty -Path "Registry::$CredDelPath" -Name 'AllowFreshCredentials' -Value '1' -PropertyType 'Dword' -Force -ErrorAction Stop
                    $Null = New-ItemProperty -Path "Registry::$CredDelPath" -Name 'ConcatenateDefaults_AllowFresh' -Value '1' -PropertyType 'Dword' -Force -ErrorAction Stop
                    $Null = New-ItemProperty -Path "Registry::$CredDelPath" -Name 'AllowFreshCredentialsWhenNTLMOnly' -Value '1' -PropertyType 'Dword' -Force -ErrorAction Stop
                    $Null = New-ItemProperty -Path "Registry::$CredDelPath" -Name 'ConcatenateDefaults_AllowFreshNTLMOnly' -Value '1' -PropertyType 'Dword' -Force -ErrorAction Stop
                    $Null = New-ItemProperty -Path "Registry::$FreshCredKeyPath" -Name '1' -Value 'WSMAN/*' -PropertyType 'String' -Force -ErrorAction Stop
                    $Null = New-ItemProperty -Path "Registry::$FreshCredKeyNTLMPath" -Name '1' -Value 'WSMAN/*' -PropertyType 'String' -Force -ErrorAction Stop
                } Catch [System.Exception] {
                    Write-ToLog -InvocationName $ServiceName -LogData "Failed to create CredSSP registry entries $_" -Severity 'ERROR'
                    Remove-Item -Path (Join-Path -Path $RootKey -ChildPath $CredDelKey) -Force -Recurse
                    Exit 1
                }
            }
        }
        'Disable' {
            Write-ToLog -InvocationName $ServiceName -LogData 'Disabling CredSSP' -Severity 'INFO'
            Try {
                Disable-WSManCredSSP -Role 'Client' -ErrorAction Continue
                Disable-WSManCredSSP -Role 'Server' -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to disable CredSSP $_" -Severity 'ERROR'
                Exit 1
            }

            Write-ToLog -InvocationName $ServiceName -LogData 'Removing CredSSP registry entries'-Severity 'INFO'
            Try {
                Remove-Item -Path (Join-Path -Path $RootKey -ChildPath $CredDelKey) -Force -Recurse
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to remove CredSSP registry entries $_" -Severity 'ERROR'
                Exit 1
            }
        }
        Default { 
            Write-ToLog -InvocationName $ServiceName -LogData 'InvalidArgument: Invalid value is passed for parameter Action' -Severity 'ERROR'
            Exit 1
        }
    }
}

Function Invoke-Sysprep {

    #==================================================
    # Main
    #==================================================

    Remove-Item -Path 'C:\Temp\*' -Recurse -Force
    Remove-Item -Path 'C:\Logs\*' -Recurse -Force -ErrorAction Stop
    & wevtutil.exe enum-logs | Foreach-Object { & wevtutil.exe clear-log '$_' }
    
    $SysPrepFile = "$Env:ProgramData\Amazon\EC2Launch\sysprep\Unattend.xml"
    $SysPrepXml = [xml](Get-Content -Path $SysPrepFile)
    $SysPrepElements = $SysPrepXml.Get_DocumentElement()  
    $SysPrepSpecSetting = $SysPrepElements.Settings | Where-Object { $_.Pass -eq 'Specialize' }
    $SysPrepSpecComponent = $SysPrepSpecSetting.Component | Where-Object { $_.Name -eq 'Microsoft-Windows-Shell-Setup' }
    $SysPrepSpecComponent.CopyProfile = 'False'
    $SysPrepOobeSetting = $SysPrepElements.Settings | Where-Object { $_.Pass -eq 'oobeSystem' }
    $SysPrepOobeComponent = $SysPrepOobeSetting.Component | Where-Object { $_.Name -eq 'Microsoft-Windows-International-Core' }
    $SysPrepOobeComponent.InputLocale = 'en-US'
    $SysPrepOobeComponent.SystemLocale = 'en-US'
    $SysPrepOobeComponent.UILanguage = 'en-US'
    $SysPrepOobeComponent.UserLocale = 'en-US'
    $SysPrepXml.Save($SysPrepFile)
    & ec2launch.exe sysprep -c -s
    Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue
}