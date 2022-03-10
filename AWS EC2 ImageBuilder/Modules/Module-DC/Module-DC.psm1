#Requires -Modules ActiveDirectory, DnsServer, GroupPolicy

Function Set-DcPromo {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)][System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory = $true)][String]$DomainName,
        [Parameter(Mandatory = $false)][String]$Mode,
        [Parameter(Mandatory = $false)][String]$NetbiosName,
        [Parameter(Mandatory = $false)][String]$RootDomainName,
        [Parameter(Mandatory = $true)][SecureString]$SafeModeAdministratorPassword,
        [Parameter(Mandatory = $true)][String][ValidateSet('First', 'Additional', 'Child', 'Tree')][String]$Type
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name

    #==================================================
    # Main
    #==================================================

    Write-ToLog -InvocationName $ServiceName -LogData 'Promoting domain controller' -Severity 'INFO'
    Switch ($Type) { 
        'First' {
            Try {
                Install-ADDSForest -InstallDns:$true -DomainName $DomainName -DomainMode $Mode -ForestMode $Mode -SafeModeAdministratorPassword $SafeModeAdministratorPassword -DomainNetbiosName $NetbiosName -DatabasePath 'D:\NTDS' -SysvolPath 'D:\SYSVOL' -LogPath 'D:\NTDS' -Confirm:$false -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to install root Active Directory domain $_" -Severity 'ERROR'
                Exit 1
            }
        }
        'Additional' { 
            Try {
                Install-ADDSDomainController -InstallDns:$true -Credential $Credentials -DomainName $DomainName -SafeModeAdministratorPassword $SafeModeAdministratorPassword -DatabasePath 'D:\NTDS' -SysvolPath 'D:\SYSVOL' -LogPath 'D:\NTDS' -Confirm:$false -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to install additional Active Directory domain controller $_" -Severity 'ERROR'
                Exit 1
            }
        }
        'Tree' { 
            Try {
                Install-ADDSDomain -InstallDNS:$true -DomainType 'TreeDomain' -ParentDomainName $RootDomainName -NewDomainName $DomainName -Credential $Credentials -DomainMode $Mode -SafeModeAdministratorPassword $SafeModeAdministratorPassword -NewDomainNetbiosName $NetbiosName -DatabasePath 'D:\NTDS' -SysvolPath 'D:\SYSVOL' -LogPath 'D:\NTDS' -Confirm:$false -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to install Active Directory $_"
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to install tree Active Directory domain $_" -Severity 'ERROR'
                Exit 1
            }
        }
        'Child' { 
            Try {
                Install-ADDSDomain -InstallDNS:$true -DomainType 'ChildDomain' -ParentDomainName $RootDomainName -NewDomainName $DomainName -Credential $Credentials -DomainMode $Mode -SafeModeAdministratorPassword $SafeModeAdministratorPassword -CreateDNSDelegation -DnsDelegationCredential $SubordinateDomainType -NewDomainNetbiosName $NetbiosName -DatabasePath 'D:\NTDS' -SysvolPath 'D:\SYSVOL' -LogPath 'D:\NTDS' -Confirm:$false -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to install Active Directory $_"
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to install child Active Directory domain $_" -Severity 'ERROR'
                Exit 1
            }
        }
        Default { Throw 'InvalidArgument: Invalid value is passed for parameter Type' }
    }
}

Function Set-DefaultContainer {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][String]$ComputerDN,
        [Parameter(Mandatory = $true)][String]$UserDN
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name
   
    #==================================================
    # Main
    #==================================================

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting domain information' -Severity 'INFO'
    Try {
        $Domain = Get-ADDomain -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get domain information $_" -Severity 'ERROR'
        Exit 1
    }
    
    $BaseDn = $Domain | Select-Object -ExpandProperty 'DistinguishedName'
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Getting Well Known Objects' -Severity 'INFO'
    Try {
        $WellKnownObjects = Get-ADObject -Identity $BaseDn -Properties wellKnownObjects -ErrorAction Stop | Select-Object -ExpandProperty 'wellKnownObjects'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get Well Known Objects $_" -Severity 'ERROR'
        Exit 1
    }

    $CurrentUserWko = $WellKnownObjects | Where-Object { $_ -match 'Users' }
    $CurrentComputerWko = $WellKnownObjects | Where-Object { $_ -match 'Computer' }
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Setting new default computer and user object location' -Severity 'INFO'
    If ($CurrentUserWko -and $CurrentComputerWko) {
        $DataUsers = $CurrentUserWko.split(':')
        $DataComputers = $CurrentComputerWko.split(':')
        $NewUserWko = $DataUsers[0] + ':' + $DataUsers[1] + ':' + $DataUsers[2] + ':' + $UserDN 
        $NewComputerWko = $DataComputers[0] + ':' + $DataComputers[1] + ':' + $DataComputers[2] + ':' + $ComputerDN

        Try {
            Set-ADObject $BaseDn -Add @{wellKnownObjects = $NewUserWko } -Remove @{wellKnownObjects = $CurrentUserWko } -ErrorAction Stop
            Set-ADObject $BaseDn -Add @{wellKnownObjects = $NewComputerWko } -Remove @{wellKnownObjects = $CurrentComputerWko } -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to set new default computer and user object location $_" -Severity 'ERROR'
            Exit 1
        }
    } Else {
        & redircmp.exe $ComputerDN
        & redirusr.exe $UserDN
    }
}

Function Set-PostDcPromo {

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name    
    $ComputerName = $Env:ComputerName
    $LoopBackAddress = '127.0.0.1'
    $InstanceMetaDataUri = 'http://169.254.169.254/latest/meta-data/'
    $DefaultDNSForwarder = '169.254.169.253'

    #==================================================
    # Main
    #==================================================

    $Logs = @(
        'Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational',
        'Microsoft-Windows-DNSServer/Audit',
        'Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational',
        'Microsoft-Windows-NTLM/Operational',
        'Microsoft-Windows-Kerberos/Operational',
        'Microsoft-Windows-Security-Netlogon/Operational'
    )

    Foreach ($Log in $Logs) {
        Try {
            $IsEnabled = Get-WinEvent -ListLog $Log -ErrorAction Stop | Select-Object -ExpandProperty 'IsEnabled'
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Unable to get log $Log $_" -Severity 'ERROR'
        }
        If ($IsEnabled -eq 'False') {
            Try {
                $SetIsEnabled = New-Object -TypeName 'System.Diagnostics.Eventing.Reader.EventLogConfiguration' $Log
                $SetIsEnabled.IsEnabled=$true
                $SetIsEnabled.SaveChanges()
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Unable to enable log $Log $_" -Severity 'ERROR'
            }
        }
    }

    [string]$Token = Invoke-RestMethod -Headers @{ 'X-aws-ec2-metadata-token-ttl-seconds' = '3600' } -Method 'PUT' -Uri 'http://169.254.169.254/latest/api/token' -UseBasicParsing -ErrorAction Stop

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting NIC information' -Severity 'INFO'
    Try {
        $Nic = Get-NetAdapter -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get NIC information $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting domain information' -Severity 'INFO'
    Try {
        $Domain = Get-ADDomain -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get domain information $_" -Severity 'ERROR'
        Exit 1
    }

    $DomainName = $Domain | Select-Object -ExpandProperty 'DNSRoot'
    $BaseDn = $Domain | Select-Object -ExpandProperty 'DistinguishedName'

    $MacAddress = $Nic | Select-Object -ExpandProperty 'MacAddress'
    $MacFormated = $MacAddress.replace('-', ':').ToLower()
    $InterfaceAlias = $Nic | Select-Object -ExpandProperty 'InterfaceAlias'

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting IP information' -Severity 'INFO'
    Try {
        $IPAddress = Get-NetIPConfiguration -InterfaceAlias $InterfaceAlias -ErrorAction Stop | Select-Object -ExpandProperty 'IPv4Address' | Select-Object -ExpandProperty 'IPAddress'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get IP information $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting client DNS IPs' -Severity 'INFO'
    Try {
        Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses ($IPAddress, $LoopBackAddress) -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set client DNS IPs $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting client DNS suffix' -Severity 'INFO'
    Try { 
        Set-DnsClient -InterfaceAlias $InterfaceAlias -ConnectionSpecificSuffix $DomainName -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set client DNS suffix $_" -Severity 'ERROR'
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting client DNS suffix search list' -Severity 'INFO'
    Try {
        Set-DnsClientGlobalSetting -SuffixSearchList @($DomainName) -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set client DNS suffix search list $_" -Severity 'ERROR'
        Exit 1
    }

    $Count = 0
    Do {
        $Count ++
        Try {
            $AdwsStatus = Get-Service -Name 'ADWS' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'Status'
        } Catch {
            $AdwsStatus = $Null
        }

        If ($Count -ge 1) {
            Start-Sleep -Seconds 10
        }

    } Until ($AdwsStatus -eq 'Running' -or $Count -eq 90)

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting PDCe' -Severity 'INFO'
    Try {
        $Pdce = Get-ADDomainController -Service 'PrimaryDC' -Discover -ErrorAction Stop | Select-Object -ExpandProperty 'Name'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to find PDCe $_" -Severity 'ERROR'
        Exit 1
    }

    If ($ComputerName -eq $Pdce) {
    
        Write-ToLog -InvocationName $ServiceName -LogData 'Setting PasswordNotRequired flag on Guest to false' -Severity 'INFO'
        Try {
            Set-ADUser 'Guest' -PasswordNotRequired $False -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to set the PasswordNotRequired flag on Guest to false $_" -Severity 'ERROR'
            #Exit 1
        }

        $OUs = @(
            'Domain Elevated Accounts',
            'Domain Users',
            'Domain Computers',
            'Domain Servers',
            'Domain Service Accounts',
            'Domain Groups'
        )

        $Groups = @(
            @{
                Name        = 'Domain Server Admins'
                Path        = "OU=Domain Groups,$BaseDn"
                Description = 'Members of this group are Domain Server Administrators'
            },
            @{
                Name        = 'Domain Workstation Admins'
                Path        = "OU=Domain Groups,$BaseDn"
                Description = 'Members of this group are Domain Workstation Administrators'
            }
        )

        Try {
            $RootDse = Get-ADRootDSE -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to get Root DSE Info $_" -Severity 'ERROR'
            Exit 1
        }

        $SchemaClassObjGuidMap = @{}
        $ScNamingContexts = Get-ADObject -SearchBase $RootDse.SchemaNamingContext -LDAPFilter '(schemaidguid=*)' -Properties lDAPDisplayName, schemaIDGUID -ErrorAction Stop
        ForEach ($ScNamingContext in $ScNamingContexts) {
            $SchemaClassObjGuidMap[$ScNamingContext.lDAPDisplayName] = [System.GUID]$ScNamingContext.schemaIDGUID
        }
    
        $Audits = @(
            @{
                Name = 'Everyone'
                Acls = @(
                    @{
                        PsProvider = 'AD'
                        AclClass   = 'AdAudit'
                        AclPath    = $BaseDN
                        AclRule    = @{
                            ActiveDirectoryRights              = 'Delete'
                            AuditFlags                         = 'Success'
                            ObjectGUID                         = $SchemaClassObjGuidMap['organizationalUnit']
                            ActiveDirectorySecurityInheritance = 'Descendents'
                            InheritedObjectGuid                = $SchemaClassObjGuidMap['organizationalUnit']
                        }
                    }
                )
            }
        )
    
        Foreach ($Audit in $Audits) {
            ForEach ($Acl in $Audit.Acls) {
                Set-AclOnObject -Name $Audit.Name @Acl
            }
        }

        Foreach ($OU in $OUs) {
            Try {
                $OuPresent = Get-ADOrganizationalUnit -Identity "OU=$OU,$BaseDn" -ErrorAction SilentlyContinue
            } Catch {
                $OuPresent = $Null
            }
            If (-not $OuPresent) {
                Write-ToLog -InvocationName $ServiceName -LogData "Creating OU $OU" -Severity 'INFO'
                Try {
                    New-ADOrganizationalUnit -Name $OU -Path $BaseDn -ProtectedFromAccidentalDeletion $True -ErrorAction Stop
                } Catch [System.Exception] {
                    Write-ToLog -InvocationName $ServiceName -LogData "Failed to create OU $OU $_" -Severity 'ERROR'
                    Exit 1
                }
            }
        }

        Foreach ($Group in $Groups) {
            Try {
                $GroupPresent = Get-ADGroup -Identity $Group.Name -ErrorAction SilentlyContinue
            } Catch {
                $GroupPresent = $Null
            }
            If (-not $GroupPresent) {
                Write-ToLog -InvocationName $ServiceName -LogData "Creating management groups $($Group.Name)" -Severity 'INFO'
                Try {
                    New-ADGroup -Name $Group.Name -SamAccountName $Group.Name -GroupCategory 'Security' -GroupScope 'DomainLocal' -DisplayName $Group.Name -Path $Group.Path -Description $Group.Description -ErrorAction Stop
                } Catch [System.Exception] {
                    Write-ToLog -InvocationName $ServiceName -LogData "Failed to create management groups $($Group.Name) $_" -Severity 'ERROR'
                    Exit 1
                }
            }
        }

        Write-ToLog -InvocationName $ServiceName -LogData 'Setting LDAP idle time to 5 Minutes' -Severity 'INFO'
        & ntdsutil.exe "LDAP policies" connections "connect to server localhost" quit "Set MaxConnIdleTime to 300" "Commit Changes" quit quit
        
        $GuestPwStatus = Get-ADUser -Identity 'Guest' -Properties 'Passwordnotrequired', 'PasswordNeverExpires' -ErrorAction SilentlyContinue
        If ($GuestPwStatus.Passwordnotrequired -eq $True -or $GuestPwStatus.PasswordNeverExpires -eq $True ) {
            Write-ToLog -InvocationName $ServiceName -LogData 'Setting -PasswordNeverExpires flag on Guest' -Severity 'INFO'
            Try {
                Set-ADUser 'Guest' -PasswordNeverExpires $False -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to set -PasswordNeverExpires flag to false on Guest $_" -Severity 'ERROR'
                #Exit 1
            }
        }

        $KdsKeyPresent = Get-KdsRootKey -ErrorAction SilentlyContinue
        If (-not $KdsKeyPresent) {
            Write-ToLog -InvocationName $ServiceName -LogData 'Adding Kds Root Key' -Severity 'INFO'
            Try {
                Add-KdsRootKey -EffectiveTime ((Get-Date).addhours(-10)) -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to add Kds Root Key $_" -Severity 'ERROR'
                Exit 1
            }
        }
        Write-ToLog -InvocationName $ServiceName -LogData 'Setting default object containers' -Severity 'INFO'
        Set-DefaultContainer -ComputerDN "OU=Domain Computers,$BaseDn" -UserDN "OU=Domain Users,$BaseDn"
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting DNS blind forwarder' -Severity 'INFO'
    Try {
        Set-DnsServerForwarder -IPAddress $DefaultDNSForwarder -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set DNS blind forwarder $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting DNS server settings' -Severity 'INFO'
    Try {
        $Dnsip = Get-DnsServerSetting -All -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get DNS server settings $_" -Severity 'ERROR'
        Exit 1
    }

    $Dnsip.listeningIpAddress = @($IPAddress)

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting DNS server settings' -Severity 'INFO'
    Try {
        Set-DnsServerSetting -InputObject $DnsIp -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set DNS server settings $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Restarting DNS server service' -Severity 'INFO'
    $Null = Restart-Service 'DNS' -ErrorAction SilentlyContinue

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting DNS server diagnostics' -Severity 'INFO'
    Try {
        Set-DnsServerDiagnostics -All $true -ErrorAction Stop
        Start-Sleep -Seconds 5
        Set-DnsServerDiagnostics -LogFilePath 'c:\DnsLogs\DNSlog.txt' -MaxMBFileSize '500000000' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set DNS server diagnostics $_" -Severity 'ERROR'
        Exit 1
    }
    
    Start-Sleep -Seconds 10

    $CIDRUrl = $InstanceMetaDataUri + "network/interfaces/macs/$MacFormated/vpc-ipv4-cidr-blocks"
    Write-ToLog -InvocationName $ServiceName -LogData 'Getting VPC CIDR block' -Severity 'INFO'
    Try {
        $CIDR = Invoke-RestMethod -Headers @{ 'X-aws-ec2-metadata-token' = $Token } -Method 'GET' -Uri $CIDRUrl -UseBasicParsing -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get CIDR block $_" -Severity 'ERROR'
        Exit 1
    }

    $AClass = 0..8
    $BClass = 9..16
    $CClass = 17..24
    $DClass = 25..32
    $CidrIP = $CIDR.Split('/')[0]
    [System.Collections.ArrayList]$IPArray = $CidrIP -Split "\."
    $Range = $CIDR.Split('/')[1]
    If ($AClass -contains $Range) {
        [System.Array]$Number = $IPArray[0] 
    } Elseif ($BClass -contains $Range) {
        [System.Array]$Number = $IPArray[0, 1]
    } Elseif ($CClass -contains $Range) {
        [System.Array]$Number = $IPArray[0, 1, 2] 
    } Elseif ($DClass -contains $Range) {
        [System.Array]$Number = $IPArray[0, 1, 2, 3] 
    } 
    [System.Array]::Reverse($Number)
    $IpRev = $Number -Join "."
    $ZoneName = $IpRev + '.in-addr.arpa'
    
    $Count = 0
    Do {
        $Count ++
        Try {
            $ZonePresent = Get-DnsServerZone -Name $ZoneName -ErrorAction Stop
        } Catch {
            $ZonePresent = $Null
        }
        If (-Not $ZonePresent) {
            Write-ToLog -InvocationName $ServiceName -LogData "Creating DNS PTR zone $CIDR" -Severity 'INFO'
            Add-DnsServerPrimaryZone -NetworkId $CIDR -ReplicationScope 'Forest' -ErrorAction SilentlyContinue
        }
    } Until ($Null -ne $ZonePresent -or $Count -eq 6)

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting primary zone to Forest replication' -Severity 'INFO'
    Try {
        Set-DnsServerPrimaryZone -Name $DomainName -ReplicationScope 'Forest' -ErrorAction Stop
    } Catch {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set primary zone to Forest replication $_" -Severity 'ERROR'
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Enabling zone scavenging on all DNS zones' -Severity 'INFO'
    Try {
        Set-DnsServerScavenging -ApplyOnAllZones -RefreshInterval '7.00:00:00' -NoRefreshInterval '7.00:00:00' -ScavengingState $True -ScavengingInterval '7.00:00:00' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to enable zone scavenging on all DNS zones $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Registering DNS client' -Severity 'INFO'
    Register-DnsClient -ErrorAction SilentlyContinue
   
    Write-ToLog -InvocationName $ServiceName -LogData 'Getting region' -Severity 'INFO'
    Try {
        $Region = (Invoke-RestMethod -Headers @{'X-aws-ec2-metadata-token' = $Token } -Method 'GET' -Uri 'http://169.254.169.254/latest/dynamic/instance-identity/document' -UseBasicParsing -ErrorAction Stop | Select-Object -ExpandProperty 'Region').ToUpper()
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get region $_" -Severity 'ERROR'
        Exit 1
    }

    Try {
        $SitePresent = Get-ADReplicationSite -Identity $Region -ErrorAction SilentlyContinue
    } Catch {
        $SitePresent = $Null
    }
    
    If (-Not $SitePresent) {
        Try {
            Write-ToLog -InvocationName $ServiceName -LogData 'Creating new site' -Severity 'INFO'
            New-ADReplicationSite -Name $Region -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to create new site $_" -Severity 'ERROR'
            Exit 1
        }

        $Sites = Get-ADReplicationSite -Filter * -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'Name'
        If ($Site -ge 2) {
            Foreach ($Site in $Sites) {
                Write-ToLog -InvocationName $ServiceName -LogData 'Creating new site link' -Severity 'INFO'
                Try {
                    New-SiteLink -SiteA $Site -SiteB $Region -Cost '50' -ReplicationFrequencyInMinutes '15' -ErrorAction Stop
                } Catch [System.Exception] {
                    Write-ToLog -InvocationName $ServiceName -LogData "Failed to create new site link $_" -Severity 'ERROR'
                    Exit 1
                }
            }
        }
    } 

    Try {
        $SubnetPresent = Get-ADReplicationSubnet -Identity $CIDR -ErrorAction SilentlyContinue
    } Catch {
        $SubnetPresent = $Null
    }
    
    If (-Not $SubnetPresent) {
        Write-ToLog -InvocationName $ServiceName -LogData 'Creating new site subnet' -Severity 'INFO'
        Try {
            New-ADReplicationSubnet -Name $CIDR -Site $Region -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to create new site subnet $_" -Severity 'ERROR'
            Exit 1
        }
    }
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Getting domain controller site' -Severity 'INFO'
    Try {
        $DcSite = Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction Stop | Select-Object -ExpandProperty 'Site'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get domain controller site $_" -Severity 'ERROR'
        Exit 1
    }

    If ($DcSite -ne $Region) {
        Write-ToLog -InvocationName $ServiceName -LogData 'Moving domain controller to proper site' -Severity 'INFO'
        Try {
            Move-ADDirectoryServer -Identity $Env:ComputerName -Site $Region -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to move domain controller to proper site $_" -Severity 'ERROR'
            Exit 1
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting certificate auto-enrollment policy' -Severity 'INFO'
    Try {
        $CertEnrollmentActive = Get-CertificateAutoEnrollmentPolicy -context 'Machine' -Scope 'Local' | Select-Object -ExpandProperty 'PolicyState' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get certificate auto-enrollment policy $_" -Severity 'ERROR'
        Exit 1
    }
    If ($CertEnrollmentActive -ne 'Enabled') {
        Write-ToLog -InvocationName $ServiceName -LogData 'Setting certificate auto-enrollment policy' -Severity 'INFO'
        Try {
            Set-CertificateAutoEnrollmentPolicy -ExpirationPercentage 10 -PolicyState 'Enabled' -EnableTemplateCheck -EnableMyStoreManagement -StoreName 'MY' -context 'Machine' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to set certificate auto-enrollment policy $_" -Severity 'ERROR'
            Exit 1
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Start certificate auto-enrollment scheduled task' -Severity 'INFO'
    Start-ScheduledTask -TaskName '\Microsoft\Windows\CertificateServicesClient\SystemTask' -ErrorAction SilentlyContinue

    Write-ToLog -InvocationName $ServiceName -LogData 'Enabling SMBv1 auditing' -Severity 'INFO'
    Set-SmbServerConfiguration -AuditSmb1Access $true -Force -ErrorAction SilentlyContinue

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting SYSVOL location' -Severity 'INFO'
    Try {
        $SysVolLocation = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ErrorAction Stop | Select-Object -ExpandProperty 'SysVol'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get SYSVOL location $_" -Severity 'ERROR'
        Exit 1
    }

    $GroupPolicyObjectsFolder = "$SysVolLocation\$DomainName\Policies"
    $PolicyDefinitions = Join-Path -Path $GroupPolicyObjectsFolder -ChildPath 'PolicyDefinitions'
    
    If (-not (Test-Path -Path $PolicyDefinitions)) {
        Write-ToLog -InvocationName $ServiceName -LogData 'Creating PolicyDefinitions folder' -Severity 'INFO'
        Try {
            $Null = New-Item -Path $GroupPolicyObjectsFolder -Name 'PolicyDefinitions' -ItemType 'Directory' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to creation PolicyDefinitions folder $_" -Severity 'ERROR'
            Exit 1
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Unzipping files to PolicyDefinitions folder' -Severity 'INFO'
    Try {
        $Null = Expand-Archive -LiteralPath 'C:\Modules\Module-DC\GPOs\PolicyDefinitions.zip' -DestinationPath $PolicyDefinitions -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to unzip files to PolicyDefinitions folder $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting Administrator KerberosEncryptionType' -Severity 'INFO'
    Try {
        Set-ADUser -Identity 'Administrator' -KerberosEncryptionType 'AES128', 'AES256' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set Administrator KerberosEncryptionType $_" -Severity 'ERROR'
        Exit 1
    }
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Running DSC configuration' -Severity 'INFO'
    & C:\Scripts\Set-DscConfiguration.ps1 -RebootNodeIfNeeded $True
}

Function Set-PostDcPromoPdce {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][String]$DeletedObjectLifetime,
        [Parameter(Mandatory = $true)][String]$Tombstonelifetime
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name
    $WMIFilters = @(
        @{
            FilterName        = 'PDCe Role Filter'
            FilterDescription = 'PDCe Role Filter'
            FilterExpression  = 'Select * From Win32_ComputerSystem where (DomainRole = 5)'
        },
        @{
            FilterName        = 'Non PDC Role Filter'
            FilterDescription = 'Non PDC Role Filter'
            FilterExpression  = 'Select * From Win32_ComputerSystem where (DomainRole = 4)'
        }
    )

    #==================================================
    # Main
    #==================================================
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Getting forest information' -Severity 'INFO'
    Try {
        $RootDomain = Get-ADForest -ErrorAction Stop | Select-Object -ExpandProperty 'RootDomain'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get forest information $_" -Severity 'ERROR'
        Exit 1
    }

    $ComputerName = "$($Env:ComputerName).$RootDomain"

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting PDCe' -Severity 'INFO'
    Try {
        $Pdce = Get-ADDomain -Identity $RootDomain -ErrorAction Stop | Select-Object -ExpandProperty 'PDCEmulator'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get PDCe $_" -Severity 'ERROR'
        Exit 1
    }

    If ($ComputerName -eq $Pdce) {
        Write-ToLog -InvocationName $ServiceName -LogData 'Getting forest information' -Severity 'INFO'
        Try {
            Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval '7.00:00:00' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to enable server zone scavenging $_" -Severity 'ERROR'
            Exit 1
        } 

        Try {
            $Domain = Get-ADDomain -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to get domain info $_" -Severity 'ERROR'
            Exit 1
        }

        $Root = $Domain | Select-Object -ExpandProperty 'DNSRoot'
        $BaseDn = $Domain | Select-Object -ExpandProperty 'DistinguishedName'

        $Groups = @(
            @{
                Name        = 'Enterprise Server Admins'
                Path        = "OU=Domain Groups,$BaseDn"
                Description = 'Members of this group are Enterprise Server Administrators'
            },
            @{
                Name        = 'Enterprise Workstation Admins'
                Path        = "OU=Domain Groups,$BaseDn"
                Description = 'Members of this group are Enterprise Workstation Administrators'
            }
        )

        $BinEnabled = Get-ADOptionalFeature -Identity 'Recycle Bin Feature' -Properties 'EnabledScopes' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'EnabledScopes'
        
        If (-not $BinEnabled) {
            Write-ToLog -InvocationName $ServiceName -LogData 'Enabling AD Recycle Bin' -Severity 'INFO'
            Try {
                $Null = Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope 'ForestOrConfigurationSet' -Target $Root -Confirm:$False -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to enable AD Recycle Bin $_" -Severity 'ERROR'
                Exit 1
            } 
        }
        
        Write-ToLog -InvocationName $ServiceName -LogData 'Setting DeletedObjectLifetime and Tombstonelifetime' -Severity 'INFO'
        Try {
            Set-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$BaseDn" -Partition "CN=Configuration,$BaseDn" -Replace:@{'msDS-DeletedObjectLifetime' = $DeletedObjectLifetime } -ErrorAction Stop
            Set-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$BaseDn" -Partition "CN=Configuration,$BaseDn" -Replace:@{'tombstonelifetime' = $Tombstonelifetime } -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to set DeletedObjectLifetime and Tombstonelifetime $_" -Severity 'ERROR'
            Exit 1
        } 

        Foreach ($Group in $Groups) {
            Try {
                $GroupPresent = Get-ADGroup -Identity $Group.Name -ErrorAction SilentlyContinue
            } Catch {
                $GroupPresent = $Null
            }
            If (-not $GroupPresent) {
                Write-ToLog -InvocationName $ServiceName -LogData "Creating management groups $($Group.Name)" -Severity 'INFO'
                Try {
                    New-ADGroup -Name $Group.Name -SamAccountName $Group.Name -GroupCategory 'Security' -GroupScope 'DomainLocal' -DisplayName $Group.Name -Path $Group.Path -Description $Group.Description -ErrorAction Stop
                } Catch [System.Exception] {
                    Write-ToLog -InvocationName $ServiceName -LogData "Failed to create management groups $($Group.Name) $_" -Severity 'ERROR'
                    Exit 1
                }
            }
        } 

        Write-ToLog -InvocationName $ServiceName -LogData 'Updating GPO migration table' -Severity 'INFO'
        Update-PolMigTable

        Foreach ($WMIFilter in $WMIFilters) {
            Import-WMIFilter @WMIFilter
        }

        $GPOs = @(
            @{
                BackupGpoName = 'Domain Computer Security Policy'
                LinkEnabled   = 'Yes'
                Targets       = @(
                    @{
                        Location = "OU=Domain Computers,$BaseDn"
                        Order    = '1'
                    }
                )
            },
            @{
                BackupGpoName = 'Domain Controller Security Policy'
                LinkEnabled   = 'Yes'
                Targets       = @(
                    @{
                        Location = "OU=Domain Controllers,$BaseDn"
                        Order    = '1'
                    }
                )
            },
            @{
                BackupGpoName = 'PDCe Time Policy'
                LinkEnabled   = 'Yes'
                WMIFilterName = 'PDCe Role Filter'
                Targets       = @(
                    @{
                        Location = "OU=Domain Controllers,$BaseDn"
                        Order    = '2'
                    }
                )
            },
            @{
                BackupGpoName = 'NT5DS Time Policy'
                LinkEnabled   = 'Yes'
                WMIFilterName = 'Non PDC Role Filter'
                Targets       = @(
                    @{
                        Location = "OU=Domain Controllers,$BaseDn"
                        Order    = '3'
                    }
                )
            },
            @{
                BackupGpoName = 'Domain Member Server Security Policy'
                LinkEnabled   = 'Yes'
                Targets       = @(
                    @{
                        Location = "OU=Domain Servers,$BaseDn"
                        Order    = '1'
                    }
                )
            },
            @{
                BackupGpoName = 'Windows Update Policy'
                LinkEnabled   = 'Yes'
                Targets       = @(
                    @{
                        Location = "OU=Domain Controllers,$BaseDn"
                        Order    = '4'
                    },
                    @{
                        Location = "OU=Domain Servers,$BaseDn"
                        Order    = '2'
                    },
                    @{
                        Location = "OU=Domain Computers,$BaseDn"
                        Order    = '2'
                    }
                )
            },
            @{
                BackupGpoName = 'Default Domain Controllers Policy'
                LinkEnabled   = 'No'
                Targets       = @(
                    @{
                        Location = "OU=Domain Controllers,$BaseDn"
                        Order    = '5'
                    }
                )
            },
            @{
                BackupGpoName = 'Default Domain Policy'
                LinkEnabled   = 'Yes'
                Targets       = @(
                    @{
                        Location = $BaseDn
                        Order    = '1'
                    }
                )
            },
            @{
                BackupGpoName = 'Certificate Auto-Enrollment Policy'
                LinkEnabled   = 'Yes'
                Targets       = @(
                    @{
                        Location = $BaseDn
                        Order    = '2'
                    }
                )
            }
        )
        Write-ToLog -InvocationName $ServiceName -LogData 'Importing GPOs' -Severity 'INFO'
        Foreach ($GPO in $GPOS) {
            Import-GroupPolicy @GPO
            ForEach ($Target in $GPO.Targets) {
                Set-GroupPolicyLink -BackupGpoName $GPO.BackupGpoName -Target $Target.Location -LinkEnabled $GPO.LinkEnabled -Order $Target.Order
            }
        }

        Write-ToLog -InvocationName $ServiceName -LogData "Removing Default Domain Controllers Policy link from OU=Domain Controllers,$BaseDn" -Severity 'INFO'
        Remove-GPLink -Name 'Default Domain Controllers Policy' -Target "OU=Domain Controllers,$BaseDn" -ErrorAction SilentlyContinue

        $SAs = Get-ADGroupMember 'Schema Admins' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'Name'
        If ($SAs) {
            Foreach ($SA in $SAs) {
                Try {
                    Remove-ADGroupMember -Identity 'Schema Admins' -Members $SA -Confirm:$False -ErrorAction Stop
                } Catch [System.Exception] {
                    Write-ToLog -InvocationName $ServiceName -LogData "Failed to remove $SA from Schema Admins $_" -Severity 'ERROR'
                }
            }
        } 

        Invoke-GPUpdate -RandomDelayInMinutes '0' -Force
        Restart-Service 'w32time' -Force
        & w32tm.exe /resync       
    } Else {
        Write-ToLog -InvocationName $ServiceName -LogData 'Not Root PDCe' -Severity 'INFO'
    }
}

Function Set-PostMadPromo {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory = $true)][String]$DeletedObjectLifetime
    )
    
    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name
    $OUs = @(
        'Elevated Accounts',
        'Servers',
        'Service Accounts',
        'Groups'
    )

    #==================================================
    # Main
    #==================================================

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting domain information' -Severity 'INFO'
    Try {
        $Domain = Get-ADDomain -Credential $Credentials -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get domain information $_" -Severity 'ERROR'
        Exit 1
    }

    $DomainName = $Domain | Select-Object -ExpandProperty 'DNSRoot'
    $BaseDn = $Domain | Select-Object -ExpandProperty 'DistinguishedName'
    $NetBIOSName = $Domain | Select-Object -ExpandProperty 'NetBIOSName'

    $Groups = @(
        @{
            Name        = 'Domain Server Admins'
            Path        = "OU=Domain Groups,$BaseDn"
            Description = 'Members of this group are Domain Server Administrators'
        },
        @{
            Name        = 'Domain Workstation Admins'
            Path        = "OU=Domain Groups,$BaseDn"
            Description = 'Members of this group are Domain Workstation Administrators'
        }
    )

    Foreach ($Group in $Groups) {
        Try {
            $GroupPresent = Get-ADGroup -Identity $Group.Name -ErrorAction SilentlyContinue
        } Catch {
            $GroupPresent = $Null
        }
        If (-not $GroupPresent) {
            Write-ToLog -InvocationName $ServiceName -LogData "Creating management groups $($Group.Name)" -Severity 'INFO'
            Try {
                New-ADGroup -Name $Group.Name -SamAccountName $Group.Name -GroupCategory 'Security' -GroupScope 'DomainLocal' -DisplayName $Group.Name -Path $Group.Path -Description $Group.Description -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to create management groups $($Group.Name) $_" -Severity 'ERROR'
                Exit 1
            }
        }
    }  

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting interface alias' -Severity 'INFO'
    Try {
        $InterfaceAlias = Get-NetAdapter -ErrorAction Stop | Select-Object -ExpandProperty 'InterfaceAlias'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get interface alias $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting DNS client suffix' -Severity 'INFO'
    Try { 
        Set-DnsClient -InterfaceAlias $InterfaceAlias -ConnectionSpecificSuffix $DomainName -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set DNS client suffix $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting client DNS client suffix search list' -Severity 'INFO'
    Try {
        Set-DnsClientGlobalSetting -SuffixSearchList @($DomainName) -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set DNS client suffix search list $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting DNS blind forwarder' -Severity 'INFO'
    Try {
        Set-DnsServerForwarder -IPAddress $DefaultDNSForwarder -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set DNS blind forwarder $_" -Severity 'ERROR'
        Exit 1
    }

    Foreach ($OU in $OUs) {
        Try {
            $OuPresent = Get-ADOrganizationalUnit -Identity "OU=$OU,OU=$NetBIOSName,$BaseDn" -Credential $Credentials -ErrorAction SilentlyContinue
        } Catch {
            $OuPresent = $Null
        }
        If (-not $OuPresent) {
            Write-ToLog -InvocationName $ServiceName -LogData "Creating OU $OU $_" -Severity 'INFO'
            Try {
                New-ADOrganizationalUnit -Name $OU -Path "OU=$NetBIOSName,$BaseDn" -ProtectedFromAccidentalDeletion $True -Credential $Credentials -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to create OU $OU $_" -Severity 'ERROR'
                Exit 1
            }
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting DeletedObjectLifetime' -Severity 'INFO'
    Try {
        Set-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$BaseDN" -Partition "CN=Configuration,$BaseDN" -Replace:@{'msDS-DeletedObjectLifetime' = $DeletedObjectLifetime } -Credential $Credentials -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set DeletedObjectLifetime $_" -Severity 'ERROR'
        Exit 1
    }

    $GroupPolicyObjectsFolder = "\\$DomainName\SYSVOL\$DomainName\Policies\"

    Try {
        $Null = New-PSDrive -Name 'SysvolPSDrive' -PSProvider 'FileSystem' -Root $GroupPolicyObjectsFolder -Credential $Credentials -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to create SubPkiSysvolPSDrive $_" -Severity 'ERROR'
        Exit 1
    }

    $PolicyDefinitions = Join-Path -Path 'SysvolPSDrive:\' -ChildPath 'PolicyDefinitions'

    If (-not (Test-Path -Path $PolicyDefinitions)) {
        Write-ToLog -InvocationName $ServiceName -LogData 'Creating PolicyDefinitions folder' -Severity 'INFO'
        Try {
            New-Item -Path 'SysvolPSDrive:\' -Name 'PolicyDefinitions' -ItemType 'Directory' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to create PolicyDefinitions folder $_" -Severity 'ERROR'
            Exit 1
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Unzipping to PolicyDefinitions folder' -Severity 'INFO'
    Try {
        Expand-Archive -LiteralPath 'C:\Modules\Module-DC\GPOs\PolicyDefinitions.zip' -DestinationPath $PolicyDefinitions -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to unzip files to PolicyDefinitions folder $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting Administrator KerberosEncryptionType' -Severity 'INFO'
    Try {
        Set-ADUser -Identity 'Administrator' -KerberosEncryptionType 'AES128', 'AES256' -Credential $Credentials -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set Administrator KerberosEncryptionType $_" -Severity 'ERROR'
        Exit 1
    }
}

Function New-SiteLink {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][String]$Cost,
        [Parameter(Mandatory = $true)][String]$ReplicationFrequencyInMinutes,
        [Parameter(Mandatory = $true)][String]$SiteA,
        [Parameter(Mandatory = $true)][String]$SiteB
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name

    #==================================================
    # Main
    #==================================================

    $SiteLinkPresent = Get-ADReplicationSiteLink -Identity "$SiteA-$SiteB" -ErrorAction SilentlyContinue
    If (-not $SiteLinkPresent) {
        Write-ToLog -InvocationName $ServiceName -LogData 'Creating new site link' -Severity 'INFO'
        Try {
            New-ADReplicationSiteLink -Name "$SiteA-$SiteB" -SitesIncluded $SiteA, $SiteB -Cost '50' -ReplicationFrequencyInMinutes '15' -InterSiteTransportProtocol 'IP' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to create new site link $_" -Severity 'ERROR'
            Exit 1
        }

        Write-ToLog -InvocationName $ServiceName -LogData 'Enabling change notification on new site link' -Severity 'INFO'
        Try {
            Set-ADReplicationSiteLink -Identity "$SiteA-$SiteB" -Replace @{ options = $($options -bor 1) } -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to enable change notification on new site link $_" -Severity 'ERROR'
            Exit 1
        } 
    }
}

Function Invoke-TrustAction {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true)][String]$Action,
        [parameter(Mandatory = $true)][String]$RemoteFQDN,
        [parameter(Mandatory = $false)][String]$TrustDirection,
        [parameter(Mandatory = $false)][String]$TrustPassword,
        [parameter(Mandatory = $False)][ValidateSet('Forest', 'Domain')][String]$Type = 'Forest'
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name

    #==================================================
    # Main
    #==================================================

    Switch ($Type) {
        'Forest' { $LocalForestOrDomain = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest() }
        'Domain' { $LocalForestOrDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() }
        Default { Throw 'InvalidArgument: Invalid value is passed for parameter Type' }
    }

    Switch ($Action) {
        'Create' {
            If (-Not $TrustPassword) {
                Throw 'MissingArgument: Value is missing for parameter TrustPassword'
            }
            Switch ($TrustDirection) {
                'Outgoing' { $AdTrustDir = [System.DirectoryServices.ActiveDirectory.TrustDirection]::Outbound }
                'Incoming' { $AdTrustDir = [System.DirectoryServices.ActiveDirectory.TrustDirection]::Inbound }
                'Bidirectional' { $AdTrustDir = [System.DirectoryServices.ActiveDirectory.TrustDirection]::Bidirectional }
                Default { throw 'InvalidArgument: Invalid value is passed for parameter TrustDirection' }
            }
            $Null = Clear-DnsServerCache -Force -ErrorAction SilentlyContinue
            $Null = Clear-DnsClientCache -ErrorAction SilentlyContinue
            $LocalForestOrDomain.CreateLocalSideOfTrustRelationship($RemoteFQDN, $AdTrustDir, $TrustPassword)
            & ksetup.exe /SetEncTypeAttr $RemoteFQDN 'RC4-HMAC-MD5' 'AES128-CTS-HMAC-SHA1-96' 'AES256-CTS-HMAC-SHA1-96'
        }
        'Delete' {
            $LocalForestOrDomain.DeleteLocalSideOfTrustRelationship($RemoteFQDN)
        } 
        'Verify' { $LocalForestOrDomain.VerifyOutboundTrustRelationship($RemoteFQDN) } 
        'EnableSelectiveAuth' { $LocalForestOrDomain.SetSelectiveAuthenticationStatus($RemoteFQDN, $True) }
        'DisableSelectiveAuth' { $LocalForestOrDomain.SetSelectiveAuthenticationStatus($RemoteFQDN, $False) }
        Default { Throw 'InvalidArgument: Invalid value is passed for parameter Action' }
    }
}

Function New-GPWmiFilter {
    [CmdletBinding()] 
    Param
    (
        [Parameter(Mandatory = $False)][string]$Description,
        [Parameter(Mandatory = $True)][string]$Expression,
        [Parameter(Mandatory = $True)][string]$Name
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name

    #==================================================
    # Main
    #==================================================

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting RootDSE' -Severity 'INFO'
    Try {
        $DefaultNamingContext = Get-ADRootDSE -ErrorAction Stop | Select-Object -ExpandProperty 'DefaultNamingContext'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get RootDSE $_" -Severity 'ERROR'
        Exit 1
    }

    $CreationDate = (Get-Date).ToUniversalTime().ToString('yyyyMMddhhmmss.ffffff-000')
    $GUID = "{$([System.Guid]::NewGuid())}"
    $DistinguishedName = "CN=$GUID,CN=SOM,CN=WMIPolicy,CN=System,$DefaultNamingContext"
    $Parm1 = $Description + ' '
    $Parm2 = "1;3;10;$($Expression.Length);WQL;root\CIMv2;$Expression;"

    $Attributes = @{
        'msWMI-Name'             = $Name
        'msWMI-Parm1'            = $Parm1
        'msWMI-Parm2'            = $Parm2
        'msWMI-ID'               = $GUID
        'instanceType'           = 4
        'showInAdvancedViewOnly' = 'TRUE'
        'distinguishedname'      = $DistinguishedName
        'msWMI-ChangeDate'       = $CreationDate
        'msWMI-CreationDate'     = $CreationDate
    }
    $Path = ("CN=SOM,CN=WMIPolicy,CN=System,$DefaultNamingContext")

    If ($GUID -and $DefaultNamingContext) {
        Write-ToLog -InvocationName $ServiceName -LogData 'Creating new WMI object' -Severity 'INFO'
        Try {
            New-ADObject -Name $GUID -Type 'msWMI-Som' -Path $Path -OtherAttributes $Attributes -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to create new WMI object $_" -Severity 'ERROR'
            Exit 1
        }
    }
}

Function Get-GPWmiFilter {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)][string]$Name
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name
    $Properties = 'msWMI-Name', 'msWMI-Parm1', 'msWMI-Parm2', 'msWMI-ID'
    $ldapFilter = "(&(objectClass=msWMI-Som)(msWMI-Name=$Name))"

    #==================================================
    # Main
    #==================================================
    
    #Write-ToLog -InvocationName $ServiceName -LogData 'Getting WMI object' -Severity 'INFO'
    Try {
        $WmiObject = Get-ADObject -LDAPFilter $ldapFilter -Properties $Properties -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get WMI Object $_" -Severity 'ERROR'
        Exit 1
    }

    If ($WmiObject) { 
        $GpoDomain = New-Object -Type 'Microsoft.GroupPolicy.GPDomain'
        $WmiObject | ForEach-Object {
            $Path = 'MSFT_SomFilter.Domain="' + $GpoDomain.DomainName + '",ID="' + $WmiObject.Name + '"'
            $Filter = $GpoDomain.GetWmiFilter($Path)

            If ($Filter) {
                [Guid]$Guid = $_.Name.Substring(1, $_.Name.Length - 2)
                $Filter | Add-Member -MemberType 'NoteProperty' -Name 'Guid' -Value $Guid -PassThru | Add-Member -MemberType 'NoteProperty' -Name 'Content' -Value $_.'msWMI-Parm2' -PassThru
            }
        }
    }
}

Function Set-GPWmiFilter {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)][string]$Name,
        [Parameter(Mandatory = $False)][string]$Expression,
        [Parameter(Mandatory = $False)][string]$Description
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name

    #==================================================
    # Main
    #==================================================

    $ADObject = Get-GPWmiFilter -Name $Name
    $ChangeDate = (Get-Date).ToUniversalTime().ToString('yyyyMMddhhmmss.ffffff-000')
    $Attributes = @{
        'msWMI-ChangeDate' = $ChangeDate;
    }

    If ($Expression) {
        $Parm2 = "1;3;10;$($Expression.Length);WQL;root\CIMv2;$Expression;"
        $Attributes.Add('msWMI-Parm2', $Parm2);
    }

    If ($Description) {
        $Parm1 = $Description + ' '
        $Attributes.Add('msWMI-Parm1', $Parm1);
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting WMI filter' -Severity 'INFO'
    Try {
        Set-ADObject -Identity $ADObject -Replace $Attributes -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set WMI filter $_" -Severity 'ERROR'
        Exit 1
    }
}

Function Import-WmiFilter {
    [CmdletBinding()]
    Param (
        [String]$FilterName,
        [String]$FilterDescription,
        [String]$FilterExpression
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name

    #==================================================
    # Main
    #==================================================

    Write-ToLog -InvocationName $ServiceName -LogData "Importing WMI filter $FilterName" -Severity 'INFO'
    $WmiExists = Get-GPWmiFilter -Name $FilterName
    If (-Not $WmiExists) {
        New-GPWmiFilter -Name $FilterName -Description $FilterDescription -Expression $FilterExpression -ErrorAction Stop
    } ElseIf ($WmiExists.Content.split(';')[6] -ne $FilterExpression) {
        Set-GPWmiFilter -Name $FilterName -Description $FilterDescription -Expression $FilterExpression
    } Else {
        Write-ToLog -InvocationName $ServiceName -LogData "GPO WMI Filter '$FilterName' already exists. Skipping creation." -Severity 'INFO'
    }
}

Function Import-GroupPolicy {
    Param (
        [String]$BackupGpoName,
        [String]$MigrationTable,
        [String]$WmiFilterName
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name
    $BackUpGpoPath = 'C:\Modules\Module-DC\GPOs\'

    #==================================================
    # Main
    #==================================================

    $Gpo = Get-GPO -Name $BackupGpoName -ErrorAction SilentlyContinue
    If (-Not $Gpo) {
        Write-ToLog -InvocationName $ServiceName -LogData "Creating new GPO $BackupGpoName" -Severity 'INFO'
        Try {
            $Gpo = New-GPO $BackupGpoName -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to create new GPO $BackupGpoName $_" -Severity 'ERROR'
            Exit 1
        }
    } Else {
        Write-ToLog -InvocationName $ServiceName -LogData "GPO '$BackupGpoName' already exists. Skipping creation" -Severity 'INFO'
    }

    If ($WmiFilterName) {
        $WmiFilter = Get-GPWmiFilter -Name $WmiFilterName -ErrorAction SilentlyContinue
        If ($WmiFilter) {
            $Gpo.WmiFilter = $WmiFilter
        } Else {
            Write-ToLog -InvocationName $ServiceName -LogData "WMI Filter '$WmiFilterName' does not exist" -Severity 'WARN'
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData "Importing GPO $BackupGpoName" -Severity 'INFO'
    If ($MigrationTable) {
        Try {
            $Null = Import-GPO -BackupGpoName $BackupGpoName -TargetName $BackupGpoName -Path $BackUpGpoPath -MigrationTable $MigrationTable -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to import GPO $_" -Severity 'ERROR'
            Exit 1
        }
    } Else {
        Try {
            $Null = Import-GPO -BackupGpoName $BackupGpoName -TargetName $BackupGpoName -Path $BackUpGpoPath -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to import GPO $_" -Severity 'ERROR'
            Exit 1
        }
    }
}

Function Set-GroupPolicyLink {
    Param (
        [Parameter(Mandatory = $True)][String]$BackupGpoName,
        [Parameter(Mandatory = $True)][String][ValidateSet('Yes', 'No')]$LinkEnabled,
        [Parameter(Mandatory = $True)][Int32][ValidateRange(0, 10)]$Order,
        [Parameter(Mandatory = $True)][String]$Target
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name
   
    #==================================================
    # Main
    #==================================================

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting domain information' -Severity 'INFO'
    Try {
        $BaseDn = Get-ADDomain -ErrorAction Stop | Select-Object -ExpandProperty 'DistinguishedName'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get domain information $_" -Severity 'ERROR'
        Exit 1
    }

    $GpLinks = Get-ADObject -Filter { DistinguishedName -eq $Target } -Properties 'gplink' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'gplink'

    Write-ToLog -InvocationName $ServiceName -LogData "Getting GPO $BackupGpoName" -Severity 'INFO'
    Try {
        $BackupGpoId = Get-GPO -Name $BackupGpoName -ErrorAction Stop | Select-Object -ExpandProperty 'ID' | Select-Object -ExpandProperty 'Guid'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get GPO $BackupGpoName $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData "Setting GP Link for $BackupGpoName" -Severity 'INFO'
    If ($GpLinks -notlike "*CN={$BackupGpoId},CN=Policies,CN=System,$BaseDn*" -or $Null -eq $GpLinks) {
        Try {
            $Null = New-GPLink -Name $BackupGpoName -Target $Target -Order $Order -ErrorAction Stop 
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to create new GP Link for $BackupGpoName $_" -Severity 'ERROR'
            Exit 1
        }
    } Else {
        Try {
            $Null = Set-GPLink -Name $BackupGpoName -Target $Target -LinkEnabled $LinkEnabled -Order $Order -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to set GP Link $_" -Severity 'ERROR'
            Exit 1
        }
    }
}

Function Update-PolMigTable {

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name
   
    #==================================================
    # Main
    #==================================================

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting domain FQDN' -Severity 'INFO'
    Try {
        $FQDN = Get-ADDomain | Select-Object -ExpandProperty 'Forest'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get FQDN $_" -Severity 'ERROR'
        Exit 1
    }
    $PolMigTablePath = 'C:\Modules\Module-DC\GPOs\PolMigTable.migtable'

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting migration table content' -Severity 'INFO'
    Try {
        [xml]$PolMigTable = Get-Content -Path $PolMigTablePath -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get migration table content $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting migration table content' -Severity 'INFO'
    $PolMigTableContentKerb = $PolMigTable.MigrationTable.Mapping | Where-Object { $_.Source -eq 'Denied RODC Password Replication Group@model.com' }
    $PolMigTableContentKerb.destination = "Denied RODC Password Replication Group@$FQDN"
    $PolMigTableContentDJoin = $PolMigTable.MigrationTable.Mapping | Where-Object { $_.Source -eq 'Group Policy Creator Owners@model.com' }
    $PolMigTableContentDJoin.destination = "Group Policy Creator Owners@$FQDN"
    $PolMigTable.Save($PolMigTablePath)
}

Function Set-ADConnectorAcl {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)][String]$AccountName
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name   
    $PsProvider = 'AD'
    $AclClass = 'AddRule'

    #==================================================
    # Main
    #==================================================

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting RootDSE' -Severity 'INFO'
    Try {
        $RootDse = Get-ADRootDSE -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get Root DSE $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting default computer object container' -Severity 'INFO'
    Try {
        $CompContainerDN = Get-ADDomain -ErrorAction Stop | Select-Object -ExpandProperty 'ComputersContainer'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get default computer object container $_" -Severity 'ERROR'
        Exit 1
    }
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Getting Schema GUIDs' -Severity 'INFO'
    Try {
        [System.GUID]$ServicePrincipalNameGuid = (Get-ADObject -SearchBase $RootDse.SchemaNamingContext -Filter { lDAPDisplayName -eq 'servicePrincipalName' } -Properties 'schemaIDGUID' -ErrorAction Stop).schemaIDGUID
        [System.GUID]$ComputerNameGuid = (Get-ADObject -SearchBase $RootDse.SchemaNamingContext -Filter { lDAPDisplayName -eq 'computer' } -Properties 'schemaIDGUID' -ErrorAction Stop).schemaIDGUID
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get Schema GUIDs $_" -Severity 'ERROR'
        Exit 1
    }

    $AccountDn = (Get-ADUser -Identity $AccountName -ErrorAction Stop).DistinguishedName
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
        Write-ToLog -InvocationName $ServiceName -LogData 'Setting ACL' -Severity 'INFO'
        Try {
            Set-AclOnObject -Name $AccountName -AclClass $AclClass -PsProvider $PsProvider -AclPath $AclRule.Path -AclRule $AclRule.Acl -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to set ACL $_" -Severity 'ERROR'
            Exit 1
        }
    }
}

Function New-AclObject {
    Param (    
        [String]$AclType,   
        [System.Security.Principal.IdentityReference]$IdentityReference,
        [System.Security.AccessControl.FileSystemRights]$FileSystemRights,
        [System.Security.AccessControl.RegistryRights]$RegistryRights,
        [System.DirectoryServices.ActiveDirectoryRights]$ActiveDirectoryRights,
        [System.Security.AccessControl.AuditFlags]$AuditFlags,
        [System.Security.AccessControl.AccessControlType]$AccessControlType,
        [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags,
        [System.Security.AccessControl.PropagationFlags]$PropagationFlags,
        [Guid]$ObjectGuid,        
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]$ActiveDirectorySecurityInheritance,
        [Guid]$InheritedObjectGuid
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name

    Switch ($AclType) {
        'AD' {
            $TypeName = 'System.DirectoryServices.ActiveDirectoryAccessRule'
            $ArgumentList = $IdentityReference, $ActiveDirectoryRights, $AccessControlType, $ObjectGuid, $ActiveDirectorySecurityInheritance, $InheritedObjectGuid
            $ArgumentList = $ArgumentList.Where( { $_ -ne $Null })
        }
        'AdAudit' {
            $TypeName = 'System.DirectoryServices.ActiveDirectoryAuditRule'
            $ArgumentList = $IdentityReference, $ActiveDirectoryRights, $AuditFlags, $ObjectGuid, $ActiveDirectorySecurityInheritance, $InheritedObjectGuid
            $ArgumentList = $ArgumentList.Where( { $_ -ne $Null })
        }
        'File' {
            $Typename = 'System.Security.AccessControl.FileSystemAccessRule'
            $ArgumentList = $IdentityReference, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType
            $ArgumentList = $ArgumentList.Where( { $_ -ne $Null })
        }
        'Registry' {
            $Typename = 'System.Security.AccessControl.RegistryAccessRule'
            $ArgumentList = $IdentityReference, $RegistryRights, $InheritanceFlags, $PropagationFlags, $AccessControlType
            $ArgumentList = $ArgumentList.Where( { $_ -ne $Null })
        }
        Default { 
            Write-ToLog -InvocationName $ServiceName -LogData 'No ACL Class passed' -Severity 'ERROR'
            Exit 1
        }
    }

    #==================================================
    # Main
    #==================================================
    Try {
        New-Object -TypeName $TypeName -ArgumentList $ArgumentList -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to create ACL object $_" -Severity 'ERROR'
        Exit 1
    }
}

Function Set-AclOnObject {
    Param (
        [String]$Name,
        [String]$PsProvider,
        [String]$AclClass,
        [String]$AclPath,
        [HashTable]$AclRule,
        [String]$AccessType,
        [bool]$Protected,
        [bool]$PreserveIn
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name   

    #==================================================
    # Main
    #==================================================

    If ($Name) {
        Switch ($Name) {
            'NT Authority\Authenticated Users' {
                $Sid = 'S-1-5-11'
                $IdentityReference = [Security.Principal.SecurityIdentifier]$Sid
            }
            'Everyone' {
                $Sid = 'S-1-1-0'
                $IdentityReference = [Security.Principal.SecurityIdentifier]$Sid 
            }
            Default { 
                Write-ToLog -InvocationName $ServiceName -LogData 'Getting identity object SID' -Severity 'INFO'
                Try {
                    $IdentityReference = Get-ADObject -Filter { sAMAccountName -eq $Name -and (ObjectClass -eq 'user' -or ObjectClass -eq 'group') } -Property 'ObjectSid' -ErrorAction Stop | Select-Object -ExpandProperty 'ObjectSid'
                } Catch [System.Exception] {
                    Write-ToLog -InvocationName $ServiceName -LogData "Failed to get identity object SID $_" -Severity 'ERROR'
                    Exit 1
                }
            }
        }
    }

    Switch ($PsProvider) {
        'AD' {
            Try {
                $ObjectDetails = Get-ADObject -Identity $AclPath -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to get object $_" -Severity 'ERROR'
                Exit 1
            }
            $Path = "AD:\$ObjectDetails"
        }
        'Registry' {
            $Path = "Registry::$AclPath"
        }
        'File' {
            $Path = $AclPath 
        }
        Default { 
            Write-ToLog -InvocationName $ServiceName -LogData 'No PowerShell provider passed' -Severity 'ERROR'
            Exit 1
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting object ACL and ACL rule' -Severity 'INFO'
    Switch ($AclClass) {
        'AdAudit' { 
            Try {
                $Rule = New-AclObject -AclType $AclClass -IdentityReference $IdentityReference @AclRule -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to get object ACL rule $_" -Severity 'ERROR'
                Exit 1
            }

            Try {
                $ObjectAcl = Get-Acl -Path $Path -Audit -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to get object ACL $_" -Severity 'ERROR'
                Exit 1
            }

            $ObjectAcl.AddAuditRule($Rule) 
        }
        'AddRule' {
            Try {
                $Rule = New-AclObject -AclType $PsProvider -IdentityReference $IdentityReference @AclRule -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to get object ACL rule $_" -Severity 'ERROR'
                Exit 1
            }

            Try {
                $ObjectAcl = Get-Acl -Path $Path -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to get object ACL $_" -Severity 'ERROR'
                Exit 1
            }

            $ObjectAcl.AddAccessRule($Rule) 
        }        
        'RemoveRule' {
            Try {
                $Rule = New-AclObject -AclType $PsProvider -IdentityReference $IdentityReference @AclRule -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to get object ACL rule $_" -Severity 'ERROR'
                Exit 1
            }

            Try {
                $ObjectAcl = Get-Acl -Path $Path -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to get object ACL $_" -Severity 'ERROR'
                Exit 1
            }

            $ObjectAcl.RemoveAccessRule($Rule) 
        }
        'Owner' {
            Try {
                $ObjectAcl = Get-Acl -Path $Path -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to get object ACL $_" -Severity 'ERROR'
                Exit 1
            }

            $ObjectAcl.SetOwner($IdentityReference) 
        }
        'RemoveAccess' {
            Try {
                $ObjectAcl = Get-Acl -Path $Path -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to get object ACL $_" -Severity 'ERROR'
                Exit 1
            }

            $ObjectAcl.RemoveAccess($IdentityReference, $AccessType) 
        }
        'Inheritance' { 
            Try {
                $ObjectAcl = Get-Acl -Path $Path -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to get object ACL $_" -Severity 'ERROR'
                Exit 1
            }
            
            $ObjectAcl.SetAccessRuleProtection($Protected, $PreserveIn) 
        }
        Default { 
            Write-ToLog -InvocationName $ServiceName -LogData 'No ACL Class passed' -Severity 'ERROR'
            Exit 1
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting object ACL' -Severity 'INFO'
    Try {
        Set-Acl -AclObject $ObjectAcl -Path $Path -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to set object ACL $_" -Severity 'ERROR'
        Exit 1
    }
}