Function Invoke-EnterpriseCaConfig {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory = $true)][ValidateSet('AWSManaged', 'SelfManaged')][String]$DirectoryType,
        [Parameter(Mandatory = $true)][String]$EntCaCommonName,
        [Parameter(Mandatory = $true)][ValidateSet('SHA256', 'SHA384', 'SHA512')][String]$EntCaHashAlgorithm,
        [Parameter(Mandatory = $true)][ValidateSet('2048', '4096')][String]$EntCaKeyLength,
        [Parameter(Mandatory = $true)][String]$EntCaValidityPeriodUnits,
        [Parameter(Mandatory = $true)][String]$S3CRLBucketName,
        [Parameter(Mandatory = $true)][ValidateSet('Yes', 'No')][String]$UseS3ForCRL,
        [Parameter(Mandatory = $true)][String]$VPCCIDR
    )
    
    #==================================================
    # Variables
    #==================================================
    
    $ServiceName = $MyInvocation.MyCommand.Name
    $CompName = $env:COMPUTERNAME
    $Folders = @(
        'D:\Pki\Req',
        'D:\ADCS\DB',
        'D:\ADCS\Log'
    )
    $FilePath = 'D:\Pki'
    $Principals = @(
        'ANONYMOUS LOGON',
        'EVERYONE'
    )
    
    #==================================================
    # Main
    #==================================================
    Write-ToLog -InvocationName $ServiceName -LogData 'Installing Windows Features' -Severity 'INFO'
    Try {
        Install-WindowsFeature -Name 'Adcs-Cert-Authority', 'RSAT-AD-Tools', 'RSAT-DNS-Server' -IncludeManagementTools -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to install Windows Features $_" -Severity 'ERROR'
        Exit 1
    }

    If ($UseS3ForCRL -eq 'No') {
        Try {
            Install-WindowsFeature -Name 'Web-WebServer' -IncludeManagementTools -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to install Windows Features $_" -Severity 'ERROR'
            Exit 1
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting AD domain' -Severity 'INFO'
    Try {
        $Domain = Get-ADDomain -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get AD domain $_" -Severity 'ERROR'
        Exit 1
    }
    $BaseDn = $Domain | Select-Object -ExpandProperty 'DistinguishedName'
    $FQDN = $Domain | Select-Object -ExpandProperty 'DNSRoot'
    $Netbios = $Domain | Select-Object -ExpandProperty 'NetBIOSName'
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Getting a domain controller to perform actions against' -Severity 'INFO'
    Try {
        $DC = Get-ADDomainController -Discover -ForceDiscover -ErrorAction Stop | Select-Object -ExpandProperty 'HostName'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get a domain controller $_" -Severity 'ERROR'
        Exit 1
    }
      
    If ($UseS3ForCRL -eq 'No') {
        $Counter = 0
        Do {
            $ARecordPresent = Resolve-DnsName -Name "$CompName.$FQDN" -DnsOnly -Server $DC -ErrorAction SilentlyContinue
            If (-not $ARecordPresent) {
                $Counter ++
                Write-ToLog -InvocationName $ServiceName -LogData 'A record missing, registering it.' -Severity 'INFO'
                Register-DnsClient
                If ($Counter -gt '1') {
                    Start-Sleep -Seconds 10
                }
            }
        } Until ($ARecordPresent -or $Counter -eq 12)
    
        If ($Counter -ge 12) {
            Write-ToLog -InvocationName $ServiceName -LogData 'A record never created' -Severity 'ERROR'
            Exit 1
        }

        If ($DirectoryType -eq 'AWSManaged') {
            Write-Output 'Enabling CredSSP'
            Set-CredSSP -Action 'Enable'
        }

        Write-ToLog -InvocationName $ServiceName -LogData 'Creating PKI CNAME record' -Severity 'INFO'
        $Counter = 0
        Do {
            $CnameRecordPresent = Resolve-DnsName -Name "PKI.$FQDN" -DnsOnly -Server $DC -ErrorAction SilentlyContinue
            If (-not $CnameRecordPresent) {
                $Counter ++
                Write-ToLog -InvocationName $ServiceName -LogData 'CNAME record missing, creating it' -Severity 'INFO'
                $HostNameAlias = "$CompName.$FQDN"
                Switch ($DirectoryType) {
                    'SelfManaged' {
                        Invoke-Command -ComputerName $DC -Credential $Credentials -ScriptBlock { Add-DnsServerResourceRecordCName -Name 'PKI' -HostNameAlias $using:HostNameAlias -ZoneName $using:FQDN }
                    }
                    'AWSManaged' {
                        Invoke-Command -Authentication 'CredSSP' -ComputerName $env:COMPUTERNAME -Credential $Credentials -ScriptBlock { Add-DnsServerResourceRecordCName -Name 'PKI' -ComputerName $using:DC -HostNameAlias $using:HostNameAlias -ZoneName $using:FQDN }
                    }
                }
                If ($Counter -gt '1') {
                    Start-Sleep -Seconds 10
                }
            }
        } Until ($CnameRecordPresent -or $Counter -eq 12)
    
        Write-Output 'Disabling CredSSP'
        Set-CredSSP -Action 'Disable'

        If ($Counter -ge 12) {
            Write-ToLog -InvocationName $ServiceName -LogData 'CNAME record never created' -Severity 'ERROR'
            Exit 1
        }
    }
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Creating PKI folders' -Severity 'INFO'
    Foreach ($Folder in $Folders) {
        $PathPresent = Test-Path -Path $Folder -ErrorAction SilentlyContinue
        If (-not $PathPresent) {
            Try {
                $Null = New-Item -Path $Folder -Type 'Directory' -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to create $Folder directory $_" -Severity 'ERROR'
                Exit 1
            }
        } 
    }
    
    Write-Output 'Example CPS statement' | Out-File 'D:\Pki\cps.txt'
    
    If ($UseS3ForCRL -eq 'No') {
        Write-ToLog -InvocationName $ServiceName -LogData 'Sharing PKI folder' -Severity 'INFO'
        $SharePresent = Get-SmbShare -Name 'Pki' -ErrorAction SilentlyContinue
        If (-not $SharePresent) {
            Try {
                $Null = New-SmbShare -Name 'Pki' -Path 'D:\Pki' -FullAccess 'SYSTEM', "$Netbios\Domain Admins" -ChangeAccess "$Netbios\Cert Publishers" -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to create PKI SMB Share $_" -Severity 'ERROR'
                Exit 1
            }
        }
    
        Write-ToLog -InvocationName $ServiceName -LogData 'Creating PKI IIS virtual directory' -Severity 'INFO'
        $VdPresent = Get-WebVirtualDirectory -Name 'Pki'
        If (-not $VdPresent) {
            Try {
                $Null = New-WebVirtualDirectory -Site 'Default Web Site' -Name 'Pki' -PhysicalPath 'D:\Pki' -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to create PKI IIS virtual directory $_" -Severity 'ERROR'
                Exit 1
            }
        }
    
        Write-ToLog -InvocationName $ServiceName -LogData 'Setting PKI IIS virtual directory requestFiltering' -Severity 'INFO'
        Try {
            Set-WebConfigurationProperty -Filter '/system.webServer/security/requestFiltering' -Name 'allowDoubleEscaping' -Value 'true' -PSPath 'IIS:\Sites\Default Web Site\Pki' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to set PKI IIS virtual directory requestFiltering $_" -Severity 'ERROR'
            Exit 1
        }
    
        Write-ToLog -InvocationName $ServiceName -LogData 'Setting PKI IIS virtual directory directoryBrowse' -Severity 'INFO'
        Try {
            Set-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' -Name 'enabled' -Value 'true' -PSPath 'IIS:\Sites\Default Web Site\Pki' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to set PKI IIS virtual directory directoryBrowse $_" -Severity 'ERROR'
            Exit 1
        }
    
        Write-ToLog -InvocationName $ServiceName -LogData 'Setting PKI folder file system ACLs' -Severity 'INFO'
        Foreach ($Princ in $Principals) {
            $Principal = New-Object -TypeName 'System.Security.Principal.NTAccount'($Princ)
            $Perms = [System.Security.AccessControl.FileSystemRights]'Read, ReadAndExecute, ListDirectory'
            $Inheritance = [System.Security.AccessControl.InheritanceFlags]::'ContainerInherit', 'ObjectInherit'
            $Propagation = [System.Security.AccessControl.PropagationFlags]::'None'
            $Access = [System.Security.AccessControl.AccessControlType]::'Allow'
            $AccessRule = New-Object -TypeName 'System.Security.AccessControl.FileSystemAccessRule'($Principal, $Perms, $Inheritance, $Propagation, $Access) 
            Try {
                $Acl = Get-Acl -Path $FilePath -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to get ACL for PKI directory $_" -Severity 'ERROR'
                Exit 1
            }
            $Acl.AddAccessRule($AccessRule)
            Try {
                Set-Acl -Path $FilePath -AclObject $Acl -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to set ACL for PKI directory $_" -Severity 'ERROR'
                Exit 1
            }
        }
    
        Write-ToLog -InvocationName $ServiceName -LogData 'Resetting IIS service' -Severity 'INFO'
        Try {
            & iisreset.exe > $null
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to reset IIS service $_" -Severity 'ERROR'
            Exit 1
        }
        If ($DirectoryType -eq 'SelfManaged') {
            $URL = "URL=http://pki.$FQDN/pki/cps.txt"
        } Else {
            $URL = "URL=http://$CompName.$FQDN/pki/cps.txt"
        }
    } Else {
        Write-ToLog -InvocationName $ServiceName -LogData 'Getting S3 bucket location' -Severity 'INFO'
        Try {
            $BucketRegion = Get-S3BucketLocation -BucketName $S3CRLBucketName | Select-Object -ExpandProperty 'Value' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to get S3 bucket location $_" -Severity 'ERROR'
            Exit 1
        }  
    
        If ($BucketRegion -eq '') {
            $S3BucketUrl = "$S3CRLBucketName.s3.amazonaws.com"
        } Else {
            $S3BucketUrl = "$S3CRLBucketName.s3-$BucketRegion.amazonaws.com"
        }
        $URL = "URL=http://$S3BucketUrl/$CompName/cps.txt"
        
        Write-ToLog -InvocationName $ServiceName -LogData 'Copying cps.txt to S3 bucket' -Severity 'INFO'
        Try {
            Write-S3Object -BucketName $S3CRLBucketName -Folder 'D:\Pki\' -KeyPrefix "$CompName\" -SearchPattern 'cps.txt' -PublicReadOnly -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to copy cps.txt to S3 bucket $_" -Severity 'ERROR'
            Exit 1
        }
    }
    
    $Inf = @(
        '[Version]',
        'Signature="$Windows NT$"',
        '[PolicyStatementExtension]',
        'Policies=InternalPolicy',
        '[InternalPolicy]',
        'OID=1.2.3.4.1455.67.89.5', 
        'Notice="Legal Policy Statement"',
        $URL
        '[Certsrv_Server]',
        "RenewalKeyLength=$EntCaKeyLength",
        'RenewalValidityPeriod=Years',
        "RenewalValidityPeriodUnits=$EntCaValidityPeriodUnits",
        'CRLPeriod=Weeks',
        'CRLPeriodUnits=1',
        'CRLDeltaPeriod=Days',  
        'CRLDeltaPeriodUnits=0',
        'LoadDefaultTemplates=0',
        'AlternateSignatureAlgorithm=0',
        '[CRLDistributionPoint]',
        '[AuthorityInformationAccess]'
    )
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Creating CAPolicy.inf' -Severity 'INFO'
    Try {
        $Inf | Out-File -FilePath 'C:\Windows\CAPolicy.inf' -Encoding 'ascii'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to create CAPolicy.inf $_" -Severity 'ERROR'
        Exit 1
    }
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Installing Enterprise Root CA' -Severity 'INFO'
    Try {
        $Null = Install-AdcsCertificationAuthority -CAType 'EnterpriseRootCA' -CACommonName $EntCaCommonName -KeyLength $EntCaKeyLength -HashAlgorithm $EntCaHashAlgorithm -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -ValidityPeriod 'Years' -ValidityPeriodUnits $EntCaValidityPeriodUnits -DatabaseDirectory 'D:\ADCS\DB' -LogDirectory 'D:\ADCS\Log' -Force -ErrorAction Stop -Credential $Credentials
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to install Enterprise Root CA $_" -Severity 'ERROR'
        Exit 1
    }
    
    If ($UseS3ForCRL -eq 'No') {
        If ($DirectoryType -eq 'SelfManaged') {
            $CDP = "http://pki.$FQDN/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
            $AIA = "http://pki.$FQDN/pki/<ServerDNSName>_<CaName><CertificateName>.crt"
        } Else {
            $CDP = "http://$CompName.$FQDN/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
            $AIA = "http://$CompName.$FQDN/pki/<ServerDNSName>_<CaName><CertificateName>.crt"
        }
    } Else {
        $CDP = "http://$S3BucketUrl/$CompName/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
        $AIA = "http://$S3BucketUrl/$CompName/<ServerDNSName>_<CaName><CertificateName>.crt"
    }
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Configuring CRL distro points' -Severity 'INFO'
    Try {
        $Null = Get-CACRLDistributionPoint | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } -ErrorAction Stop | Remove-CACRLDistributionPoint -Force -ErrorAction Stop
        $Null = Add-CACRLDistributionPoint -Uri $CDP -AddToCertificateCDP -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to configure CRL Distro $_" -Severity 'ERROR'
        Exit 1
    }
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Configuring AIA distro points' -Severity 'INFO'
    Try {
        $Null = Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } -ErrorAction Stop | Remove-CAAuthorityInformationAccess -Force -ErrorAction Stop
        $Null = Add-CAAuthorityInformationAccess -AddToCertificateAia -Uri $AIA -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to configure AIA Distro $_" -Severity 'ERROR'
        Exit 1
    }
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Configuring Enterprise CA' -Severity 'INFO'
    & certutil.exe -setreg CA\CRLOverlapPeriodUnits '12' > $null
    & certutil.exe -setreg CA\CRLOverlapPeriod 'Hours' > $null
    & certutil.exe -setreg CA\ValidityPeriodUnits '5' > $null
    & certutil.exe -setreg CA\ValidityPeriod 'Years' > $null
    & certutil.exe -setreg CA\AuditFilter '127' > $null
    & auditpol.exe /set /subcategory:'Certification Services' /failure:enable /success:enable > $null
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Restarting CA service' -Severity 'INFO'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to restart CA service $_" -Severity 'ERROR'
        Exit 1
    }
    
    Start-Sleep -Seconds 10
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Publishing CRL' -Severity 'INFO'
    & certutil.exe -crl > $null
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Copying CRL to PKI folder' -Severity 'INFO'
    Try {
        Copy-Item -Path 'C:\Windows\System32\CertSrv\CertEnroll\*.cr*' -Destination 'D:\Pki\' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to copy CRL to PKI folder  $_" -Severity 'ERROR'
        Exit 1
    }
    
    If ($UseS3ForCRL -eq 'Yes') {
        Write-ToLog -InvocationName $ServiceName -LogData 'Copying CRL to S3 bucket' -Severity 'INFO'
        Try {
            Write-S3Object -BucketName $S3CRLBucketName -Folder 'C:\Windows\System32\CertSrv\CertEnroll\' -KeyPrefix "$CompName\" -SearchPattern '*.cr*' -PublicReadOnly -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to copy CRL to S3 bucket $_" -Severity 'ERROR'
            Exit 1
        }
    }
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Restarting CA service' -Severity 'INFO'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to restart CA service $_" -Severity 'ERROR'
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Creating LdapOverSSL certificate template' -Severity 'INFO'
    New-KerbCertTemplate -BaseDn $BaseDn -Credential $Credentials -Server $DC
    
    If ($DirectoryType -eq 'SelfManaged') {
        Write-ToLog -InvocationName $ServiceName -LogData 'Getting domain controllers' -Severity 'INFO'
        Try {
            $DomainControllers = Get-ADComputer -SearchBase "OU=Domain Controllers,$BaseDn" -Filter * | Select-Object -ExpandProperty 'DNSHostName'
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to get domain controllers $_" -Severity 'WARN'
        }
    
        Write-ToLog -InvocationName $ServiceName -LogData 'Running Group Policy update on all domain controllers' -Severity 'INFO'
        Foreach ($DomainController in $DomainControllers) {
            Invoke-Command -ComputerName $DomainController -Credential $Credentials -ScriptBlock { Invoke-GPUpdate -RandomDelayInMinutes '0' -Force }
        }
    }
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Creating Update CRL scheduled task' -Severity 'INFO'
    Try {
        If ($UseS3ForCRL -eq 'No') {
            $ScheduledTaskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '& certutil.exe -crl; Copy-Item -Path C:\Windows\System32\CertSrv\CertEnroll\*.cr* -Destination D:\Pki\'
        } Else {
            $ScheduledTaskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "& certutil.exe -crl; Write-S3Object -BucketName $S3CRLBucketName -Folder C:\Windows\System32\CertSrv\CertEnroll\ -KeyPrefix $CompName\ -SearchPattern *.cr* -PublicReadOnly"
        }
        $ScheduledTaskTrigger = New-ScheduledTaskTrigger -Daily -DaysInterval '5' -At '12am' -ErrorAction Stop
        $ScheduledTaskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType 'ServiceAccount' -RunLevel 'Highest' -ErrorAction Stop
        $ScheduledTaskSettingsSet = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Compatibility 'Win8' -ExecutionTimeLimit (New-TimeSpan -Hours '1') -ErrorAction Stop
        $ScheduledTask = New-ScheduledTask -Action $ScheduledTaskAction -Principal $ScheduledTaskPrincipal -Trigger $ScheduledTaskTrigger -Settings $ScheduledTaskSettingsSet -Description 'Updates CRL to Local Pki Folder' -ErrorAction Stop
        $Null = Register-ScheduledTask 'Update CRL' -InputObject $ScheduledTask -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to register Update CRL scheduled task $_" -Severity 'WARN'
    }
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Running CRL scheduled task' -Severity 'INFO'
    Try {
        Start-ScheduledTask -TaskName 'Update CRL' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to run CRL scheduled task $_" -Severity 'WARN'
    }
    
    Write-ToLog -InvocationName $ServiceName -LogData 'Restarting CA service' -Severity 'INFO'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to restart CA service $_" -Severity 'WARN'
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting Windows Firewall WinRM Public rule to allow VPC CIDR traffic'
    Try {
        Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP-PUBLIC' -RemoteAddress $VPCCIDR -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to allow WinRM traffic from VPC CIDR $_" -Severity 'WARN'
    }
}

Function Invoke-OfflineCaConfig {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory = $true)][ValidateSet('AWSManaged', 'SelfManaged')][String]$DirectoryType,
        [Parameter(Mandatory = $true)][String]$DomainDNSName,
        [Parameter(Mandatory = $true)][String]$OrCaCommonName,
        [Parameter(Mandatory = $true)][ValidateSet('SHA256', 'SHA384', 'SHA512')][String]$OrCaHashAlgorithm,
        [Parameter(Mandatory = $true)][ValidateSet('2048', '4096')][String]$OrCaKeyLength,
        [Parameter(Mandatory = $true)][String]$OrCaValidityPeriodUnits,
        [Parameter(Mandatory = $true)][String]$S3CRLBucketName,
        [Parameter(Mandatory = $true)][String]$SubCaServerNetBIOSName,
        [Parameter(Mandatory = $true)][ValidateSet('Yes', 'No')][String]$UseS3ForCRL,
        [Parameter(Mandatory = $true)][String]$VPCCIDR
    )
    #==================================================
    # Variables
    #==================================================

    $CompName = $env:COMPUTERNAME
    $ServiceName = $MyInvocation.MyCommand.Name
    $Folders = @(
        'D:\Pki\SubCA',
        'D:\ADCS\DB',
        'D:\ADCS\Log'
    )

    #==================================================
    # Main
    #==================================================
    Write-ToLog -InvocationName $ServiceName -LogData 'Installing Windows Features' -Severity 'INFO'
    Try {
        Install-WindowsFeature -Name 'Adcs-Cert-Authority' -IncludeManagementTools
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to install Windows Features $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Creating PKI folders' -Severity 'INFO'
    Foreach ($Folder in $Folders) {
        $PathPresent = Test-Path -Path $Folder
        If (-not $PathPresent) {
            Try {
                $Null = New-Item -Path $Folder -Type 'Directory' -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to create $Folder directory $_" -Severity 'ERROR'
                Exit 1
            }
        } 
    }

    Write-Output 'Example CPS statement' | Out-File 'D:\Pki\cps.txt'

    If ($UseS3ForCRL -eq 'No') {
        If ($DirectoryType -eq 'SelfManaged') {
            $URL = "URL=http://pki.$DomainDNSName/pki/cps.txt"
        } Else {
            $URL = "URL=http://$SubCaServerNetBIOSName.$DomainDNSName/pki/cps.txt"
        }
    } Else {
        Write-ToLog -InvocationName $ServiceName -LogData 'Getting S3 bucket location' -Severity 'INFO'
        Try {
            $BucketRegion = Get-S3BucketLocation -BucketName $S3CRLBucketName | Select-Object -ExpandProperty 'Value' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to get S3 bucket location $_" -Severity 'ERROR'
            Exit 1
        }

        If ($BucketRegion -eq '') {
            $S3BucketUrl = "$S3CRLBucketName.s3.amazonaws.com"
        } Else {
            $S3BucketUrl = "$S3CRLBucketName.s3-$BucketRegion.amazonaws.com"
        }
        $URL = "URL=http://$S3BucketUrl/$CompName/cps.txt"

        Write-ToLog -InvocationName $ServiceName -LogData 'Copying cps.txt to S3 bucket' -Severity 'INFO'
        Try {
            Write-S3Object -BucketName $S3CRLBucketName -Folder 'D:\Pki\' -KeyPrefix "$CompName\" -SearchPattern 'cps.txt' -PublicReadOnly -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to copy cps.txt to S3 bucket $_" -Severity 'ERROR'
            Exit 1
        }
    }

    $Inf = @(
        '[Version]',
        'Signature="$Windows NT$"',
        '[PolicyStatementExtension]',
        'Policies=InternalPolicy',
        '[InternalPolicy]',
        'OID=1.2.3.4.1455.67.89.5', 
        'Notice="Legal Policy Statement"',
        $URL
        '[Certsrv_Server]',
        "RenewalKeyLength=$OrCaKeyLength",
        'RenewalValidityPeriod=Years',
        "RenewalValidityPeriodUnits=$OrCaValidityPeriodUnits",
        'CRLPeriod=Weeks',
        'CRLPeriodUnits=26',
        'CRLDeltaPeriod=Days',  
        'CRLDeltaPeriodUnits=0',
        'LoadDefaultTemplates=0',
        'AlternateSignatureAlgorithm=0',
        '[CRLDistributionPoint]',
        '[AuthorityInformationAccess]'
    )

    Write-ToLog -InvocationName $ServiceName -LogData 'Creating CAPolicy.inf' -Severity 'INFO'
    Try {
        $Inf | Out-File -FilePath 'C:\Windows\CAPolicy.inf' -Encoding 'ascii'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to create CAPolicy.inf $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Installing Offline Root CA' -Severity 'INFO'
    Try {
        $Null = Install-AdcsCertificationAuthority -CAType 'StandaloneRootCA' -CACommonName $OrCaCommonName -KeyLength $OrCaKeyLength -HashAlgorithm $OrCaHashAlgorithm -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -ValidityPeriod 'Years' -ValidityPeriodUnits $OrCaValidityPeriodUnits -DatabaseDirectory 'D:\ADCS\DB' -LogDirectory 'D:\ADCS\Log' -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to install Offline Root CA $_" -Severity 'ERROR'
        Exit 1
    }

    If ($UseS3ForCRL -eq 'No') {
        If ($DirectoryType -eq 'SelfManaged') {
            $CDP = "http://pki.$DomainDNSName/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
            $AIA = "http://pki.$DomainDNSName/pki/<ServerDNSName>_<CaName><CertificateName>.crt"
        } Else {
            $CDP = "http://$SubCaServerNetBIOSName.$DomainDNSName/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
            $AIA = "http://$SubCaServerNetBIOSName.$DomainDNSName/pki/<ServerDNSName>_<CaName><CertificateName>.crt"
        }
    } Else {
        $CDP = "http://$S3BucketUrl/$CompName/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
        $AIA = "http://$S3BucketUrl/$CompName/<ServerDNSName>_<CaName><CertificateName>.crt"
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Configuring CRL distro points' -Severity 'INFO'
    Try {
        $Null = Get-CACRLDistributionPoint | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } -ErrorAction Stop | Remove-CACRLDistributionPoint -Force -ErrorAction Stop
        $Null = Add-CACRLDistributionPoint -Uri $CDP -AddToCertificateCDP -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to configure CRL Distro $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Configuring AIA distro points' -Severity 'INFO'
    Try {
        $Null = Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } -ErrorAction Stop | Remove-CAAuthorityInformationAccess -Force -ErrorAction Stop
        $Null = Add-CAAuthorityInformationAccess -AddToCertificateAia -Uri $AIA -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to configure AIA Distro $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Configuring Offline Root CA' -Severity 'INFO'
    & certutil.exe -setreg CA\CRLOverlapPeriodUnits '12' > $null
    & certutil.exe -setreg CA\CRLOverlapPeriod 'Hours' > $null
    & certutil.exe -setreg CA\ValidityPeriodUnits '5' > $null
    & certutil.exe -setreg CA\ValidityPeriod 'Years' > $null
    & certutil.exe -setreg CA\AuditFilter '127' > $null
    & auditpol.exe /set /subcategory:'Certification Services' /failure:enable /success:enable > $null

    Write-ToLog -InvocationName $ServiceName -LogData 'Restarting CA service' -Severity 'INFO'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to restart CA service $_" -Severity 'ERROR'
        Exit 1
    }

    Start-Sleep -Seconds 10

    Write-ToLog -InvocationName $ServiceName -LogData 'Publishing CRL' -Severity 'INFO'
    & certutil.exe -crl > $null

    Write-ToLog -InvocationName $ServiceName -LogData 'Copying CRL to PKI folder' -Severity 'INFO'
    Try {
        Copy-Item -Path 'C:\Windows\System32\CertSrv\CertEnroll\*.cr*' -Destination 'D:\Pki\' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to copy CRL to PKI folder $_" -Severity 'ERROR'
        Exit 1
    }

    If ($UseS3ForCRL -eq 'Yes') {
        Write-ToLog -InvocationName $ServiceName -LogData 'Copying CRL to S3 bucket' -Severity 'INFO'
        Try {
            Write-S3Object -BucketName $S3CRLBucketName -Folder 'C:\Windows\System32\CertSrv\CertEnroll\' -KeyPrefix "$CompName\" -SearchPattern '*.cr*' -PublicReadOnly -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to copy CRL to S3 bucket $_" -Severity 'ERROR'
            Exit 1
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Restarting CA service' -Severity 'INFO'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to restart CA service $_" -Severity 'WARN'
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Creating Update CRL scheduled task'
    Try {
        If ($UseS3ForCRL -eq 'No') {
            $ScheduledTaskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '& certutil.exe -crl; Copy-Item -Path C:\Windows\System32\CertSrv\CertEnroll\*.cr* -Destination D:\Pki\'
        } Else {
            $ScheduledTaskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "& certutil.exe -crl; Write-S3Object -BucketName $S3CRLBucketName -Folder C:\Windows\System32\CertSrv\CertEnroll\ -KeyPrefix $CompName\ -SearchPattern *.cr* -PublicReadOnly"
        }
        $ScheduledTaskTrigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval '25' -DaysOfWeek 'Sunday' -At '12am' -ErrorAction Stop
        $ScheduledTaskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType 'ServiceAccount' -RunLevel 'Highest' -ErrorAction Stop
        $ScheduledTaskSettingsSet = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Compatibility 'Win8' -ExecutionTimeLimit (New-TimeSpan -Hours '1') -ErrorAction Stop
        $ScheduledTask = New-ScheduledTask -Action $ScheduledTaskAction -Principal $ScheduledTaskPrincipal -Trigger $ScheduledTaskTrigger -Settings $ScheduledTaskSettingsSet -Description 'Updates CRL to Local Pki Folder' -ErrorAction Stop
        $Null = Register-ScheduledTask 'Update CRL' -InputObject $ScheduledTask -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to register Update CRL scheduled task $_" -Severity 'WARN'
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Running CRL scheduled task' -Severity 'INFO'
    Try {
        Start-ScheduledTask -TaskName 'Update CRL' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to run CRL scheduled task $_" -Severity 'WARN'
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Restarting CA service' -Severity 'INFO'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to restart CA service $_" -Severity 'WARN'
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Creating PkiSysvolPSDrive' -Severity 'INFO'
    If ($DirectoryType -eq 'SelfManaged') {
        $SysvolPath = "\\$DomainDNSName\SYSVOL\$DomainDNSName"
    } Else {
        $SysvolPath = "\\$DomainDNSName\SYSVOL\$DomainDNSName\Policies"
    }

    Try {
        $Null = New-PSDrive -Name 'PkiSysvolPSDrive' -PSProvider 'FileSystem' -Root $SysvolPath -Credential $Credentials -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to create PkiSysvolPSDrive $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Creating the PkiRootCA SYSVOL folder' -Severity 'INFO'
    Try {
        $Null = New-Item -ItemType 'Directory' -Path 'PkiSysvolPSDrive:\PkiRootCA' -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to create PkiRootCA SYSVOL folder $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Copying CertEnroll contents to SYSVOL PkiRootCA folder' -Severity 'INFO'
    Try {
        Copy-Item -Path 'C:\Windows\System32\CertSrv\CertEnroll\*.cr*' -Destination 'PkiSysvolPSDrive:\PkiRootCA' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to copy CertEnroll contents to SYSVOL PkiRootCA folder $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting Windows Firewall WinRM Public rule to allow VPC CIDR traffic' -Severity 'INFO'
    Try {
        Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP-PUBLIC' -RemoteAddress $VPCCIDR -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to allow WinRM traffic from VPC CIDR $_" -Severity 'WARN'
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Removing PkiSysvolPSDrive' -Severity 'INFO'
    Try {
        Remove-PSDrive -Name 'PkiSysvolPSDrive' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to remove PkiSysvolPSDrive $_" -Severity 'ERROR'
        Exit 1
    }
}

Function Invoke-SubCaPreConfig {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory = $true)][ValidateSet('AWSManaged', 'SelfManaged')][String]$DirectoryType,
        [Parameter(Mandatory = $true)][String]$S3CRLBucketName,
        [Parameter(Mandatory = $true)][String]$SubCaCommonName,
        [Parameter(Mandatory = $true)][ValidateSet('SHA256', 'SHA384', 'SHA512')][String]$SubCaHashAlgorithm,
        [Parameter(Mandatory = $true)][ValidateSet('2048', '4096')][String]$SubCaKeyLength,
        [Parameter(Mandatory = $true)][String]$SubCaValidityPeriodUnits,
        [Parameter(Mandatory = $true)][ValidateSet('Yes', 'No')][String]$UseS3ForCRL
    )

    #==================================================
    # Variables
    #==================================================

    $CompName = $env:COMPUTERNAME
    $ServiceName = $MyInvocation.MyCommand.Name


    $Folders = @(
        'D:\Pki\Req',
        'D:\ADCS\DB',
        'D:\ADCS\Log'
    )
    $FilePath = 'D:\Pki'
    $Principals = @(
        'ANONYMOUS LOGON',
        'EVERYONE'
    )

    #==================================================
    # Main
    #==================================================

    Write-ToLog -InvocationName $ServiceName -LogData 'Installing Windows Features' -Severity 'INFO'
    Try {
        Install-WindowsFeature -Name 'Adcs-Cert-Authority', 'RSAT-AD-Tools', 'RSAT-DNS-Server' -IncludeManagementTools -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to install Windows Features $_" -Severity 'ERROR'
        Exit 1
    }

    If ($UseS3ForCRL -eq 'No') {
        Try {
            Install-WindowsFeature -Name 'Web-WebServer' -IncludeManagementTools -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to install Windows Features $_" -Severity 'ERROR'
            Exit 1
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting AD domain information' -Severity 'INFO'
    Try {
        $Domain = Get-ADDomain -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get AD domain information $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting a domain controller to perform actions against' -Severity 'INFO'
    Try {
        $DC = Get-ADDomainController -Discover -ForceDiscover -ErrorAction Stop | Select-Object -ExpandProperty 'HostName'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get a domain controller $_" -Severity 'ERROR'
        Exit 1
    }

    $FQDN = $Domain | Select-Object -ExpandProperty 'DNSRoot'
    $Netbios = $Domain | Select-Object -ExpandProperty 'NetBIOSName'

    Write-ToLog -InvocationName $ServiceName -LogData 'Adding computer account to elevated permission group for install' -Severity 'INFO'
    If ($DirectoryType -eq 'SelfManaged') {
        Try {
            Add-ADGroupMember -Identity 'Enterprise Admins' -Members (Get-ADComputer -Identity $CompName -Credential $Credentials -ErrorAction Stop | Select-Object -ExpandProperty 'DistinguishedName') -Credential $Credentials -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to add computer account to Enteprise Admins $_" -Severity 'ERROR'
            Exit 1
        }
    } Else {
        Try {
            Add-ADGroupMember -Identity 'AWS Delegated Enterprise Certificate Authority Administrators' -Members (Get-ADComputer -Identity $CompName -Credential $Credentials -ErrorAction Stop | Select-Object -ExpandProperty 'DistinguishedName') -Credential $Credentials -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to add computer account to AWS Delegated Enterprise Certificate Authority Administrators $_" -Severity 'ERROR'
            Exit 1
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Sleeping to ensure replication of group membership has completed' -Severity 'INFO'
    Start-Sleep -Seconds 60 

    Write-ToLog -InvocationName $ServiceName -LogData 'Clearing all SYSTEM kerberos tickets' -Severity 'INFO'
    & Klist.exe -li 0x3e7 purge > $null
    Start-Sleep -Seconds 5

    If ($UseS3ForCRL -eq 'No') {
        $Counter = 0
        Do {
            $ARecordPresent = Resolve-DnsName -Name "$CompName.$FQDN" -DnsOnly -Server $DC -ErrorAction SilentlyContinue
            If (-not $ARecordPresent) {
                $Counter ++
                Write-ToLog -InvocationName $ServiceName -LogData 'A record missing, registering it.' -Severity 'INFO'
                Register-DnsClient
                If ($Counter -gt '1') {
                    Start-Sleep -Seconds 10
                }
            }
        } Until ($ARecordPresent -or $Counter -eq 12)

        If ($Counter -ge 12) {
            Write-ToLog -InvocationName $ServiceName -LogData 'A record never created' -Severity 'ERROR'
            Exit 1
        }

        If ($DirectoryType -eq 'AWSManaged') {
            Write-Output 'Enabling CredSSP'
            Set-CredSSP -Action 'Enable'
        }

        Write-ToLog -InvocationName $ServiceName -LogData 'Creating PKI CNAME record' -Severity 'INFO'
        $Counter = 0
        Do {
            $CnameRecordPresent = Resolve-DnsName -Name "PKI.$FQDN" -DnsOnly -Server $DC -ErrorAction SilentlyContinue
            If (-not $CnameRecordPresent) {
                $Counter ++
                Write-ToLog -InvocationName $ServiceName -LogData 'PKI CNAME record missing, creating it' -Severity 'INFO'
                $HostNameAlias = "$CompName.$FQDN"
                Switch ($DirectoryType) {
                    'SelfManaged' {
                        Invoke-Command -ComputerName $DC -Credential $Credentials -ScriptBlock { Add-DnsServerResourceRecordCName -Name 'PKI' -HostNameAlias $using:HostNameAlias -ZoneName $using:FQDN }
                    }
                    'AWSManaged' {
                        Invoke-Command -Authentication 'CredSSP' -ComputerName $env:COMPUTERNAME -Credential $Credentials -ScriptBlock { Add-DnsServerResourceRecordCName -Name 'PKI' -ComputerName $using:DC -HostNameAlias $using:HostNameAlias -ZoneName $using:FQDN }
                    }
                }
                If ($Counter -gt '1') {
                    Start-Sleep -Seconds 10
                }
            }
        } Until ($CnameRecordPresent -or $Counter -eq 12)

        Write-Output 'Disabling CredSSP'
        Set-CredSSP -Action 'Disable'

        If ($Counter -ge 12) {
            Write-ToLog -InvocationName $ServiceName -LogData 'PKI CNAME record never created' -Severity 'ERROR'
            Exit 1
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Creating PKI folders' -Severity 'INFO'
    Foreach ($Folder in $Folders) {
        $PathPresent = Test-Path -Path $Folder -ErrorAction SilentlyContinue
        If (-not $PathPresent) {
            Try {
                $Null = New-Item -Path $Folder -Type 'Directory' -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to create $Folder directory $_" -Severity 'ERROR'
                Exit 1
            }
        } 
    }

    Write-Output 'Example CPS statement' | Out-File 'D:\Pki\cps.txt'

    If ($UseS3ForCRL -eq 'No') {
        Write-ToLog -InvocationName $ServiceName -LogData 'Sharing PKI folder' -Severity 'INFO'
        $SharePresent = Get-SmbShare -Name 'Pki' -ErrorAction SilentlyContinue
        If (-not $SharePresent) {
            Try {
                $Null = New-SmbShare -Name 'Pki' -Path 'D:\Pki' -FullAccess 'SYSTEM', "$Netbios\Domain Admins" -ChangeAccess "$Netbios\Cert Publishers" -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to create PKI SMB Share $_" -Severity 'ERROR'
                Exit 1
            }
        }

        Write-ToLog -InvocationName $ServiceName -LogData 'Creating PKI IIS virtual directory' -Severity 'INFO'
        $VdPresent = Get-WebVirtualDirectory -Name 'Pki'
        If (-not $VdPresent) {
            Try {
                $Null = New-WebVirtualDirectory -Site 'Default Web Site' -Name 'Pki' -PhysicalPath 'D:\Pki' -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to create PKI IIS virtual directory $_" -Severity 'ERROR'
                Exit 1
            }
        }

        Write-ToLog -InvocationName $ServiceName -LogData 'Setting PKI IIS virtual directory requestFiltering' -Severity 'INFO'
        Try {
            $Null = Set-WebConfigurationProperty -Filter '/system.webServer/security/requestFiltering' -Name 'allowDoubleEscaping' -Value 'true' -PSPath 'IIS:\Sites\Default Web Site\Pki' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to set PKI IIS virtual directory requestFiltering $_" -Severity 'ERROR'
            Exit 1
        }

        Write-ToLog -InvocationName $ServiceName -LogData 'Setting PKI IIS virtual directory directoryBrowse' -Severity 'INFO'
        Try {
            $Null = Set-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' -Name 'enabled' -Value 'true' -PSPath 'IIS:\Sites\Default Web Site\Pki' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to set PKI IIS virtual directory directoryBrowse $_" -Severity 'ERROR'
            Exit 1
        }
        Write-ToLog -InvocationName $ServiceName -LogData 'Setting PKI folder file system ACLs' -Severity 'INFO'
        Foreach ($Princ in $Principals) {
            $Principal = New-Object -TypeName 'System.Security.Principal.NTAccount'($Princ)
            $Perms = [System.Security.AccessControl.FileSystemRights]'Read, ReadAndExecute, ListDirectory'
            $Inheritance = [System.Security.AccessControl.InheritanceFlags]::'ContainerInherit', 'ObjectInherit'
            $Propagation = [System.Security.AccessControl.PropagationFlags]::'None'
            $Access = [System.Security.AccessControl.AccessControlType]::'Allow'
            $AccessRule = New-Object -TypeName 'System.Security.AccessControl.FileSystemAccessRule'($Principal, $Perms, $Inheritance, $Propagation, $Access) 
            Try {
                $Acl = Get-Acl -Path $FilePath -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to get ACL for PKI directory $_" -Severity 'ERROR'
                Exit 1
            }
            $Acl.AddAccessRule($AccessRule)
            Try {
                Set-Acl -Path $FilePath -AclObject $Acl -ErrorAction Stop
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to set ACL for PKI directory $_" -Severity 'ERROR'
                Exit 1
            }
        }

        Write-ToLog -InvocationName $ServiceName -LogData 'Resetting IIS' -Severity 'INFO'
        Try {
            & iisreset.exe > $null
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to reset IIS service $_" -Severity 'ERROR'
            Exit 1
        }

        If ($DirectoryType -eq 'SelfManaged') {
            $URL = "URL=http://pki.$FQDN/pki/cps.txt"
        } Else {
            $URL = "URL=http://$CompName.$FQDN/pki/cps.txt"
        }
    } Else {
        Write-ToLog -InvocationName $ServiceName -LogData 'Getting S3 bucket location' -Severity 'INFO'
        Try {
            $BucketRegion = Get-S3BucketLocation -BucketName $S3CRLBucketName | Select-Object -ExpandProperty 'Value' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to get S3 bucket location $_" -Severity 'ERROR'
            Exit 1
        }

        If ($BucketRegion -eq '') {
            $S3BucketUrl = "$S3CRLBucketName.s3.amazonaws.com"
        } Else {
            $S3BucketUrl = "$S3CRLBucketName.s3-$BucketRegion.amazonaws.com"
        }
        $URL = "URL=http://$S3BucketUrl/SubCa/cps.txt"

        Write-ToLog -InvocationName $ServiceName -LogData 'Copying cps.txt to S3 bucket' -Severity 'INFO'
        Try {
            Write-S3Object -BucketName $S3CRLBucketName -Folder 'D:\Pki\' -KeyPrefix "$CompName\" -SearchPattern 'cps.txt' -PublicReadOnly -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to copy cps.txt to S3 bucket $_" -Severity 'ERROR'
            Exit 1
        }
    }

    $Inf = @(
        '[Version]',
        'Signature="$Windows NT$"',
        '[PolicyStatementExtension]',
        'Policies=InternalPolicy',
        '[InternalPolicy]',
        'OID=1.2.3.4.1455.67.89.5', 
        'Notice="Legal Policy Statement"',
        $URL
        '[Certsrv_Server]',
        "RenewalKeyLength=$SubCaKeyLength",
        'RenewalValidityPeriod=Years',
        "RenewalValidityPeriodUnits=$SubCaValidityPeriodUnits",
        'CRLPeriod=Weeks',
        'CRLPeriodUnits=1',
        'CRLDeltaPeriod=Days',  
        'CRLDeltaPeriodUnits=0',
        'LoadDefaultTemplates=0',
        'AlternateSignatureAlgorithm=0',
        '[CRLDistributionPoint]',
        '[AuthorityInformationAccess]'
    )

    Write-ToLog -InvocationName $ServiceName -LogData 'Creating CAPolicy.inf' -Severity 'INFO'
    Try {
        $Inf | Out-File -FilePath 'C:\Windows\CAPolicy.inf' -Encoding 'ascii'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to create CAPolicy.inf $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Creating SubPkiSysvolPSDrive' -Severity 'INFO'
    If ($DirectoryType -eq 'SelfManaged') {
        $SysvolPath = "\\$FQDN\SYSVOL\$FQDN"
    } Else {
        $SysvolPath = "\\$FQDN\SYSVOL\$FQDN\Policies"
    }

    Try {
        $Null = New-PSDrive -Name 'SubPkiSysvolPSDrive' -PSProvider 'FileSystem' -Root $SysvolPath -Credential $Credentials -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to create SubPkiSysvolPSDrive $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Creating the PkiSubCA SYSVOL folder' -Severity 'INFO'
    Try {
        $Null = New-Item -ItemType 'Directory' -Path 'SubPkiSysvolPSDrive:\PkiSubCA' -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to create PkiSubCA SYSVOL folder $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Copying the SYSVOL PkiRootCA contents to local folder' -Severity 'INFO'
    Try {
        Copy-Item -Path 'SubPkiSysvolPSDrive:\PkiRootCA\*.cr*' -Destination 'D:\Pki' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to copy PkiRootCA SYSVOL folder contents $_" -Severity 'ERROR'
        Exit 1
    }

    $OrcaCert = Get-ChildItem -Path 'D:\Pki\*.crt' -ErrorAction Stop
    $OrcaCertFn = $OrcaCert | Select-Object -ExpandProperty 'FullName'
    $OrcaCrlFn = Get-ChildItem -Path 'D:\Pki\*.crl' | Select-Object -ExpandProperty 'FullName'

    Write-ToLog -InvocationName $ServiceName -LogData 'Publishing Offline CA certificate and CRLs' -Severity 'INFO'
    & certutil.exe -dspublish -f $OrcaCertFn RootCA > $null
    & certutil.exe -addstore -f root $OrcaCertFn > $null
    & certutil.exe -addstore -f root $OrcaCrlFn > $null

    Write-ToLog -InvocationName $ServiceName -LogData 'Installing Subordinate CA' -Severity 'INFO'
    Try {
        Install-AdcsCertificationAuthority -CAType 'EnterpriseSubordinateCA' -CACommonName $SubCaCommonName -KeyLength $SubCaKeyLength -HashAlgorithm $SubCaHashAlgorithm -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -OutputCertRequestFile 'D:\Pki\Req\SubCa.req' -DatabaseDirectory 'D:\ADCS\DB' -LogDirectory 'D:\ADCS\Log' -Force -WarningAction SilentlyContinue -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to create install Subordinate CA $_" -Severity 'WARN'
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Copying SubCa.req to PkiSubCA SYSVOL folder' -Severity 'INFO'
    Try {
        Copy-Item -Path 'D:\Pki\Req\SubCa.req' -Destination 'SubPkiSysvolPSDrive:\PkiSubCA\SubCa.req'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to copy SubCa.req to PkiSubCA SYSVOL folder $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Removing SubPkiSysvolPSDrive' -Severity 'INFO'
    Try {
        Remove-PSDrive -Name 'SubPkiSysvolPSDrive' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to remove SubPkiSysvolPSDrive $_" -Severity 'ERROR'
        Exit 1
    }
}

Function Invoke-TwoTierSubCaCertIssue {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory = $true)][ValidateSet('AWSManaged', 'SelfManaged')][String]$DirectoryType,
        [Parameter(Mandatory = $true)][String]$DomainDNSName
    )

    #==================================================
    # Variables
    #==================================================

    $CAComputerName = "$env:COMPUTERNAME\$env:COMPUTERNAME"
    $ServiceName = $MyInvocation.MyCommand.Name

    #==================================================
    # Main
    #==================================================

    Write-ToLog -InvocationName $ServiceName -LogData 'Creating IssuePkiSysvolPSDrive' -Severity 'INFO'
    If ($DirectoryType -eq 'SelfManaged') {
        $SysvolPath = "\\$DomainDNSName\SYSVOL\$DomainDNSName"
    } Else {
        $SysvolPath = "\\$DomainDNSName\SYSVOL\$DomainDNSName\Policies"
    }

    Try {
        $Null = New-PSDrive -Name 'IssuePkiSysvolPSDrive' -PSProvider 'FileSystem' -Root $SysvolPath -Credential $Credentials -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to create IssuePkiSysvolPSDrive $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Copying SubCa.req from PkiSubCA SYSVOL folder' -Severity 'INFO'
    Try {
        Copy-Item -Path 'IssuePkiSysvolPSDrive:\PkiSubCA\SubCa.req' -Destination 'D:\Pki\SubCA\SubCa.req' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to copy SubCa.req from PkiSubCA SYSVOL folder $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Submitting, Issuing and Retrieving the SubCA certificate' -Severity 'INFO'
    $SubReq = 'D:\Pki\SubCA\SubCa.req'
    $Request = & Certreq.exe -f -q -config $CAComputerName -Submit $SubReq 'D:\Pki\SubCA\SubCa.cer'
    $RequestString = $Request | Select-String -Pattern 'RequestIC:.\d$'
    $RequestId = $RequestString -replace ('RequestIC: ', '')
    & Certutil.exe -config $CAComputerName -Resubmit $RequestId > $null
    & Certreq.exe -f -q -config $CAComputerName -Retrieve $RequestId 'D:\Pki\SubCA\SubCa.cer' > $null

    Write-ToLog -InvocationName $ServiceName -LogData 'Copying SubCa.cer to PkiSubCA SYSVOL folder' -Severity 'INFO'
    Try {
        Copy-Item -Path 'D:\Pki\SubCA\SubCa.cer' -Destination 'IssuePkiSysvolPSDrive:\PkiSubCA\SubCa.cer' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to copy SubCa.req from PkiSubCA SYSVOL folder $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Removing IssuePkiSysvolPSDrive' -Severity 'INFO'
    Try {
        Remove-PSDrive -Name 'IssuePkiSysvolPSDrive' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to remove IssuePkiSysvolPSDrive $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Removing SubCA Cert request files' -Severity 'INFO'
    Try {
        Remove-Item -Path 'D:\Pki\SubCA' -Recurse -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to remove SubCA Cert request files $_" -Severity 'ERROR'
    }

}

Function Invoke-SubCaConfig {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credentials,
        [Parameter(Mandatory = $true)][ValidateSet('AWSManaged', 'SelfManaged')][String]$DirectoryType,
        [Parameter(Mandatory = $true)][String]$S3CRLBucketName,
        [Parameter(Mandatory = $true)][ValidateSet('Yes', 'No')][String]$UseS3ForCRL,
        [Parameter(Mandatory = $true)][String]$VPCCIDR
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting AD domain' -Severity 'INFO'
    Try {
        $Domain = Get-ADDomain -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get AD domain $_" -Severity 'ERROR'
        Exit 1
    }

    $FQDN = $Domain | Select-Object -ExpandProperty 'DNSRoot'
    $BaseDn = $Domain | Select-Object -ExpandProperty 'DistinguishedName'
    $CompName = $env:COMPUTERNAME
    $SvolFolders = @(
        'CertPkiSysvolPSDrive:\PkiSubCA',
        'CertPkiSysvolPSDrive:\PkiRootCA'
    )

    #==================================================
    # Main
    #==================================================

    Write-ToLog -InvocationName $ServiceName -LogData 'Getting a domain controller to perform actions against' -Severity 'INFO'
    Try {
        $DC = Get-ADDomainController -Discover -ForceDiscover -ErrorAction Stop | Select-Object -ExpandProperty 'HostName'
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to get a domain controller $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Creating CertPkiSysvolPSDrive' -Severity 'INFO'
    If ($DirectoryType -eq 'SelfManaged') {
        $SysvolPath = "\\$FQDN\SYSVOL\$FQDN"
    } Else {
        $SysvolPath = "\\$FQDN\SYSVOL\$FQDN\Policies"
    }

    Try {
        $Null = New-PSDrive -Name 'CertPkiSysvolPSDrive' -PSProvider 'FileSystem' -Root $SysvolPath -Credential $Credentials -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to create CertPkiSysvolPSDrive $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Copying SubCa.cer from PkiSubCA SYSVOL folder' -Severity 'INFO'
    Try {
        Copy-Item -Path 'CertPkiSysvolPSDrive:\PkiSubCA\SubCa.cer' -Destination 'D:\Pki\Req\SubCa.cer' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to copy SubCa.cer from PkiSubCA SYSVOL folder $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Installing SubCA certificate' -Severity 'INFO'
    & certutil.exe -f -silent -installcert 'D:\Pki\Req\SubCa.cer' > $null

    Start-Sleep -Seconds 5

    Write-ToLog -InvocationName $ServiceName -LogData 'Starting CA service' -Severity 'INFO'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to restart CA service $_" -Severity 'ERROR'
        Exit 1
    }

    If ($UseS3ForCRL -eq 'Yes') {
        Write-ToLog -InvocationName $ServiceName -LogData 'Getting S3 bucket location' -Severity 'INFO'
        Try {
            $BucketRegion = Get-S3BucketLocation -BucketName $S3CRLBucketName | Select-Object -ExpandProperty 'Value' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to get S3 bucket location $_" -Severity 'ERROR'
            Exit 1
        }

        If ($BucketRegion -eq '') {
            $S3BucketUrl = "$S3CRLBucketName.s3.amazonaws.com"
        } Else {
            $S3BucketUrl = "$S3CRLBucketName.s3-$BucketRegion.amazonaws.com"
        }

        $CDP = "http://$S3BucketUrl/$CompName/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
        $AIA = "http://$S3BucketUrl/$CompName/<ServerDNSName>_<CaName><CertificateName>.crt"
    } Else {
        If ($DirectoryType -eq 'SelfManaged') {
            $CDP = "http://pki.$FQDN/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
            $AIA = "http://pki.$FQDN/pki/<ServerDNSName>_<CaName><CertificateName>.crt"
        } Else {
            $CDP = "http://$CompName.$FQDN/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
            $AIA = "http://$CompName.$FQDN/pki/<ServerDNSName>_<CaName><CertificateName>.crt"
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Configuring CRL distro points' -Severity 'INFO'
    Try {
        $Null = Get-CACRLDistributionPoint | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } -ErrorAction Stop | Remove-CACRLDistributionPoint -Force -ErrorAction Stop
        $Null = Add-CACRLDistributionPoint -Uri $CDP -AddToCertificateCDP -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to configure CRL Distro $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Configuring AIA distro points' -Severity 'INFO'
    Try {
        $Null = Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } -ErrorAction Stop | Remove-CAAuthorityInformationAccess -Force -ErrorAction Stop
        $Null = Add-CAAuthorityInformationAccess -AddToCertificateAia -Uri $AIA -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to configure AIA Distro $_" -Severity 'ERROR'
        Exit 1
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Configuring Enterprise CA' -Severity 'INFO'
    & certutil.exe -setreg CA\CRLOverlapPeriodUnits '12' > $null
    & certutil.exe -setreg CA\CRLOverlapPeriod 'Hours' > $null
    & certutil.exe -setreg CA\ValidityPeriodUnits '5' > $null
    & certutil.exe -setreg CA\ValidityPeriod 'Years' > $null
    & certutil.exe -setreg CA\AuditFilter '127' > $null
    & auditpol.exe /set /subcategory:'Certification Services' /failure:enable /success:enable > $null

    Write-ToLog -InvocationName $ServiceName -LogData 'Restarting CA service' -Severity 'INFO'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to restart CA service $_" -Severity 'ERROR'
        Exit 1
    }

    Start-Sleep -Seconds 10

    Write-ToLog -InvocationName $ServiceName -LogData 'Publishing CRL' -Severity 'INFO'
    & certutil.exe -crl > $null

    Write-ToLog -InvocationName $ServiceName -LogData 'Copying CRL to PKI folder' -Severity 'INFO'
    Try {
        Copy-Item -Path 'C:\Windows\System32\CertSrv\CertEnroll\*.cr*' -Destination 'D:\Pki\' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to copy CRL to PKI folder $_" -Severity 'ERROR'
        Exit 1
    }

    If ($UseS3ForCRL -eq 'Yes') {
        Write-ToLog -InvocationName $ServiceName -LogData 'Copying CRL to S3 bucket' -Severity 'INFO'
        Try {
            Write-S3Object -BucketName $S3CRLBucketName -Folder 'C:\Windows\System32\CertSrv\CertEnroll\' -KeyPrefix "$CompName\" -SearchPattern '*.cr*' -PublicReadOnly -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to copy CRL to S3 bucket $_" -Severity 'ERROR'
            Exit 1
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Restarting CA service' -Severity 'INFO'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to restart CA service $_" -Severity 'WARN'
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Creating LdapOverSSL certificate template' -Severity 'INFO'
    New-KerbCertTemplate -BaseDn $BaseDn -Credential $Credentials -Server $DC

    If ($DirectoryType -eq 'SelfManaged') {
        Write-ToLog -InvocationName $ServiceName -LogData 'Getting domain controllers' -Severity 'INFO'
        Try {
            $DomainControllers = Get-ADComputer -SearchBase "OU=Domain Controllers,$BaseDn" -Filter * | Select-Object -ExpandProperty 'DNSHostName'
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to get domain controllers $_" -Severity 'WARN'
        }

        Write-ToLog -InvocationName $ServiceName -LogData 'Running Group Policy update against all domain controllers' -Severity 'INFO'
        Foreach ($DomainController in $DomainControllers) {
            Invoke-Command -ComputerName $DomainController -Credential $Credentials -ScriptBlock { Invoke-GPUpdate -RandomDelayInMinutes '0' -Force }
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Creating Update CRL scheduled task' -Severity 'INFO'
    Try {
        If ($UseS3ForCRL -eq 'Yes') {
            $ScheduledTaskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "& certutil.exe -crl; Write-S3Object -BucketName $S3CRLBucketName -Folder C:\Windows\System32\CertSrv\CertEnroll\ -KeyPrefix $CompName\ -SearchPattern *.cr* -PublicReadOnly"
        } Else {
            $ScheduledTaskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '& certutil.exe -crl; Copy-Item -Path C:\Windows\System32\CertSrv\CertEnroll\*.cr* -Destination D:\Pki\'
        }
        $ScheduledTaskTrigger = New-ScheduledTaskTrigger -Daily -DaysInterval '5' -At '12am' -ErrorAction Stop
        $ScheduledTaskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType 'ServiceAccount' -RunLevel 'Highest' -ErrorAction Stop
        $ScheduledTaskSettingsSet = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Compatibility 'Win8' -ExecutionTimeLimit (New-TimeSpan -Hours '1') -ErrorAction Stop
        $ScheduledTask = New-ScheduledTask -Action $ScheduledTaskAction -Principal $ScheduledTaskPrincipal -Trigger $ScheduledTaskTrigger -Settings $ScheduledTaskSettingsSet -Description 'Updates CRL to Local Pki Folder' -ErrorAction Stop
        $Null = Register-ScheduledTask 'Update CRL' -InputObject $ScheduledTask -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to register Update CRL scheduled task $_" -Severity 'WARN'
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Running CRL scheduled task' -Severity 'INFO'
    Try {
        Start-ScheduledTask -TaskName 'Update CRL' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to run CRL scheduled task $_" -Severity 'WARN'
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Restarting CA service' -Severity 'INFO'
    Try {
        Restart-Service -Name 'certsvc' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to restart CA service $_" -Severity 'WARN'
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Removing RootCA certificate request files' -Severity 'INFO'
    Try {
        Remove-Item -Path 'D:\Pki\Req' -Recurse -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to remove RootCA certificate request files $_" -Severity 'WARN'
    }
 
    Write-ToLog -InvocationName $ServiceName -LogData 'Removing the PkiSubCA and PKIRootCA SYSVOL folders' -Severity 'INFO'
    Foreach ($SvolFolder in $SvolFolders) {
        Try {
            Remove-Item -Path $SvolFolder -Recurse -Force -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to remove PkiSubCA and PKIRootCA SYSVOL folders $_" -Severity 'ERROR'
            Exit 1
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Removing computer account from elevated groups' -Severity 'INFO'
    If ($DirectoryType -eq 'SelfManaged') {
        Try {
            Remove-ADGroupMember -Identity 'Enterprise Admins' -Members (Get-ADComputer -Identity $CompName | Select-Object -ExpandProperty 'DistinguishedName') -Confirm:$false -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to remove computer account from Enterprise Admins $_" -Severity 'ERROR'
            Exit 1
        }
    } Else {
        Try {
            Remove-ADGroupMember -Identity 'AWS Delegated Enterprise Certificate Authority Administrators' -Members (Get-ADComputer -Identity $CompName -Credential $Credentials | Select-Object -ExpandProperty 'DistinguishedName') -Confirm:$false -ErrorAction Stop -Credential $Credentials
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to remove computer account from AWS Delegated Enterprise Certificate Authority Administrators $_" -Severity 'ERROR'
            Exit 1
        }
    }

    Write-ToLog -InvocationName $ServiceName -LogData 'Clearing all SYSTEM kerberos tickets' -Severity 'INFO'
    & Klist.exe -li 0x3e7 purge > $null

    Write-ToLog -InvocationName $ServiceName -LogData 'Setting Windows Firewall WinRM Public rule to allow VPC CIDR traffic' -Severity 'INFO'
    Try {
        Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP-PUBLIC' -RemoteAddress $VPCCIDR -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to allow WinRM Traffic from VPC CIDR $_" -Severity 'WARN'
    }
}

Function New-TemplateOID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][string]$ConfigNC
    )

    #==================================================
    # Variables
    #==================================================
    
    $Hex = '0123456789ABCDEF'

    #==================================================
    # Main
    #==================================================

    Do {
        [string]$RandomHex = $null
        For ($i = 1; $i -le 32; $i++) {
            $RandomHex += $Hex.Substring((Get-Random -Minimum 0 -Maximum 16), 1)
        }

        $OID_Part_1 = Get-Random -Minimum 1000000 -Maximum 99999999
        $OID_Part_2 = Get-Random -Minimum 10000000 -Maximum 99999999
        $OID_Part_3 = $RandomHex
        $OID_Forest = Get-ADObject -Server $Server -Identity "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" -Properties msPKI-Cert-Template-OID | Select-Object -ExpandProperty msPKI-Cert-Template-OID -ErrorAction SilentlyContinue
        $msPKICertTemplateOID = "$OID_Forest.$OID_Part_1.$OID_Part_2"
        $Name = "$OID_Part_2.$OID_Part_3"
        $Search = Get-ADObject -Server $Server -SearchBase "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" -Filter { cn -eq $Name -and msPKI-Cert-Template-OID -eq $msPKICertTemplateOID } -ErrorAction SilentlyContinue
        If ($Search) { 
            $Unique = 'False'
        } Else { 
            $Unique = 'True'
        }
    } Until ($Unique = 'True')
    Return @{
        TemplateOID  = $msPKICertTemplateOID
        TemplateName = $Name
    }
}

Function New-KerbCertTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$BaseDn,
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$Server
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name
    $CA = $env:COMPUTERNAME

    #==================================================
    # Main
    #==================================================

    $OID = New-TemplateOID -Server $Server -ConfigNC "CN=Configuration,$BaseDn"

    $TemplateOIDPath = "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn"
    $OidOtherAttributes = @{
        'DisplayName'             = 'LdapOverSSL'
        'flags'                   = [System.Int32]'1'
        'msPKI-Cert-Template-OID' = $OID.TemplateOID
    }

    $OtherAttributes = @{
        'flags'                                = [System.Int32]'131168'
        'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.2.3.5', '1.3.6.1.4.1.311.20.2.2', '1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2')
        'msPKI-Certificate-Name-Flag'          = [System.Int32]'138412032'
        'msPKI-Enrollment-Flag'                = [System.Int32]'40'
        'msPKI-Minimal-Key-Size'               = [System.Int32]'2048'
        'msPKI-Private-Key-Flag'               = [System.Int32]'84279552'
        'msPKI-Template-Minor-Revision'        = [System.Int32]'1'
        'msPKI-Template-Schema-Version'        = [System.Int32]'4'
        'msPKI-RA-Signature'                   = [System.Int32]'0'
        'pKIMaxIssuingDepth'                   = [System.Int32]'0'
        'ObjectClass'                          = [System.String]'pKICertificateTemplate'
        'pKICriticalExtensions'                = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2.5.29.17', '2.5.29.15')
        'pKIDefaultCSPs'                       = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1,Microsoft RSA SChannel Cryptographic Provider')
        'pKIDefaultKeySpec'                    = [System.Int32]'1'
        'pKIExpirationPeriod'                  = [System.Byte[]]@('0', '64', '57', '135', '46', '225', '254', '255')
        'pKIExtendedKeyUsage'                  = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.2.3.5', '1.3.6.1.4.1.311.20.2.2', '1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2')
        'pKIKeyUsage'                          = [System.Byte[]]@('160', '0')
        'pKIOverlapPeriod'                     = [System.Byte[]]@('0', '128', '166', '10', '255', '222', '255', '255')
        'revision'                             = [System.Int32]'100'
        'msPKI-Cert-Template-OID'              = $OID.TemplateOID
    }

    Write-ToLog -InvocationName $ServiceName -LogData "Creating new LdapOverSSL certificate template OID $_" -Severity 'INFO'
    Try {
        New-ADObject -Path $TemplateOIDPath -OtherAttributes $OidOtherAttributes -Name $OID.TemplateName -Type 'msPKI-Enterprise-Oid' -Server $Server -Credential $Credential -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to create new LdapOverSSL certificate template OID $_" -Severity 'ERROR'
        Exit 1
    }

    $TemplatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn"

    Write-ToLog -InvocationName $ServiceName -LogData "Creating new LdapOverSSL certificate template $_" -Severity 'INFO'
    Try {
        New-ADObject -Path $TemplatePath -OtherAttributes $OtherAttributes -Name 'LdapOverSSL' -DisplayName 'LdapOverSSL' -Type 'pKICertificateTemplate' -Server $Server -Credential $Credential -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -InvocationName $ServiceName -LogData "Failed to create new LdapOverSSL certificate template $_" -Severity 'ERROR'
        Exit 1
    }

    $SidsToAdd = @(
        [Security.Principal.SecurityIdentifier]'S-1-5-9'
        (Get-ADGroup -Identity 'Domain Controllers' | Select-Object -ExpandProperty 'SID')
    )

    $SidsToRemove = @(
        [Security.Principal.SecurityIdentifier]'S-1-5-18',
        (Get-ADGroup -Identity 'Domain Admins' | Select-Object -ExpandProperty 'SID')
    )

    Write-ToLog -InvocationName $ServiceName -LogData 'Enabling CredSSP' -Severity 'INFO'
    Set-CredSSP -Action 'Enable'

    Write-ToLog -InvocationName $ServiceName -LogData 'Sleeping to ensure replication of certificate template has completed' -Severity 'INFO'
    Start-Sleep -Seconds 60 

    Write-ToLog -InvocationName $ServiceName -LogData 'Cleaning up ACLs on LdapOverSSL certificate template' -Severity 'INFO'
    $ExtendedRightGuids = @(
        [GUID]'0e10c968-78fb-11d2-90d4-00c04f79dc55',
        [GUID]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
    )
    Foreach ($SidToAdd in $SidsToAdd) {
        Add-CertTemplateAcl -Credential $Credential -Path "CN=LdapOverSSL,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn" -IdentityReference $SidToAdd -ActiveDirectoryRights 'GenericRead,GenericWrite,WriteDacl,WriteOwner,Delete' -AccessControlType 'Allow' -ActiveDirectorySecurityInheritance 'None'

        Foreach ($ExtendedRightGuid in $ExtendedRightGuids) {
            Add-CertTemplateAcl -Credential $Credential -Path "CN=LdapOverSSL,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn" -IdentityReference $SidToAdd -ActiveDirectoryRights 'ExtendedRight' -AccessControlType 'Allow' -ObjectGuid $ExtendedRightGuid -ActiveDirectorySecurityInheritance 'None'
        }
    }

    Set-CertTemplateAclInheritance -Credential $Credential -Path "CN=LdapOverSSL,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn"

    Foreach ($SidToRemove in $SidsToRemove) {
        Remove-CertTemplateAcl -Credential $Credential -Path "CN=LdapOverSSL,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$BaseDn" -IdentityReference $SidToRemove -AccessControlType 'Allow'
    }

    Write-ToLog -InvocationName $ServiceName -LogData "Publishing LdapOverSSL template to allow enrollment" -Severity 'INFO'
    $Counter = 0
    Do {
        $TempPresent = $Null
        Try {
            $TempPresent = Invoke-Command -Authentication 'Credssp' -ComputerName $env:COMPUTERNAME -Credential $Credential -ScriptBlock { 
                Get-ADObject "CN=$Using:CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$Using:BaseDn" -Partition "CN=Configuration,$Using:BaseDn" -Properties 'certificateTemplates' | Select-Object -ExpandProperty 'certificateTemplates' | Where-Object { $_ -contains 'LdapOverSSL' }
            }
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "LdapOverSSL Template missing" -Severity 'WARN'
            $TempPresent = $Null
        }
        If (-not $TempPresent) {
            $Counter ++
            Write-ToLog -InvocationName $ServiceName -LogData "LdapOverSSL Template missing adding it." -Severity 'INFO'
            Try {
                Invoke-Command -Authentication 'Credssp' -ComputerName $env:COMPUTERNAME -Credential $Credential -ScriptBlock {
                    Set-ADObject "CN=$Using:CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$Using:BaseDn" -Partition "CN=Configuration,$Using:BaseDn" -Add @{ 'certificateTemplates' = 'LdapOverSSL' } 
                }
            } Catch [System.Exception] {
                Write-ToLog -InvocationName $ServiceName -LogData "Failed to add publish LdapOverSSL template $_" -Severity 'WARN'
            }
            If ($Counter -gt '1') {
                Start-Sleep -Seconds 10
            }
        }
    } Until ($TempPresent -or $Counter -eq 12)

    Write-ToLog -InvocationName $ServiceName -LogData 'Sleeping to ensure replication of certificate template publish has completed' -Severity 'INFO'
    Start-Sleep -Seconds 60 

    Write-ToLog -InvocationName $ServiceName -LogData 'Disabling CredSSP' -Severity 'INFO'
    Set-CredSSP -Action 'Disable'
}

Function Add-CertTemplateAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$IdentityReference,
        [Parameter(Mandatory = $true)][System.DirectoryServices.ActiveDirectoryRights]$ActiveDirectoryRights,
        [Parameter(Mandatory = $true)][System.Security.AccessControl.AccessControlType]$AccessControlType,
        [Parameter(Mandatory = $false)][Guid]$ObjectGuid,        
        [Parameter(Mandatory = $false)][System.DirectoryServices.ActiveDirectorySecurityInheritance]$ActiveDirectorySecurityInheritance,
        [Parameter(Mandatory = $false)][Guid]$InheritedObjectGuid
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name

    #==================================================
    # Main
    #==================================================

    Invoke-Command -Authentication 'Credssp' -ComputerName $env:COMPUTERNAME -Credential $Credential -ScriptBlock {
        Import-Module -Name 'ActiveDirectory' -Force

        [Security.Principal.SecurityIdentifier]$IdentityReference = $Using:IdentityReference | Select-Object -ExpandProperty 'Value'

        $ArgumentList = $IdentityReference, $Using:ActiveDirectoryRights, $Using:AccessControlType, $Using:ObjectGuid, $Using:ActiveDirectorySecurityInheritance, $Using:InheritedObjectGuid
        $ArgumentList = $ArgumentList.Where( { $_ -ne $Null })

        Write-ToLog -InvocationName $ServiceName -LogData 'Creating ACL object' -Severity 'INFO'
        Try {
            $Rule = New-Object -TypeName 'System.DirectoryServices.ActiveDirectoryAccessRule' -ArgumentList $ArgumentList -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to create ACL object $_" -Severity 'ERROR'
            Exit 1
        }

        Write-ToLog -InvocationName $ServiceName -LogData "Getting ACL for $Using:Path" -Severity 'INFO'
        Try {
            $ObjectAcl = Get-Acl -Path "AD:\$Using:Path" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to get ACL for $Using:Path $_" -Severity 'ERROR'
            Exit 1
        }

        $ObjectAcl.AddAccessRule($Rule) 

        Write-ToLog -InvocationName $ServiceName -LogData "Setting ACL for $Using:Path" -Severity 'INFO'
        Try {
            Set-Acl -AclObject $ObjectAcl -Path "AD:\$Using:Path" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to set ACL for $Using:Path $_" -Severity 'ERROR'
            Exit 1
        }
    }
}

Function Set-CertTemplateAclInheritance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$Path
    )

    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name

    #==================================================
    # Main
    #==================================================

    Invoke-Command -Authentication 'Credssp' -ComputerName $env:COMPUTERNAME -Credential $Credential -ScriptBlock {
        Import-Module -Name 'ActiveDirectory' -Force -ErrorAction Stop

        Write-ToLog -InvocationName $ServiceName -LogData "Getting ACL for $Using:Path" -Severity 'INFO'
        Try {
            $ObjectAcl = Get-Acl -Path "AD:\$Using:Path" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to get ACL for $Using:Path $_" -Severity 'ERROR'
            Exit 1
        }

        $ObjectAcl.SetAccessRuleProtection($true, $false)

        Write-ToLog -InvocationName $ServiceName -LogData "Setting ACL for $Using:Path" -Severity 'INFO'
        Try {
            Set-Acl -AclObject $ObjectAcl -Path "AD:\$Using:Path" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to set ACL for $Using:Path $_" -Severity 'ERROR'
            Exit 1
        }
    }
}

Function Remove-CertTemplateAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][PSCredential]$Credential,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$IdentityReference,
        [Parameter(Mandatory = $true)][System.Security.AccessControl.AccessControlType]$AccessControlType
    )
    
    #==================================================
    # Variables
    #==================================================

    $ServiceName = $MyInvocation.MyCommand.Name
    
    #==================================================
    # Main
    #==================================================

    Invoke-Command -Authentication 'Credssp' -ComputerName $env:COMPUTERNAME -Credential $Credential -ScriptBlock {
        Import-Module -Name 'ActiveDirectory' -Force -ErrorAction Stop

        Write-ToLog -InvocationName $ServiceName -LogData "Getting ACL for $Using:Path" -Severity 'INFO'
        Try {
            $ObjectAcl = Get-Acl -Path "AD:\$Using:Path" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to get ACL for $Using:Path $_" -Severity 'ERROR'
            Exit 1
        }

        [Security.Principal.SecurityIdentifier]$IdentityReference = $Using:IdentityReference | Select-Object -ExpandProperty 'Value'

        $ObjectAcl.RemoveAccess($IdentityReference, $Using:AccessControlType)

        Write-ToLog -InvocationName $ServiceName -LogData "Removing ACL for $Using:Path" -Severity 'INFO'
        Try {
            Set-Acl -AclObject $ObjectAcl -Path "AD:\$Using:Path" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-ToLog -InvocationName $ServiceName -LogData "Failed to remove ACL for $Using:Path $_" -Severity 'ERROR'
            Exit 1
        }
    }
}