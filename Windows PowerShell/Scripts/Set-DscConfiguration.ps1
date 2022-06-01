<#
 .SYNOPSIS
 Configures the DSC agent.

 .DESCRIPTION
 This script configures the Local Configuration Manager for PowerShell Desired State Configuration.

 Reference:
 https://msdn.microsoft.com/en-us/powershell/dsc/metaconfig

 .PARAMETER Rollback
 Switch that will flip new DSC configurations to 'Absent' in order to rollback a change.

 .Example
 .\Set-DscConfiguration.ps1
 #>

 Param (
    [Bool]$RebootNodeIfNeeded = $False
)

#==================================================
# Variables 
#==================================================

Try {
    $OsInstall = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' -Name 'InstallationType' | Select-Object -ExpandProperty 'InstallationType' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to get OS installation type $_"
    Exit 1
}

Try {
    $AmIaDC = Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction SilentlyContinue
} Catch {
    $AmIaDC = $Null
}

Write-Output 'Getting MAC address'
Try {
    $MacAddress = Get-NetAdapter -ErrorAction Stop | Select-Object -ExpandProperty 'MacAddress'
} Catch [System.Exception] {
    Write-Output "Failed to get MAC address $_"
    Exit 1
}

$KtVersion = (Invoke-WebRequest 'https://s3-us-west-2.amazonaws.com/kinesis-agent-windows/downloads/packages.json' -Headers @{"Accept" = "application/json" } -UseBasicParsing | Select-Object -ExpandProperty 'Content' | ConvertFrom-Json | Select-Object -ExpandProperty 'Packages').Version[0]

#==================================================
# Functions
#==================================================

#Requires -Modules PSDscResources, Module-DSC, PSDesiredStateConfiguration, NetworkingDsc, ComputerManagementDsc, 'SChannelDsc', 'AuditPolicyDsc'

#==================================================
# Configurations
#==================================================

Configuration AwsDriversInstall {
    Import-DscResource -ModuleName 'Module-DSC'
    Node LocalHost {
        AwsDriverPnPInstaller ENA {
            Ensure        = 'Present'  
            DeviceName    = 'Amazon Elastic Network Adapter'
            DriverVersion = '2.2.4.0'
            URL           = 'https://s3.amazonaws.com/ec2-windows-drivers-downloads/ENA/Latest/AwsEnaNetworkDriver.zip'
        }
        AwsDriverPnPInstaller NVMe {
            Ensure        = 'Present'  
            DeviceName    = 'AWS NVMe Elastic Block Storage Adapter'
            DriverVersion = '1.4.0.13'
            URL           = 'https://s3.amazonaws.com/ec2-windows-drivers-downloads/NVMe/Latest/AWSNVMe.zip'
        }
        AwsDriverPvInstaller PV {
            Ensure        = 'Present'  
            DeviceName    = 'AWS PV Drivers'
            DriverVersion = '8.4.1'
            URL           = 'https://s3.amazonaws.com/ec2-windows-drivers-downloads/AWSPV/Latest/AWSPVDriver.zip'
        }
    }
}

Configuration ComputerConfig {
    Import-DscResource -ModuleName 'ComputerManagementDsc'
    Node LocalHost {
        PowerPlan 'SetPlanHighPerformance' {
            IsSingleInstance = 'Yes'
            Name             = 'High performance'
        }
        If ($OsInstall -eq 'Server') {
            IEEnhancedSecurityConfiguration 'DisableForAdministrators' {
                Role    = 'Administrators'
                Enabled = $false
            }
            IEEnhancedSecurityConfiguration 'DisableForUsers' {
                Role    = 'Users'
                Enabled = $false
            }
        }
    }
}

Configuration DisabledServicesDsc {
    Import-DscResource -ModuleName 'PSDscResources'
    Node LocalHost {
        Service Internet-Connection-Sharing-ICS {
            Name        = 'SharedAccess'
            StartupType = 'Disabled'
            State       = 'Stopped'
        }
        Service Link-Layer-Topology-Discovery-Mapper {
            Name        = 'lltdsvc'
            StartupType = 'Disabled'
            State       = 'Stopped'
        }
        Service Net.Tcp-Port-Sharing-Service {
            Name        = 'NetTcpPortSharing'
            StartupType = 'Disabled'
            State       = 'Stopped'
        }
        Service Routing-and-Remote-Access {
            Name        = 'RemoteAccess'
            StartupType = 'Disabled'
            State       = 'Stopped'
        }
        Service Windows-Insider-Service {
            Name        = 'wisvc'
            StartupType = 'Disabled'
            State       = 'Stopped'
        }
        Service Smart-Card {
            Name        = 'SCardSvr'
            StartupType = 'Disabled'
            State       = 'Stopped'
        }
        Service Smart-Card-Device-Enumeration-Service {
            Name        = 'ScDeviceEnum'
            StartupType = 'Disabled'
            State       = 'Stopped'
        }       
        If ($OsInstall -eq 'Server') {
            Service ActiveX-Installer-AxInstSV {
                Name        = 'AxInstSV'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }        
            Service Auto-Time-Zone-Updater {
                Name        = 'tzautoupdate'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Bluetooth-Support-Service {
                Name        = 'bthserv'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Device-Management-Wireless-Application-Protocol-WAP-Push-message-Routing-Service {
                Name        = 'dmwappushservice'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Downloaded-Maps-Manager {
                Name        = 'MapsBroker'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Geolocation-Service {
                Name        = 'lfsvc'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Microsoft-Account-Sign-in-Assistant {
                Name        = 'wlidsvc'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Microsoft-App-V-Client {
                Name        = 'AppVClient'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Microsoft-Passport {
                Name        = 'NgcSvc'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Microsoft-Passport-Container {
                Name        = 'NgcCtnrSvc'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Offline-Files {
                Name        = 'CscService'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Print-Spooler {
                Name        = 'Spooler'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Printer-Extensions-and-Notifications {
                Name        = 'PrintNotify'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Program-Compatibility-Assistant-Service {
                Name        = 'PcaSvc'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Quality-Windows-Audio-Video-Experience {
                Name        = 'QWAVE'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Radio-Management-Service {
                Name        = 'RmSvc'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Sensor-Data-Service {
                Name        = 'SensorDataService'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Sensor-Monitoring-Service {
                Name        = 'SensrSvc'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Sensor-Service {
                Name        = 'SensorService'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Shell-Hardware-Detection {
                Name        = 'ShellHWDetection'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service SSDP-Discovery {
                Name        = 'SSDPSRV'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Still-Image-Acquisition-Events {
                Name        = 'WiaRpc'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Themes {
                Name        = 'Themes'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service UPnP-Device-Host {
                Name        = 'upnphost'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service User-Experience-Virtualization-Service {
                Name        = 'UevAgentService'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service WalletService {
                Name        = 'WalletService'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Windows-Audio {
                Name        = 'Audiosrv'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Windows-Audio-Endpoint-Builder {
                Name        = 'AudioEndpointBuilder'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Windows-Camera-Frame-Server {
                Name        = 'FrameServer'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Windows-Image-Acquisition-WIA {
                Name        = 'stisvc'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Windows-Push-Notifications-System-Service {
                Name        = 'WpnService'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service Windows-Search {
                Name        = 'WSearch'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
        }
    }
}

Configuration EnabledServicesDsc {
    Import-DscResource -ModuleName 'PSDscResources'
    Node LocalHost {
        If ($AmIaDC) {
            Service Active-Directory-Domain-Services {
                Name        = 'NTDS'
                StartupType = 'Automatic'
                State       = 'Running'
            }
            Service Active-Directory-Web-Services {
                Name        = 'ADWS'
                StartupType = 'Automatic'
                State       = 'Running'
            }
            Service DFS-Namespace {
                Name        = 'Dfs'
                StartupType = 'Automatic'
                State       = 'Running'
            }
            Service DFS-Replication {
                Name        = 'DFSR'
                StartupType = 'Automatic'
                State       = 'Running'
            }
            Service DNS-Server {
                Name        = 'DNS'
                StartupType = 'Automatic'
                State       = 'Running'
            }
            Service Intersite-Messaging {
                Name        = 'IsmServ'
                StartupType = 'Automatic'
                State       = 'Running'
            }
            Service Kerberos-Key-Distribution-Center {
                Name        = 'Kdc'
                StartupType = 'Automatic'
                State       = 'Running'
            }
            Service Netlogon {
                Name        = 'Netlogon'
                StartupType = 'Automatic'
                State       = 'Running'
            }
        }
        Service Amazon-SSM-Agent {
            Name        = 'AmazonSSMAgent'
            StartupType = 'Automatic'
            State       = 'Running'
        }
        #Service Amazon-EC2-Launch {
        #    Name        = 'Amazon EC2Launch'
        #    StartupType = 'Automatic'
        #    State       = 'Running'
        #}
        #Service Application-Identity {
        #    Name        = 'AppIDSvc'
        #    StartupType = 'Automatic'
        #    State       = 'Running'
        #}
        Service COM+-Event-System {
            Name        = 'EventSystem'
            StartupType = 'Automatic'
            State       = 'Running'
        }
        Service DNS-Client {
            Name        = 'Dnscache'
            StartupType = 'Automatic'
            State       = 'Running'
        }
        Service Group-Policy-Client {
            Name        = 'gpsvc'
            StartupType = 'Automatic'
            State       = 'Running'
        }
        Service Remote-Procedure-Call-RPC {
            Name        = 'RpcSs'
            StartupType = 'Automatic'
            State       = 'Running'
        }
        Service Security-Accounts-Manager {
            Name        = 'SamSs'
            StartupType = 'Automatic'
            State       = 'Running'
        }
        Service Server {
            Name        = 'LanmanServer'
            StartupType = 'Automatic'
            State       = 'Running'
        }
        #Service Smart-Card-Removal-Policy {
        #    Name        = 'SCPolicySvc'
        #    StartupType = 'Automatic'
        #    State       = 'Running'
        #}
        Service Windows-Time {
            Name        = 'W32Time'
            StartupType = 'Automatic'
            State       = 'Running'
        }
        Service Workstation {
            Name        = 'LanmanWorkstation'
            StartupType = 'Automatic'
            State       = 'Running'
        }
        If ($OsInstall -eq 'Server') {
            Service Application-Information {
                Name        = 'Appinfo'
                StartupType = 'Automatic'
                State       = 'Running'
            }
        }
    }
}

Configuration NetworkConfig {
    Import-DscResource -ModuleName 'NetworkingDsc'
    Node LocalHost {
        NetAdapterName RenameNetAdapterPrimary {
            NewName    = 'ETH0'
            MacAddress = $MacAddress
        }
        NetAdapterAdvancedProperty JumboPacket {
            NetworkAdapterName = 'ETH0'
            RegistryKeyword    = '*JumboPacket'
            RegistryValue      = 9015
        }
        NetAdapterAdvancedProperty ReceiveBuffers {
            NetworkAdapterName = 'ETH0'
            RegistryKeyword    = '*ReceiveBuffers'
            RegistryValue      = 8192
        }
        NetAdapterAdvancedProperty TransmitBuffers {
            NetworkAdapterName = 'ETH0'
            RegistryKeyword    = '*TransmitBuffers'
            RegistryValue      = 1024
        }
        NetBios DisableNetBios {
            InterfaceAlias = 'ETH0'
            Setting        = 'Disable'
        }
        <#NetConnectionProfile SetPrivate
        {
            InterfaceAlias   = 'ETH0'
            NetworkCategory  = 'Private'
        }#>
    }
}

Configuration RegistrySettingsDscNewModule {
    Import-DscResource -ModuleName 'PSDscResources'
    Node LocalHost {
        Registry DisableDCCheck {
            Ensure    = 'Present'  
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Amazon\AWSPVDriverSetup'
            ValueName = 'DisableDCCheck'
            ValueType = 'String'
            ValueData = 'true'
            Force     = $true
        }
        If ($OsInstall -eq 'Server') {
            Registry Chrome-TLS {
                Ensure    = 'Present'  
                Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome'
                ValueName = 'SSLVersionMin'
                ValueType = 'String'
                ValueData = 'tls1.2'
                Force     = $true
            }
            Registry Edge-TLS {
                Ensure    = 'Present'  
                Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge'
                ValueName = 'SSLVersionMin'
                ValueType = 'String'
                ValueData = 'tls1.2'
                Force     = $true
            }
            Registry Firefox-TLS {
                Ensure    = 'Present'  
                Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox'
                ValueName = 'SSLVersionMin'
                ValueType = 'String'
                ValueData = 'tls1.2'
                Force     = $true
            }
        }
    }
}

Configuration RegistrySettingsDscOldModule {
    Import-DscResource -ModuleName 'Module-DSC'
    Node LocalHost {
        RegistryKeyAndValue Schannel-EventLogging {
            Ensure    = 'Present'  
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
            ValueName = 'EventLogging'
            ValueType = 'Dword'
            ValueData = '7'
        }
    }
}

Configuration SChannelDsc {
    Import-DscResource -ModuleName 'SChannelDsc'
    Protocol DisableSSLv3 {
        Protocol           = 'SSL 3.0'
        IncludeClientSide  = $true
        State              = 'Disabled'
        RebootWhenRequired = $true
    }
    Protocol DisableTLS1 {
        Protocol           = 'TLS 1.0' 
        IncludeClientSide  = $true
        State              = 'Disabled'
        RebootWhenRequired = $true
    }
    Protocol DisableTLS11 {
        Protocol           = 'TLS 1.1'
        IncludeClientSide  = $true
        State              = 'Disabled'
        RebootWhenRequired = $true
    }
    Protocol EnableTLS12 {
        Protocol           = 'TLS 1.2'
        IncludeClientSide  = $true
        State              = 'Enabled'
        RebootWhenRequired = $true
    }
    Protocol EnableTLS13 {
        Protocol           = 'TLS 1.3'
        IncludeClientSide  = $true
        State              = 'Enabled'
        RebootWhenRequired = $true
    }    
    Cipher DisableRC4-40 {
        Cipher             = 'RC4 40/128'
        State              = 'Disabled'
        RebootWhenRequired = $true
    }
    Cipher DisableRC4-56 {
        Cipher             = 'RC4 56/128'
        State              = 'Disabled'
        RebootWhenRequired = $true
    }
    Cipher DisableRC4-64 {
        Cipher             = 'RC4 64/128'
        State              = 'Disabled'
        RebootWhenRequired = $true
    }
    Cipher DisableRC4-128 {
        Cipher             = 'RC4 128/128'
        State              = 'Disabled'
        RebootWhenRequired = $true
    }
    Cipher Disable3Des {
        Cipher             = 'Triple DES 168'
        State              = 'Disabled'
        RebootWhenRequired = $true
    }
    Cipher EnableAES128 {
        Cipher             = 'AES 128/128'
        State              = 'Enabled'
        RebootWhenRequired = $true
    }
    Cipher EnableAES256 {
        Cipher             = 'AES 256/256'
        State              = 'Enabled'
        RebootWhenRequired = $true
    }
    CipherSuites 3DESCipher {
        IsSingleInstance   = 'Yes'
        CipherSuitesOrder  = 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
        Ensure             = 'Absent'
        RebootWhenRequired = $true
    }
    SChannelSettings 'ConfigureSChannel' {
        IsSingleInstance              = 'Yes'
        TLS12State                    = 'Enabled'
        WinHttpDefaultSecureProtocols = @('TLS1.2')
        RebootWhenRequired            = $true
    }
}

Configuration SoftwareInstall {
    Import-DscResource -ModuleName 'Module-DSC'
    Node LocalHost {
        MsiInstaller EC2Launch {
            Ensure          = 'Present'  
            SoftwareName    = 'Amazon EC2Launch'
            SoftwareVersion = '2.0.698.0'
            URL             = 'https://s3.amazonaws.com/amazon-ec2launch-v2/windows/amd64/latest/AmazonEC2Launch.msi'
        }
        MsiInstaller KinesisAgent {
            Ensure          = 'Present'  
            SoftwareName    = 'Amazon Kinesis Agent for Microsoft Windows'
            SoftwareVersion = $KtVersion
            URL             = "https://s3-us-west-2.amazonaws.com/kinesis-agent-windows/downloads/AWSKinesisTap.$KtVersion.msi"
        }
        <#MsiInstaller CWAgent {
            Ensure          = 'Present'  
            SoftwareName    = 'Amazon CloudWatch Agent'
            SoftwareVersion = '1.3.50739'
            URL             = 'https://s3.amazonaws.com/amazoncloudwatch-agent/windows/amd64/latest/amazon-cloudwatch-agent.msi'
        }#>
        ExeInstaller SSMAgent {
            Ensure          = 'Present'  
            SoftwareName    = 'Amazon SSM Agent'
            SoftwareVersion = '3.1.1004.0'
            URL             = 'https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe'
        }
        <#DotNetOfflineInstall DotNet48 {
            Ensure = 'Present'  
            KbId   = 'KB4486153'
            URL    = 'https://go.microsoft.com/fwlink/?linkid=2088631'
        }#>
    }
}

Configuration WindowsFeaturesDsc {
    Import-DscResource -ModuleName 'PSDscResources'
    Node LocalHost {
        WindowsFeature FS-SMB1 {
            Ensure = 'Absent'
            Name   = 'FS-SMB1'
        }
        WindowsFeature PNRP {
            Ensure = 'Absent'
            Name   = 'PNRP'
        }
        WindowsFeature PowerShell-v2 {
            Ensure = 'Absent'
            Name   = 'PowerShell-v2'
        }
        WindowsFeature Simple-TCPIP {
            Ensure = 'Absent'
            Name   = 'Simple-TCPIP'
        }
        WindowsFeature Telnet-Client {
            Ensure = 'Absent'
            Name   = 'Telnet-Client'
        }
        WindowsFeature System-Insights {
            Ensure = 'Present'
            Name   = 'System-Insights'
        }
        WindowsFeature Web-Ftp-Service {
            Ensure = 'Absent'
            Name   = 'Web-Ftp-Service'
        }
        WindowsFeature Windows-Defender {
            Ensure = 'Absent'
            Name   = 'Windows-Defender'
        }
        WindowsFeature Windows-Server-Backup {
            Ensure = 'Present'
            Name   = 'Windows-Server-Backup'
        }
        If ($OsInstall -eq 'Server') {
            WindowsFeature Fax {
                Ensure = 'Absent'
                Name   = 'Fax'
            }
            WindowsFeature TFTP-Client {
                Ensure = 'Absent'
                Name   = 'TFTP-Client'
            }
            WindowsFeature XPS-Viewer {
                Ensure = 'Absent'
                Name   = 'XPS-Viewer'
            }
        }
    }
}

If ($AmIaDC) {
    Configuration DcAdvAudit {
        Import-DscResource -ModuleName 'AuditPolicyDsc'
        Node LocalHost {
            AuditPolicySubcategory CredentialValidationSuccess {
                Name      = 'Credential Validation'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory CredentialValidationFailure {
                Name      = 'Credential Validation'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory KerberosAuthenticationServiceSuccess {
                Name      = 'Kerberos Authentication Service'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory KerberosAuthenticationServiceFailure {
                Name      = 'Kerberos Authentication Service'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory KerberosServiceTicketOperationsSuccess {
                Name      = 'Kerberos Service Ticket Operations'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory KerberosServiceTicketOperationsFailure {
                Name      = 'Kerberos Service Ticket Operations'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherAccountLogonEventsSuccess {
                Name      = 'Other Account Logon Events'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherAccountLogonEventsFailure {
                Name      = 'Other Account Logon Events'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ApplicationGroupManagementSuccess {
                Name      = 'Application Group Management'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ApplicationGroupManagementFailure {
                Name      = 'Application Group Management'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ComputerAccountManagementSuccess {
                Name      = 'Computer Account Management'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory ComputerAccountManagementFailure {
                Name      = 'Computer Account Management'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DistributionGroupManagementSuccess {
                Name      = 'Distribution Group Management'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory DistributionGroupManagementFailure {
                Name      = 'Distribution Group Management'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherAccountManagementEventsSuccess {
                Name      = 'Other Account Management Events'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherAccountManagementEventsFailure {
                Name      = 'Other Account Management Events'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory SecurityGroupManagementSuccess {
                Name      = 'Security Group Management'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SecurityGroupManagementFailure {
                Name      = 'Security Group Management'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory UserAccountManagementSuccess {
                Name      = 'User Account Management'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory UserAccountManagementFailure {
                Name      = 'User Account Management'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory DPAPIActivitySuccess {
                Name      = 'DPAPI Activity'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory DPAPIActivityFailure {
                Name      = 'DPAPI Activity'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory PNPActivitySuccess {
                Name      = 'Plug and Play Events'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory PNPActivityFailure {
                Name      = 'Plug and Play Events'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ProcessCreationSuccess {
                Name      = 'Process Creation'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory ProcessCreationFailure {
                Name      = 'Process Creation'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ProcessTerminationSuccess {
                Name      = 'Process Termination'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory ProcessTerminationFailure {
                Name      = 'Process Termination'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory RPCEventsSuccess {
                Name      = 'RPC Events'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory RPCEventsFailure {
                Name      = 'RPC Events'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory TokenRightAdjustedSuccess {
                Name      = 'Token Right Adjusted Events'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory TokenRightAdjustedFailure {
                Name      = 'Token Right Adjusted Events'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DetailedDirectoryServiceReplicationSuccess {
                Name      = 'Detailed Directory Service Replication'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory DetailedDirectoryServiceReplicationFailure {
                Name      = 'Detailed Directory Service Replication'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory DirectoryServiceAccessSuccess {
                Name      = 'Directory Service Access'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DirectoryServiceAccessFailure {
                Name      = 'Directory Service Access'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory DirectoryServiceChangesSuccess {
                Name      = 'Directory Service Changes'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory DirectoryServiceChangesFailure {
                Name      = 'Directory Service Changes'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DirectoryServiceReplicationSuccess {
                Name      = 'Directory Service Replication'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory DirectoryServiceReplicationFailure {
                Name      = 'Directory Service Replication'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory AccountLockoutSuccess {
                Name      = 'Account Lockout'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory AccountLockoutFailure {
                Name      = 'Account Lockout'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory UserDeviceClaimsSuccess {
                Name      = 'User / Device Claims'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory UserDeviceClaimsFailure {
                Name      = 'User / Device Claims'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory GroupMembershipSuccess {
                Name      = 'Group Membership'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory GroupMembershipFailure {
                Name      = 'Group Membership'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory IPsecExtendedModeSuccess {
                Name      = 'IPsec Extended Mode'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecExtendedModeFailure {
                Name      = 'IPsec Extended Mode'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecMainModeSuccess {
                Name      = 'IPsec Main Mode'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecMainModeFailure {
                Name      = 'IPsec Main Mode'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecQuickModeSuccess {
                Name      = 'IPsec Quick Mode'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecQuickModeFailure {
                Name      = 'IPsec Quick Mode'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory LogoffSuccess {
                Name      = 'Logoff'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory Logoffailure {
                Name      = 'Logoff'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory LogonSuccess {
                Name      = 'Logon'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory LogonFailure {
                Name      = 'Logon'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory NetworkPolicyServerSuccess {
                Name      = 'Network Policy Server'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory NetworkPolicyServerFailure {
                Name      = 'Network Policy Server'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherLogonLogoffEventsSuccess {
                Name      = 'Other Logon/Logoff Events'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherLogonLogoffEventsFailure {
                Name      = 'Other Logon/Logoff Events'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SpecialLogonSuccess {
                Name      = 'Special Logon'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SpecialLogonFailure {
                Name      = 'Special Logon'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ApplicationGeneratedSuccess {
                Name      = 'Application Generated'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory ApplicationGeneratedFailure {
                Name      = 'Application Generated'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory CertificationServicesSuccess {
                Name      = 'Certification Services'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory CertificationServicesFailure {
                Name      = 'Certification Services'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DetailedFileShareSuccess {
                Name      = 'Detailed File Share'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory DetailedFileShareFailure {
                Name      = 'Detailed File Share'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FileShareSuccess {
                Name      = 'File Share'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FileShareFailure {
                Name      = 'File Share'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FileSystemSuccess {
                Name      = 'File System'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FileSystemFailure {
                Name      = 'File System'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FilteringPlatformConnectionSuccess {
                Name      = 'Filtering Platform Connection'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FilteringPlatformConnectionFailure {
                Name      = 'Filtering Platform Connection'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory FilteringPlatformPacketDropSuccess {
                Name      = 'Filtering Platform Packet Drop'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory FilteringPlatformPacketDropFailure {
                Name      = 'Filtering Platform Packet Drop'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory HandleManipulationSuccess {
                Name      = 'Handle Manipulation'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory HandleManipulationFailure {
                Name      = 'Handle Manipulation'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory KernelObjectSuccess {
                Name      = 'Kernel Object'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory KernelObjectFailure {
                Name      = 'Kernel Object'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherObjectAccessEventsSuccess {
                Name      = 'Other Object Access Events'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherObjectAccessEventsFailure {
                Name      = 'Other Object Access Events'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory RegistrySuccess {
                Name      = 'Registry'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory RegistryFailure {
                Name      = 'Registry'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory RemovableStorageSuccess {
                Name      = 'Removable Storage'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory RemovableStorageFailure {
                Name      = 'Removable Storage'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory CentralAccessPolicyStagingSuccess {
                Name      = 'Central Policy Staging'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory CentralAccessPolicyStagingFailure {
                Name      = 'Central Policy Staging'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory AuditPolicyChangeSuccess {
                Name      = 'Audit Policy Change'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory AuditPolicyChangeFailure {
                Name      = 'Audit Policy Change'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory AuthenticationPolicyChangeSuccess {
                Name      = 'Authentication Policy Change'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory AuthenticationPolicyChangeFailure {
                Name      = 'Authentication Policy Change'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory AuthorizationPolicyChangeSuccess {
                Name      = 'Authorization Policy Change'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory AuthorizationPolicyChangeFailure {
                Name      = 'Authorization Policy Change'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory MPSSVCRule-LevelPolicyChangeSuccess {
                Name      = 'MPSSVC Rule-Level Policy Change'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory MPSSVCRule-LevelPolicyChangeFailure {
                Name      = 'MPSSVC Rule-Level Policy Change'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherPolicyChangeEventsSuccess {
                Name      = 'Other Policy Change Events'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherPolicyChangeEventsFailure {
                Name      = 'Other Policy Change Events'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory NonSensitivePrivilegeUseSuccess {
                Name      = 'Non Sensitive Privilege Use'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory NonSensitivePrivilegeUseFailure {
                Name      = 'Non Sensitive Privilege Use'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherPrivilegeUseEventsSuccess {
                Name      = 'Other Privilege Use Events'
                AuditFlag = 'Success'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory OtherPrivilegeUseEventsFailure {
                Name      = 'Other Privilege Use Events'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory SensitivePrivilegeUseSuccess {
                Name      = 'Sensitive Privilege Use'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SensitivePrivilegeUseFailure {
                Name      = 'Sensitive Privilege Use'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecDriverSuccess {
                Name      = 'IPsec Driver'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory IPsecDriverFailure {
                Name      = 'IPsec Driver'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherSystemEventsSuccess {
                Name      = 'Other System Events'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory OtherSystemEventsFailure {
                Name      = 'Other System Events'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SecurityStateChangeSuccess {
                Name      = 'Security State Change'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SecurityStateChangeFailure {
                Name      = 'Security State Change'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory SecuritySystemExtensionSuccess {
                Name      = 'Security System Extension'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SecuritySystemExtensionFailure {
                Name      = 'Security System Extension'
                AuditFlag = 'Failure'
                Ensure    = 'Absent'
            }
            AuditPolicySubcategory SystemIntegritySuccess {
                Name      = 'System Integrity'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }
            AuditPolicySubcategory SystemIntegrityFailure {
                Name      = 'System Integrity'
                AuditFlag = 'Failure'
                Ensure    = 'Present'
            }
        }
    }
}

#==================================================
# DSC Local Configuration Manager
#==================================================

[DSCLocalConfigurationManager()]
Configuration LCM {
    Node LocalHost {
        Settings {
            RefreshMode                    = 'Push'
            ConfigurationModeFrequencyMins = 15
            RebootNodeIfNeeded             = $RebootNodeIfNeeded
            ConfigurationMode              = 'ApplyAndAutoCorrect'
            ActionAfterReboot              = 'ContinueConfiguration'
            StatusRetentionTimeInDays      = 15
        }
        PartialConfiguration AwsDriversInstall {
            RefreshMode = 'Push'
            Description = 'Ensures AWS Drivers are Up to Date'
        }
        PartialConfiguration CipherSuitesDsc {
            RefreshMode = 'Push'
            Description = 'Setting Certain Cipher Suites'
        }
        PartialConfiguration ComputerConfig {
            RefreshMode = 'Push'
            Description = 'Setting various system settings'
        }
        PartialConfiguration DisabledServicesDsc {
            RefreshMode = 'Push'
            Description = 'Disable Certain Services'
        }
        PartialConfiguration EnabledServicesDsc {
            RefreshMode = 'Push'
            Description = 'Enable Certain Services'
        }
        PartialConfiguration NetworkConfig {
            RefreshMode = 'Push'
            Description = 'Setting various network settings'
        }
        PartialConfiguration RegistrySettingsDscNewModule {
            RefreshMode = 'Push'
            Description = 'Setting Certain Registry Keys'
        }
        PartialConfiguration RegistrySettingsDscOldModule {
            RefreshMode = 'Push'
            Description = 'Setting Certain Registry Keys'
        }
        PartialConfiguration SChannelDsc {
            RefreshMode = 'Push'
            Description = 'Setting various SChannel settings'
        }
        PartialConfiguration SoftwareInstall {
            RefreshMode = 'Push'
            Description = 'Ensures AWS Software is Up to Date'
        }
        PartialConfiguration WindowsFeaturesDsc {
            RefreshMode = 'Push'
            Description = 'Ensure Features are not installed'
        }
        If ($AmIaDC) {
            PartialConfiguration DcAdvAudit {
                RefreshMode = 'Push'
                Description = 'Ensures Advance Audit Policy is Set'
            }
        }
    }
}

#==================================================
# Main
#==================================================

$DscPath = Join-Path -Path 'C:\' -ChildPath 'Scripts\DSC'

$Null = LCM -OutputPath $DscPath

Try {
    Set-DscLocalConfigurationManager -Path $DscPath -Force -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to set DSC local configuration manager $_"
    Exit 1
}

$PartialConfigs = @(
    'AwsDriversInstall'
    'CipherSuitesDsc'
    'ComputerConfig'
    'DisabledServicesDsc'
    'EnabledServicesDsc'
    'NetworkConfig'
    'RegistrySettingsDscNewModule'
    'RegistrySettingsDscOldModule'
    'SChannelDsc'
    'SoftwareInstall'
    'WindowsFeaturesDsc'
    If ($AmIaDC) {
        'DcAdvAudit'
    }
)

Foreach ($PartialConfig in $PartialConfigs) {
    $Null = & $PartialConfig -OutputPath "$DscPath\$PartialConfig"
    Try {
        Publish-DscConfiguration -Path "$DscPath\$PartialConfig" -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to published DSC configuration $_"
        Exit 1
    }
}

Try {
    Start-DscConfiguration -UseExisting -Force -Wait -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to start DSC configuration $_"
    Exit 1
}