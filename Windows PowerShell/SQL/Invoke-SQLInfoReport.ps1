<#
    .SYNOPSIS
    Invoke-SQLInfoReport.ps1

    .DESCRIPTION
    This script collects various information on Microsoft SQL Servers. If you pass in UserName, Password, DomainFQDN it will create a credential object.  
    It requires the SqlServer PowerShell Module and WMF5.1 to be installed.  If it creates a credential object it will use those creds to update the SQLServer PS module.
    
    Note, the SQLServer Powershell module needs to be at least major version 21, older versions will not work. 
    
    .EXAMPLE
    # Manually add servers
    .\Invoke-SQLInfoReport.ps1 -ServerName 'Server1', 'Server2' -ReportPath 'C:\Temp'

    # Pull servers from a list
    .\Invoke-SQLInfoReport.ps1 -ServerName (Get-Content -Path 'C:\Temp\Servers.csv') -ReportPath 'C:\Temp'
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][String[]]$ServerName,
    [Parameter(Mandatory = $true)][String]$ReportPath
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 


#==================================================
# Variables
#==================================================

$FilePath = Join-Path -Path $ReportPath -ChildPath "SQLReport$(Get-Random).JSON"

#==================================================
# Functions
#==================================================

Function Get-SQLServerPSModule {

    $CurrentPSVersion = $PSVersionTable.PSVersion
    [version]$DesiredPSVersion = '5.1.0.0'

    If ($CurrentPSVersion -lt $DesiredPSVersion) {
        Write-Output 'ERROR: WMF5.1 Not installed, see here for the installation file: https://www.microsoft.com/en-us/download/details.aspx?id=54616'
        Exit 1
    }

    $PPPresent = Get-PackageProvider -Name 'Nuget' -Force -ErrorAction SilentlyContinue
    If (-not $PPPresent) {
        Write-Output 'INFO: Installing the NuGet package provider'
        Try {
            $Null = Install-PackageProvider -Name 'NuGet' -MinimumVersion '2.8.5' -Force -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "ERROR: Failed to install NuGet package provider $_"
            Exit 1
        }
    }

    $PsRepPresent = Get-PSRepository -Name 'PSGallery' | Select-Object -ExpandProperty 'InstallationPolicy' -ErrorAction SilentlyContinue
    If ($PsRepPresent -ne 'Trusted') {
        Write-Output 'INFO: Setting PSGallery respository to trusted'
        Try {
            Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "ERROR: Failed to set PSGallery respository to trusted $_"
            Exit 1
        }
    }

    $ModPresent = Get-Module -Name 'SqlServer' -ListAvailable | Select-Object -ExpandProperty 'Version' | Select-Object -ExpandProperty 'Major'
    If (-not $ModPresent -or $ModPresent -lt 21) {
        Write-Output 'INFO: Downloading and installing the SQL Server PowerShell module'
        Try {
            Install-Module 'SqlServer' -AllowClobber -Force -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "ERROR: Failed to download and install the SQL Server PowerShell module $_"
            Exit 1
        }
    }
}

Function Get-SQLServerInfo { 
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][String]$Server
    )

    #=Variables=================================================

    $Counters = @(
        @{
            Label       = 'CPU Utilization'
            CounterName = '\Processor(_Total)\% Processor Time'
        },
        @{
            Label       = 'Available RAM'
            CounterName = '\Memory\Available MBytes'
        }
    )
    
    $InstProperties = @(
        'AvailabilityGroups',
        'Collation',
        'Configuration',
        'ClusterName',
        'ClusterQuorumType',
        'DatabaseEngineEdition',
        'Databases',
        'Edition',
        'FilestreamLevel',
        'InstanceName',
        'IsClustered',
        'IsFullTextInstalled',
        'IsHadrEnabled',
        'IsPolyBaseInstalled',
        'LinkedServers',
        'PerfMonMode',
        'Triggers',
        'Version',
        'VersionMajor'
    )


    $Query = @'
    WITH
        AGStatus
        AS
        
        (
            SELECT
                name as AGname,
                replica_server_name,
                CASE WHEN  (primary_replica  = replica_server_name) THEN  1
    ELSE  '' END AS IsPrimaryServer,
                secondary_role_allow_connections_desc AS ReadableSecondary,
                [availability_mode]  AS [Synchronous],
                failover_mode_desc
            FROM master.sys.availability_groups Groups
                INNER JOIN master.sys.availability_replicas Replicas ON Groups.group_id = Replicas.group_id
                INNER JOIN master.sys.dm_hadr_availability_group_states States ON Groups.group_id = States.group_id
        )
    Select
        [AGname],
        [Replica_server_name],
        [IsPrimaryServer],
        [Synchronous],
        [ReadableSecondary],
        [Failover_mode_desc]
    FROM AGStatus
    --WHERE
    --IsPrimaryServer = 1
    --AND Synchronous = 1
    ORDER BY
    AGname ASC,
    IsPrimaryServer DESC;
'@

    #=Main++++++================================================

    Write-Host "INFO ($Server): Getting system information"
    Try {
        $HardwareInfo = Get-CimInstance -ClassName 'Win32_ComputerSystem' -ComputerName $Server -ErrorAction Stop | Select-Object -Property 'Name', 'Manufacturer', 'Model', @{ Name = 'MemoryGB'; Expression = { $_.TotalPhysicalMemory / 1GB -as [int] } }
    } Catch [System.Exception] {
        Write-Output "ERROR ($Server): Failed to get system information $_"
        Exit 1
    }

    Switch ($HardwareInfo.Model) { 
        'Virtual Machine' { $Plat = 'Virtual' }  
        'VMware Virtual Platform' { $Plat = 'Virtual' } 
        'VirtualBox' { $Plat = 'Virtual' } 
        default { 
            Switch ($HardwareInfo.Manufacturer) { 
                'Amazon EC2' { $Plat = 'Virtual' }
                'Google' { $Plat = 'Virtual' }  
                'QEMU' { $Plat = 'Virtual' } 
                'Xen' { $Plat = 'Virtual' } 
                default { $Plat = 'Physical' } 
            } 
        } 
    }

    Write-Host "INFO ($Server): Getting CPU information"
    Try {
        $CPUInfo = Get-CimInstance -ClassName 'Win32_Processor' -ComputerName $Server -ErrorAction Stop | Select-Object -Property 'DeviceID', 'NumberOfLogicalProcessors', 'NumberOfCores', 'NumberOfEnabledCore', 'ThreadCount'
    } Catch [System.Exception] {
        Write-Output "ERROR ($Server): Failed to get CPU information $_"
        #Exit 1
    }

    Write-Host "INFO ($Server): Getting performance counters"
    [System.Collections.ArrayList]$PerfCounterArray = @()
    Foreach ($Counter in $Counters) {
        $Count = Get-Counter -Counter $Counter.CounterName -SampleInterval 10 -MaxSamples 6 -ComputerName $Server | Select-Object -ExpandProperty 'CounterSamples' | Select-Object -ExpandProperty 'CookedValue'
        $CountAvg = $Count | Measure-Object -Average | Select-Object -ExpandProperty 'Average'
        $CountMax = $Count | Measure-Object -Maximum | Select-Object -ExpandProperty 'Maximum'
        $PsObj = [PSCustomObject][Ordered]@{
            Name = $Counter.Label
            Avg  = $CountAvg
            Max  = $CountMax
        }
        [void]$PerfCounterArray.Add($PsObj)
    }

    Write-Host "INFO ($Server): Getting OS information"
    Try {
        $OSInfo = Get-CimInstance -ClassName 'Win32_OperatingSystem' -ComputerName $Server -ErrorAction Stop | Select-Object -ExpandProperty 'Caption'
    } Catch [System.Exception] {
        Write-Output "ERROR ($Server): Failed to get system information $_"
        #Exit 1
    }

    $Output = [Ordered]@{
        'Device Name'             = $Server
        'Operating System'        = $OSInfo
        'Socket Count'            = $CPUinfo.DeviceID.Count
        'Logical Processor Count' = $CPUinfo.NumberOfLogicalProcessors | Measure-Object -Sum | Select-Object -ExpandProperty 'Sum'
        'Total Cores'             = $CPUinfo.NumberOfCores | Measure-Object -Sum | Select-Object -ExpandProperty 'Sum'
        'Enabled Cores'           = $CPUinfo.NumberOfEnabledCore | Measure-Object -Sum | Select-Object -ExpandProperty 'Sum'
        'Thread Count'            = $CPUinfo.ThreadCount | Measure-Object -Sum | Select-Object -ExpandProperty 'Sum'
        'Avg CPU Util%'           = [math]::Round(($PerfCounterArray | Where-Object { $_.Name -eq 'CPU Utilization' } | Select-Object -ExpandProperty 'Avg'), 2)
        'Max CPU Util%'           = [math]::Round(($PerfCounterArray | Where-Object { $_.Name -eq 'CPU Utilization' } | Select-Object -ExpandProperty 'Max'), 2)
        'Total RAM (GB)'          = $HardwareInfo.MemoryGB
        'Avg Used RAM (GB)'       = [math]::Round((($HardwareInfo.MemoryGB) - ([int]($PerfCounterArray | Where-Object { $_.Name -eq 'Available RAM' } | Select-Object -ExpandProperty 'Avg') / 1024)), 2)
        'Max Used RAM (GB)'       = [math]::Round((($HardwareInfo.MemoryGB) - ([int]($PerfCounterArray | Where-Object { $_.Name -eq 'Available RAM' } | Select-Object -ExpandProperty 'Max') / 1024)), 2)
        'Platform'                = $Plat
        'Manufacturer'            = $HardwareInfo.Manufacturer
        'Model'                   = $HardwareInfo.Model
    }

    Write-Host "INFO ($Server): Getting SQL instance name(s)"
    Try {
        $Registry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Server)
        $RegistryKey = $Registry.OpenSubKey('Software\Microsoft\Microsoft SQL Server\')
        $Instances = $RegistryKey.GetValue('InstalledInstances')
    } Catch [System.Exception] {
        Write-Output "ERROR ($Server): Failed to get SQL instance name(s) $_"
        Exit 1
    }

    [System.Collections.ArrayList]$InstanceArray = @()
    ForEach ($Instance in $Instances) {
        If ($Instance -eq 'MSSQLSERVER') {
            $ServerInstance = $Server
        } Else {
            $ServerInstance = "$Server\$Instance"
        }

        Write-Host "INFO ($ServerInstance): Getting SQL instance information"
        Try {
            $SqlInstance = Get-SqlInstance -ServerInstance $ServerInstance -ErrorAction Stop | Select-Object -Property $InstProperties
        } Catch [System.Exception] {
            Write-Output "ERROR ($ServerInstance): Failed to get SQL instance information $_"
            #Exit 1
        }

        Switch ($SqlInstance.VersionMajor) {
            '9' { $SQLVer = 'Microsoft SQL Server 2005' }
            '10' { $SQLVer = 'Microsoft SQL Server 2008 / 2008 R2' }
            '11' { $SQLVer = 'Microsoft SQL Server 2012' }
            '12' { $SQLVer = 'Microsoft SQL Server 2014' }
            '13' { $SQLVer = 'Microsoft SQL Server 2016' }
            '14' { $SQLVer = 'Microsoft SQL Server 2017' }
            '15' { $SQLVer = 'Microsoft SQL Server 2019' }
            default { $SQLVer = 'Microsoft SQL Server older than 2005' } 
        }

        $Response = Invoke-Sqlcmd -Query $Query -ServerInstance $ServerInstance | Where-Object { $_.Replica_server_name -eq $ENV:COMPUTERNAME }

        If ($SqlInstance.ClusterName) {
            $ClusterName = $SqlInstance.ClusterName
        } Else {
            $ClusterName = 'N/A'
        }

        If ($SqlInstance.AvailabilityGroups | Select-Object -ExpandProperty 'Name') {
            $AgName = $SqlInstance.AvailabilityGroups | Select-Object -ExpandProperty 'Name'
        } Else {
            $AgName = 'N/A'
        }

        If ($SqlInstance.AvailabilityGroups | Select-Object -ExpandProperty 'PrimaryReplicaServerName') {
            $ReplicaName = $SqlInstance.AvailabilityGroups | Select-Object -ExpandProperty 'PrimaryReplicaServerName'
            If ($ReplicaName -eq $Env:COMPUTERNAME) {
                $Primary = 'Yes'
            } else {
                $Primary = 'No'
            }
            $PrimaryName = $ReplicaName
        } Else {
            $Primary = 'N/A'
            $PrimaryName = 'N/A'
        }

        If ($SqlInstance.AvailabilityGroups | Select-Object -ExpandProperty 'AvailabilityReplicas') {
            $AvailabilityReplicas = $SqlInstance.AvailabilityGroups | Select-Object -ExpandProperty 'AvailabilityReplicas'
        } Else {
            $AvailabilityReplicas = 'N/A'
        }

        If ([string]$SqlInstance.AvailabilityGroups.LocalReplicaRole) {
            $AgRole = [string]$SqlInstance.AvailabilityGroups.LocalReplicaRole
        } Else {
            $AgRole = 'N/A'
        }

        If ($SqlInstance.LinkedServers.Count -eq 0) { 
            $SqlLink = 'No'
        } Else { 
            $SqlLink = 'Yes'
        } 

        If ($SqlInstance.Triggers.Count -eq 0) { 
            $SqlLink = 'No'
        } Else { 
            $SqlLink = 'Yes'
        } 

        If ($SqlInstance.Configuration.XPCmdShellEnabled.ConfigValue = 1) { 
            $Xpenabled = 'Yes'
        } Else { 
            $Xpenabled = 'No'
        } 

        If ($SqlInstance.Configuration.IsSqlClrEnabled -eq $True) { 
            $Clr = 'Yes'
        } Else { 
            $Clr = 'No'
        }

        If ($SqlInstance.Databases.EncryptionEnabled -contains 'True') { 
            $EncryptionPresent = 'Yes'
        } Else { 
            $EncryptionPresent = 'No'
        }

        If ($SqlInstance.Databases.IsMirroringEnabled -contains 'True') { 
            $MirroringPresent = 'Yes'
        } Else { 
            $MirroringPresent = 'No'
        }

        If ($SqlInstance.Databases.ReplicationOptions -contains 'MergePublished' -or $SqlInstance.Databases.ReplicationOptions -contains 'MergeSubscribed' -or $SqlInstance.Databases.ReplicationOptions -contains 'Published' -or $SqlInstance.Databases.ReplicationOptions -contains 'Subscribed') { 
            $ReplicationPresent = 'Yes'
        } Else { 
            $ReplicationPresent = 'No'
        }

        $SumDbSize = 0
        $DbSize = $SqlInstance | Select-Object -ExpandProperty 'Databases' | Select-Object -ExpandProperty 'Size' 
        $DbSize | ForEach-Object { $SumDbSize += $_ }

        [void]$InstanceArray.Add("$Instance SQL Version : $SQLVer")
        [void]$InstanceArray.Add("$Instance SQL Version Number : $([string]$SqlInstance.Version)")
        [void]$InstanceArray.Add("$Instance SQL Edition : $([string]$SqlInstance.DatabaseEngineEdition)")
        [void]$InstanceArray.Add("$Instance SQL in a Failover Cluster : $($SqlInstance.IsClustered)")
        [void]$InstanceArray.Add("$Instance SQL is HA-DR : $($SqlInstance.IsHadrEnabled)")
        [void]$InstanceArray.Add("$Instance SQL Cluster Name : $ClusterName")
        [void]$InstanceArray.Add("$Instance SQL Quorum Type : $([string]$SqlInstance.ClusterQuorumType)")
        [void]$InstanceArray.Add("$Instance SQL Availability Group : $AgName")
        [void]$InstanceArray.Add("$Instance Is the SQL Availability Group Primary : $Primary")
        [void]$InstanceArray.Add("$Instance SQL Availability Group Primary : $PrimaryName")
        [void]$InstanceArray.Add("$Instance SQL Availability Group Replicas : $AvailabilityReplicas")
        [void]$InstanceArray.Add("$Instance SQL Availability Group Role : $AgRole")
        [void]$InstanceArray.Add("$Instance Is a SQL Availability Group Readable Secondary : $([string]$Response.ReadableSecondary)")
        [void]$InstanceArray.Add("$Instance SQL Availability Group Using Synchronous Replication : $([string]$Response.Synchronous)")
        [void]$InstanceArray.Add("$Instance SQL Availability Group Failover Mode : $([string]$Response.Failover_mode_desc)")
        [void]$InstanceArray.Add("$Instance SQL FileStream Status : $($SqlInstance.FilestreamLevel)")
        [void]$InstanceArray.Add("$Instance SQL PolyBase Status : $($SqlInstance.IsPolyBaseInstalled)")
        [void]$InstanceArray.Add("$Instance SQL FullText Status : $($SqlInstance.IsFullTextInstalled)")
        [void]$InstanceArray.Add("$Instance SQL PerfMonMode : $($SqlInstance | Select-Object -ExpandProperty 'PerfMonMode')")
        [void]$InstanceArray.Add("$Instance Lic SQL By : $($SqlInstance.Edition)")
        [void]$InstanceArray.Add("$Instance SQL Collation : $($SqlInstance.Collation)")
        [void]$InstanceArray.Add("$Instance SQL Max Server Mem in MB : $($SqlInstance.Configuration.MaxServerMemory.ConfigValue)")
        [void]$InstanceArray.Add("$Instance SQL Linked Servers : $SqlLink")
        [void]$InstanceArray.Add("$Instance SQL XP Cmd Shell Status : $Xpenabled")
        [void]$InstanceArray.Add("$Instance SQL CLR Status : $Clr")
        [void]$InstanceArray.Add("$Instance SQL DB Count : $($SqlInstance.Databases.Count)")
        [void]$InstanceArray.Add("$Instance SQL DB Encryption Present : $EncryptionPresent")
        [void]$InstanceArray.Add("$Instance SQL DB Mirroring Present : $MirroringPresent")
        [void]$InstanceArray.Add("$Instance SQL DB Replication Present : $ReplicationPresent")
        [void]$InstanceArray.Add("$Instance SQL Total DB Size MB : $SumDbSize")
    }
    [void]$Output.Add('Instance Info', $InstanceArray)

    Write-Host "INFO ($Server): Getting disk information"
    Try {
        $Volumes = Get-CimInstance -ClassName 'Win32_LogicalDisk' -Filter "DriveType = 3" -ComputerName $Server -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "ERROR ($Server): Failed to disk information $_"
        #Exit 1
    }

    [System.Collections.ArrayList]$DiskArray = @()
    Foreach ($Volume in $Volumes) {
        $VolLetter = $Volume | Select-Object -ExpandProperty 'DeviceID'
        $DiskSizeGB = $Volume | Select-Object -Property @{ Name = 'DiskSizeGB'; Expression = { $_.Size / 1GB -as [int] } } | Select-Object -ExpandProperty 'DiskSizeGB'
        $DiskFreeSpaceGB = $Volume | Select-Object -Property @{ Name = 'DiskFreeSpaceGB'; Expression = { [math]::Round($_.Freespace / 1GB, 2) } } | Select-Object -ExpandProperty 'DiskFreeSpaceGB'
        
        Try {
            $Partition = Get-CimAssociatedInstance -InputObject $Volume -ResultClass 'Win32_DiskPartition' -ComputerName $Server -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "ERROR ($Server): Failed to partition information $_"
            #Exit 1
        }
        
        Try {
            $DiskIndex = Get-CimAssociatedInstance -InputObject $Partition -ResultClassName 'Win32_DiskDrive' -ComputerName $Server -ErrorAction Stop | Select-Object -ExpandProperty 'Index'
        } Catch [System.Exception] {
            Write-Output "ERROR ($Server): Failed to disk index $_"
            #Exit 1
        }

        Try {
            $MediaType = Get-CimInstance -ClassName 'MSFT_physicaldisk' -Namespace 'root\Microsoft\Windows\Storage' -ComputerName $Server -ErrorAction Stop | Where-Object { $_.DeviceId -eq $DiskIndex } | Select-Object -ExpandProperty 'MediaType'
        } Catch [System.Exception] {
            Write-Output "ERROR ($Server): Failed to physical disk $_"
            #Exit 1
        }

        $PerfName = "$($DiskIndex) $VolLetter"

        Switch ($MediaType) { 
            '3' { $DiskType = 'HDD' }
            '4' { $DiskType = 'SSD' }
            '5' { $DiskType = 'SCM' }
            default { $DiskType = "Unspecified" } 
        }

        $Counters = @(
            @{
                Label       = 'Read Bytes'
                CounterName = "\PhysicalDisk($($PerfName))\Disk Read Bytes/sec"
            },
            @{
                Label       = 'Write Bytes'
                CounterName = "\PhysicalDisk($($PerfName))\Disk Write Bytes/sec"
            },
            @{
                Label       = 'Read IO'
                CounterName = "\PhysicalDisk($($PerfName))\Disk Reads/sec"
            },
            @{
                Label       = 'Write IO'
                CounterName = "\PhysicalDisk($($PerfName))\Disk Writes/sec"
            },
            @{
                Label       = 'Queue Length'
                CounterName = "\PhysicalDisk($($PerfName))\Avg. Disk Queue Length"
            }
        )

        [System.Collections.ArrayList]$DiskCounterArray = @()
        Foreach ($Counter in $Counters) {
            $Count = Get-Counter -Counter $Counter.CounterName -SampleInterval 10 -MaxSamples 6 -ComputerName $Server | Select-Object -ExpandProperty 'CounterSamples' | Select-Object -ExpandProperty 'CookedValue'
            $CountAvg = $Count | Measure-Object -Average | Select-Object -ExpandProperty 'Average'
            $CountMax = $Count | Measure-Object -Maximum | Select-Object -ExpandProperty 'Maximum'
            $PsObj = [PSCustomObject][Ordered]@{
                Name = $Counter.Label
                Avg  = $CountAvg
                Max  = $CountMax
            }
            [void]$DiskCounterArray.Add($PsObj)
        }

        [void]$DiskArray.Add("$VolLetter Storage Type : $DiskType")
        [void]$DiskArray.Add("$VolLetter Disk Size in GB : $DiskSizeGB")
        [void]$DiskArray.Add("$VolLetter Disk Free in GB : $DiskFreeSpaceGB")
        [void]$DiskArray.Add("$VolLetter Disk Free % : $([math]::Round((($DiskFreeSpaceGB / $DiskSizeGB) * 100), 2))")
        [void]$DiskArray.Add("$VolLetter Avg Read (MB/sec) : $([math]::Round(($DiskCounterArray | Where-Object { $_.Name -eq 'Read Bytes' } | Select-Object -ExpandProperty 'Avg')/1MB, 2))")
        [void]$DiskArray.Add("$VolLetter Max Read (MB/sec) : $([math]::Round(($DiskCounterArray | Where-Object { $_.Name -eq 'Read Bytes' } | Select-Object -ExpandProperty 'Max')/1MB, 2))")
        [void]$DiskArray.Add("$VolLetter Avg Write (MB/sec) : $([math]::Round(($DiskCounterArray | Where-Object { $_.Name -eq 'Write Bytes' } | Select-Object -ExpandProperty 'Avg')/1MB, 2))")
        [void]$DiskArray.Add("$VolLetter Max Write (MB/sec) : $([math]::Round(($DiskCounterArray | Where-Object { $_.Name -eq 'Write Bytes' } | Select-Object -ExpandProperty 'Max')/1MB, 2))")
        [void]$DiskArray.Add("$VolLetter Avg Read IOPS : $([math]::Round(($DiskCounterArray | Where-Object { $_.Name -eq 'Read IO' } | Select-Object -ExpandProperty 'Avg'), 2))")
        [void]$DiskArray.Add("$VolLetter Max Read IOPS : $([math]::Round(($DiskCounterArray | Where-Object { $_.Name -eq 'Read IO' } | Select-Object -ExpandProperty 'Max'), 2))")
        [void]$DiskArray.Add("$VolLetter Avg Write IOPS : $([math]::Round(($DiskCounterArray | Where-Object { $_.Name -eq 'Write IO' } | Select-Object -ExpandProperty 'Avg'), 2))")
        [void]$DiskArray.Add("$VolLetter Max Write IOPS : $([math]::Round(($DiskCounterArray | Where-Object { $_.Name -eq 'Write IO' } | Select-Object -ExpandProperty 'Max'), 2))")
        [void]$DiskArray.Add("$VolLetter Avg Average Disk Queue Length : $([math]::Round(($DiskCounterArray | Where-Object { $_.Name -eq 'Queue Length' } | Select-Object -ExpandProperty 'Avg'), 5))")
        [void]$DiskArray.Add("$VolLetter Max Average Disk Queue Length : $([math]::Round(($DiskCounterArray | Where-Object { $_.Name -eq 'Queue Length' } | Select-Object -ExpandProperty 'Max'), 5))")
    }

    [void]$Output.Add('Disk Info', $DiskArray)

    Write-Host "INFO ($Server): Data gathering completed"

    $Output = [PSCustomObject]$Output
    Return $Output
}

#==================================================
# Main
#==================================================

$ModuleVersion = Get-Module -ListAvailable -Name 'SqlServer' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'Version' | Select-Object -ExpandProperty 'Major'
If ($ModuleVersion -lt '21' -and -not ($ModuleVersion -ge '21')) {
    Write-Output 'INFO: Installing the SQL Server PowerShell Module'
    Get-SQLServerPSModule
}

$FeaturePresent = Get-WindowsFeature -Name 'RSAT-Clustering' | Select-Object -ExpandProperty 'InstallState'
If ($FeaturePresent -ne 'Installed') {
    Write-Output 'INFO: Installing Windows Failover Clustering RSAT tools'
    Try {
        $Null = Install-WindowsFeature -Name 'RSAT-Clustering' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "ERROR: Failed to install Windows Failover Clustering RSAT tools $_"
        Exit 1
    }
}

$Pathpresent = Test-Path -Path $ReportPath

If (-not $Pathpresent) {
    Write-Output 'ERROR: Report path is missing'
    Exit 1
}

[System.Collections.ArrayList]$Jobs = @()
Foreach ($Server in $ServerName) {
    Write-Output "INFO ($Server): Data gathering starting"
    [void]$Jobs.Add($(Start-Job -ScriptBlock ${Function:Get-SQLServerInfo} -ArgumentList $Server))
}

[System.Collections.ArrayList]$Outputs = @()
Do {
    Start-Sleep 2
    ForEach ($Job in $Jobs.Clone()) {
        $JobStatus = Get-Job -Id $Job.Id
        If ($JobStatus.State -ne 'Running') {
            $Output = Receive-Job -Job $Job | Select-Object -Property '*' -ExcludeProperty 'PSComputerName', 'RunspaceID', 'PSShowComputerName'
            [void]$Outputs.Add($Output)
            Remove-Job -Job $Job
            $Jobs.Remove($Job)
        }
    }
} While ($Jobs)

$Outputs | ConvertTo-Json -Depth 5 | Out-File $FilePath
Write-Output "INFO: Data gathering completed"

Return $Output