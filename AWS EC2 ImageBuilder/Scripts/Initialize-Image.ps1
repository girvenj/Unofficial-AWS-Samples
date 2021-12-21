#==================================================
# Functions
#==================================================

Function Set-ModulePath {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][String]$Path
    )
    $ModulePaths = $Env:PsModulePath.split(';')
    If ($ModulePaths -NotContains $Path) {
        [Environment]::SetEnvironmentVariable('PsModulePath', "$Env:PsModulePath;$Path", 'Machine')
        $Env:PsModulePath = $Env:PsModulePath + ";$Path"
    }
}

#==================================================
# Main
#==================================================

'[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12' | Out-File -FilePath 'C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1'

$Folders = @(
    'ConfigFiles',
    'Logs',
    'Modules',
    'Scripts',
    'Temp'
)

Foreach ($Folder in $Folders) {
    $FolderPath = Join-Path -Path 'C:\' -ChildPath $Folder
    If ((Test-Path -Path $FolderPath) -and $Folder -eq 'Modules') {
        Set-ModulePath -Path $FolderPath
    } ElseIf (-not (Test-Path -Path $FolderPath)) {
        Write-Output "Creating $Folder directory"
        Try {
            $Null = New-Item -Path 'C:\' -Name $Folder -ItemType 'Directory' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to create $Folder directory $_"
            Exit 1
        }
        If ($Folder -eq 'Modules') {
            Set-ModulePath -Path $FolderPath
        }
    } 
}

Try {
    $OsInstall = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' -Name 'InstallationType' -ErrorAction Stop | Select-Object -ExpandProperty 'InstallationType'
} Catch [System.Exception] {
    Write-Output "Failed to get OS installation type $_"
    Exit 1
}

Write-Output 'Setting Windows features'
Try {
    $Null = Uninstall-WindowsFeature -Name 'Windows-Defender' -ErrorAction Stop
    $Null = Uninstall-WindowsFeature -Remove -Name 'FS-SMB1', 'PNRP', 'PowerShell-v2', 'Simple-TCPIP', 'Telnet-Client', 'Web-Ftp-Service' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to uninstall un-needed features $_"
    Exit 1
}
    
Try {
    $Null = Install-WindowsFeature -Name 'System-Insights', 'Windows-Server-Backup' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to install features $_"
    Exit 1
}

If ($OsInstall -eq 'Server') {
    Write-Output 'Disabling un-needed services'
    $Services = @(
        'NcbService',
        'TabletInputService'
    )
    Foreach ($Service in $Services) {
        Try {
            Set-Service -Name $Service -StartupType 'Disabled' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to set $Service to disabled $_"
            Exit 1
        }
    }

    Try {
        $Null = Uninstall-WindowsFeature -Name 'XPS-Viewer' -ErrorAction Stop
        $Null = Uninstall-WindowsFeature -Remove -Name 'Fax', 'TFTP-Client' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to uninstall not needed features $_"
        Exit 1
    }
}