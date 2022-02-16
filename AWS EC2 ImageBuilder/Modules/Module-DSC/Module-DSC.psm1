Enum Ensure {
    Absent
    Present
}

[DscResource()]
Class SetRC4Key {
    [DscProperty(Key)]
    [String] $Key

    [DscProperty(Mandatory)]
    [Ensure] $Ensure

    [DscProperty(Mandatory)]
    [String] $ValueName

    [DscProperty(Mandatory)]
    [String] $ValueType

    [DscProperty(Mandatory)]
    [String] $ValueData

    [SetRC4Key] Get() {
        $GetObject = [SetRC4Key]::New()
        $GetObject.Key = $This.Key
        $GetObject.ValueName = $This.ValueName
        $GetObject.ValueType = $This.ValueType
        $GetObject.ValueData = $This.ValueData

        $KeyPresent = Get-Item -Path "Registry::$($This.Key)" -ErrorAction SilentlyContinue
        If ($KeyPresent) {
            $ValuePresent = Get-ItemProperty -Path "Registry::$($This.Key)" -Name $This.ValueName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $This.ValueName
            If ($ValuePresent -eq $This.ValueData) {
                $GetObject.Ensure = [Ensure]::Present
                Write-Verbose -Message 'The registry key is present and set.'
            } Else {
                $GetObject.Ensure = [Ensure]::Absent
                Write-Verbose -Message 'The registry key is present and not set.'
            }
        } Else {
            $GetObject.Ensure = [Ensure]::Absent
            Write-Verbose -Message 'The registry key is missing.'
        }
        Return $GetObject
    }

    [Boolean] Test() {
        $TestObject = $This.Get()
        $Result = ($TestObject.Ensure -eq $This.Ensure)
        Return $Result
    }

    [Void] Set() {
        If ($This.Ensure -eq [Ensure]::Present) {
            Write-Verbose -Message "Setting registry key and value $($This.Key) & $($This.ValueName)"
            $KeyPresent = Get-Item -Path "Registry::$($This.Key)" -ErrorAction SilentlyContinue
            If (-not $KeyPresent) {
                $CiphersSubPath = $($This.Key).Substring($($This.Key).IndexOf('\') + 1)
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME)).CreateSubKey($CiphersSubPath) 
            }            
            $ValueNamePresent = Get-ItemProperty -Path "Registry::$($This.Key)" -Name $This.ValueName -ErrorAction SilentlyContinue    
            If (-not $ValueNamePresent) {
                New-ItemProperty -Path "Registry::$($This.Key)" -Name $This.ValueName -Value $This.ValueData -PropertyType $This.ValueType
            } 
            $ValuePresent = Get-ItemProperty -Path "Registry::$($This.Key)" -Name $This.ValueName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $This.ValueName 
            If ($ValuePresent -ne $This.ValueData) {
                Set-ItemProperty -Path "Registry::$($This.Key)" -Name $This.ValueName -Value $This.ValueData
            } 
        } Else {
            Write-Verbose -Message "Removing registry key and value $($This.Key) & $($This.ValueName)"
            Remove-ItemProperty -Path "Registry::$($This.Key)" -Name $This.ValueName 
        }        
    }
}

[DscResource()]
Class RegistryKeyAndValue {
    [DscProperty(Key)]
    [String] $Key

    [DscProperty(Mandatory)]
    [Ensure] $Ensure

    [DscProperty(Mandatory)]
    [String] $ValueName

    [DscProperty(Mandatory)]
    [String] $ValueType

    [DscProperty(Mandatory)]
    [String] $ValueData

    [RegistryKeyAndValue] Get() {
        $GetObject = [RegistryKeyAndValue]::New()
        $GetObject.Key = $This.Key
        $GetObject.ValueName = $This.ValueName
        $GetObject.ValueType = $This.ValueType
        $GetObject.ValueData = $This.ValueData

        $KeyPresent = Get-Item -Path "Registry::$($This.Key)" -ErrorAction SilentlyContinue
        If ($KeyPresent) {
            $ValuePresent = Get-ItemProperty -Path "Registry::$($This.Key)" -Name $This.ValueName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $This.ValueName
            If ($ValuePresent -eq $This.ValueData) {
                $GetObject.Ensure = [Ensure]::Present
                Write-Verbose -Message 'The registry key is present and set.'
            } Else {
                $GetObject.Ensure = [Ensure]::Absent
                Write-Verbose -Message 'The registry key is present and not set.'
            }
        } Else {
            $GetObject.Ensure = [Ensure]::Absent
            Write-Verbose -Message 'The registry key is missing.'
        }
        Return $GetObject
    }

    [Boolean] Test() {
        $TestObject = $This.Get()
        $Result = ($TestObject.Ensure -eq $This.Ensure)
        Return $Result
    }

    [Void] Set() {
        If ($This.Ensure -eq [Ensure]::Present) {
            Write-Verbose -Message "Setting registry key and value $($This.Key) & $($This.ValueName)"
            $KeyPresent = Get-Item -Path "Registry::$($This.Key)" -ErrorAction SilentlyContinue
            If (-not $KeyPresent) {
                $CiphersSubPath = $($This.Key).Substring($($This.Key).IndexOf('\') + 1)
                ([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME)).CreateSubKey($CiphersSubPath) 
            }            
            $ValueNamePresent = Get-ItemProperty -Path "Registry::$($This.Key)" -Name $This.ValueName -ErrorAction SilentlyContinue    
            If (-not $ValueNamePresent) {
                New-ItemProperty -Path "Registry::$($This.Key)" -Name $This.ValueName -Value $This.ValueData -PropertyType $This.ValueType
            } 
            $ValuePresent = Get-ItemProperty -Path "Registry::$($This.Key)" -Name $This.ValueName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $This.ValueName 
            If ($ValuePresent -ne $This.ValueData) {
                Set-ItemProperty -Path "Registry::$($This.Key)" -Name $This.ValueName -Value $This.ValueData -Force
            } 
        } Else {
            Write-Verbose -Message "Removing registry key and value $($This.Key) & $($This.ValueName)"
            Remove-ItemProperty -Path "Registry::$($This.Key)" -Name $This.ValueName 
        }        
    }
}

[DscResource()]
Class SetCipherSuite {
    [DscProperty(Key)]
    [String] $ValueName

    [DscProperty(Mandatory)]
    [Ensure] $Ensure

    [SetCipherSuite] Get() {
        $GetObject = [SetCipherSuite]::New()
        $GetObject.ValueName = $This.ValueName

        $CipherPresent = Get-TlsCipherSuite -Name $This.ValueName -ErrorAction SilentlyContinue
        If ($CipherPresent) {
            $GetObject.Ensure = [Ensure]::Present
            Write-Verbose -Message 'The cipher suite is present'
        } Else {
            $GetObject.Ensure = [Ensure]::Absent
            Write-Verbose -Message 'The cipher suite is not present'
        }
        Return $GetObject
    }

    [Boolean] Test() {
        $TestObject = $This.Get()
        $Result = ($TestObject.Ensure -eq $This.Ensure)
        Return $Result
    }

    [Void] Set() {
        If ($This.Ensure -eq [Ensure]::Present) {
            Write-Verbose -Message "Enabling cipher suite $($This.ValueName)"
            Enable-TlsCipherSuite -Name $This.ValueName
        } Else {
            Write-Verbose -Message "Disabling cipher suite $($This.ValueName)"
            Disable-TlsCipherSuite -Name $This.ValueName
        }        
    }
}

[DscResource()]
Class AwsDriverPnPInstaller {
    [DscProperty(Key)]
    [String] $DeviceName
    
    [DscProperty(Mandatory)]
    [String] $DriverVersion

    [DscProperty(Mandatory)]
    [Ensure] $Ensure

    [DscProperty(Mandatory)]
    [String] $URL
    
    [AwsDriverPnPInstaller] Get() {
        $GetObject = [AwsDriverPnPInstaller]::New()
        $GetObject.DeviceName = $This.DeviceName
        $GetObject.DriverVersion = $This.DriverVersion
        $GetObject.URL = $This.URL

        $DriverInstalled = Get-CimInstance -Class 'Win32_PnPSignedDriver' -ErrorAction SilentlyContinue | Where-Object { $_.DeviceName -eq $This.DeviceName } | Select-Object 'DeviceName', 'Manufacturer', 'DriverVersion'
        If ($DriverInstalled) {
            If ($DriverInstalled.Count -ge 2) {
                $DriverInstalled = $DriverInstalled[0]
            }
            $GetObject.DriverVersion = $DriverInstalled.DriverVersion
            If ([version]($GetObject.DriverVersion) -ge [version]($This.DriverVersion)) {
                $GetObject.Ensure = [Ensure]::Present
                Write-Verbose -Message "AWS Driver version $($GetObject.DriverVersion) is installed."
            } Else {
                $GetObject.Ensure = [Ensure]::Absent
                Write-Verbose -Message "Found AWS Driver version $($GetObject.DriverVersion) which does not match the desired version $($This.DriverVersion)."
            }
        } Else {
            $GetObject.Ensure = [Ensure]::Absent
            Write-Verbose -Message "AWS Driver is not installed."
        }
        Return $GetObject
    }

    [Boolean] Test() {
        $TestObject = $This.Get()
        $Result = ($TestObject.Ensure -eq $This.Ensure)
        Return $Result
    }

    [Void] Set() {
        $Device = $This.DeviceName

        (New-Object -TypeName 'System.Net.WebClient').DownloadFile($This.Url, "C:\Temp\$Device.zip")
        Expand-Archive -LiteralPath "C:\Temp\$Device.zip" -DestinationPath "C:\Temp\$Device-Driver" -Force
        $InfFile = Get-ChildItem -Path "C:\Temp\$Device-Driver" -Filter '*.inf' | Select-Object -ExpandProperty 'FullName'

        If ($This.Ensure -eq [Ensure]::Present) {
            Write-Verbose -Message 'Installing AWS Driver'
            $ArgumentList = "/add-driver `"$InfFile`"", '/install'

        } Else {
            Write-Verbose -Message 'Removing AWS Driver'
            $ArgumentList = "/delete-driver `"$InfFile`"", '/uninstall', '/reboot'
        }

        $pnputilProc = Start-Process -FilePath 'pnputil.exe' -ArgumentList $ArgumentList -PassThru -Wait
    }
}

[DscResource()]
Class AwsDriverPvInstaller {
    [DscProperty(Key)]
    [String] $DeviceName
    
    [DscProperty(Mandatory)]
    [String] $DriverVersion

    [DscProperty(Mandatory)]
    [Ensure] $Ensure

    [DscProperty(Mandatory)]
    [String] $URL
    
    [AwsDriverPvInstaller] Get() {
        $GetObject = [AwsDriverPvInstaller]::New()
        $GetObject.DeviceName = $This.DeviceName
        $GetObject.DriverVersion = $This.DriverVersion
        $GetObject.URL = $This.URL

        $DriverName = $This.DeviceName
        $DriverInstalled = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $DriverName } | Select-Object -ExpandProperty 'DisplayVersion'
        If ($DriverInstalled) {
            $GetObject.DriverVersion = $DriverInstalled
            If ([version]($GetObject.DriverVersion) -ge [version]($This.DriverVersion)) {
                $GetObject.Ensure = [Ensure]::Present
                Write-Verbose -Message "AWS PV Driver version $($GetObject.DriverVersion) is installed."
            } Else {
                $GetObject.Ensure = [Ensure]::Absent
                Write-Verbose -Message "Found AWS PV Driver version $($GetObject.DriverVersion) which does not match the desired version $($This.DriverVersion)."
            }
        } Else {
            $GetObject.Ensure = [Ensure]::Absent
            Write-Verbose -Message 'AWS PV Driver is not installed.'
        }
        Return $GetObject
    }

    [Boolean] Test() {
        $TestObject = $This.Get()
        $Result = ($TestObject.Ensure -eq $This.Ensure)
        Return $Result
    }

    [Void] Set() {
        $Device = $This.DeviceName
        $LogFilePath = Join-Path -Path 'C:\Temp' -ChildPath "$Device.log"
        Write-Verbose -Message "The AWS PV Driver installation will log to the file '$LogFilePath'."

        (New-Object -TypeName 'System.Net.WebClient').DownloadFile($This.Url, "C:\Temp\$Device.zip")
        Expand-Archive -LiteralPath "C:\Temp\$Device.zip" -DestinationPath "C:\Temp\$Device-Driver" -Force
        $InstallFile = Get-ChildItem -Path "C:\Temp\$Device-Driver" -Filter '*.msi' | Select-Object -ExpandProperty 'FullName'
        If ($This.Ensure -eq [Ensure]::Present) {
            Write-Verbose -Message 'Installing AWS PV Drivers'
            $ArgumentList = "/i `"$InstallFile`"", '/quiet', '/norestart', "/l*v `"$LogFilePath`""
        } Else {
            Write-Verbose -Message 'Removing AWS PV Drivers'
            $ArgumentList = "/uninstall `"$InstallFile`"", '/quiet', "/l*v `"$LogFilePath`""
        }
        
        $Process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $ArgumentList -NoNewWindow -Wait -PassThru
        $Null
    }
}

[DscResource()]
Class ExeInstaller {
    [DscProperty(Key)]
    [String] $SoftWareName
    
    [DscProperty(Mandatory)]
    [String] $SoftwareVersion

    [DscProperty(Mandatory)]
    [Ensure] $Ensure

    [DscProperty(Mandatory)]
    [String] $URL
    
    [ExeInstaller] Get() {
        $GetObject = [ExeInstaller]::New()
        $GetObject.SoftWareName = $This.SoftWareName
        $GetObject.SoftwareVersion = $This.SoftwareVersion
        $GetObject.URL = $This.URL

        $SofName = $This.SoftWareName
        $ExeInstalled = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -eq $SofName } | Select-Object -ExpandProperty 'DisplayVersion'
        If ($ExeInstalled) {
            $GetObject.SoftwareVersion = $ExeInstalled
            If ([version]($GetObject.SoftwareVersion) -ge [version]($This.SoftwareVersion)) {
                $GetObject.Ensure = [Ensure]::Present
                Write-Verbose -Message "The $SofName version $($GetObject.SoftwareVersion) is installed."
            } Else {
                $GetObject.Ensure = [Ensure]::Absent
                Write-Verbose -Message "Found $SofName version $($GetObject.SoftwareVersion) which does not match the desired version $($This.SoftwareVersion)."
            }
        } Else {
            $GetObject.Ensure = [Ensure]::Absent
            Write-Verbose -Message "$SofName is not installed."
        }
        Return $GetObject
    }

    [Boolean] Test() {
        $TestObject = $This.Get()
        $Result = ($TestObject.Ensure -eq $This.Ensure)
        Return $Result
    }

    [Void] Set() {
        $SofName = $This.SoftWareName
        $LogFilePath = Join-Path -Path 'C:\Temp' -ChildPath "$SofName.log"
        Write-Verbose -Message "The $SofName installation will log to the file '$LogFilePath'."

        (New-Object -TypeName 'System.Net.WebClient').DownloadFile($This.Url, "C:\Temp\$SofName.exe")
        $InstallFile = "C:\Temp\$SofName.exe"
        If ($This.Ensure -eq [Ensure]::Present) {
            Write-Verbose -Message "Installing $SofName"
            $ArgumentList = '/quiet', "/l*v `"$LogFilePath`""
        } Else {
            Write-Verbose -Message "Removing $SofName"
            $ArgumentList = '/uninstall', '/quiet', "/l*v `"$LogFilePath`""
        }
        
        $Process = Start-Process -FilePath $InstallFile -ArgumentList $ArgumentList -NoNewWindow -Wait
        $Null
    }
}

[DscResource()]
Class MsiInstaller {
    [DscProperty(Key)]
    [String] $SoftWareName
    
    [DscProperty(Mandatory)]
    [String] $SoftwareVersion

    [DscProperty(Mandatory)]
    [Ensure] $Ensure

    [DscProperty(Mandatory)]
    [String] $URL
    
    [MsiInstaller] Get() {
        $GetObject = [MsiInstaller]::New()
        $GetObject.SoftWareName = $This.SoftWareName
        $GetObject.SoftwareVersion = $This.SoftwareVersion
        $GetObject.URL = $This.URL

        $SofName = $This.SoftWareName
        $MsiInstalled = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -eq $SofName } | Select-Object -ExpandProperty 'DisplayVersion'
        If ($MsiInstalled) {
            $GetObject.SoftwareVersion = $MsiInstalled
            If ([version]($GetObject.SoftwareVersion) -ge [version]($This.SoftwareVersion)) {
                $GetObject.Ensure = [Ensure]::Present
                Write-Verbose -Message "The $SofName version $($GetObject.SoftwareVersion) is installed."
            } Else {
                $GetObject.Ensure = [Ensure]::Absent
                Write-Verbose -Message "Found $SofName version $($GetObject.SoftwareVersion) which does not match the desired version $($This.SoftwareVersion)."
            }
        } Else {
            $GetObject.Ensure = [Ensure]::Absent
            Write-Verbose -Message "$SofName is not installed."
        }
        Return $GetObject
    }

    [Boolean] Test() {
        $TestObject = $This.Get()
        $Result = ($TestObject.Ensure -eq $This.Ensure)
        Return $Result
    }

    [Void] Set() {
        $SofName = $This.SoftWareName
        $LogFilePath = Join-Path -Path 'C:\Temp' -ChildPath "$SofName.log"
        Write-Verbose -Message "The $SofName installation will log to the file '$LogFilePath'."

        (New-Object -TypeName 'System.Net.WebClient').DownloadFile($This.Url, "C:\Temp\$SofName.msi")
        $InstallFile = "C:\Temp\$SofName.msi"
        If ($This.Ensure -eq [Ensure]::Present) {
            Write-Verbose -Message "Installing $SofName"
            $ArgumentList = "/i `"$InstallFile`"", '/quiet', '/norestart', "/l*v `"$LogFilePath`""
        } Else {
            Write-Verbose -Message "Removing $SofName"
            $ArgumentList = "/uninstall `"$InstallFile`"", '/quiet', "/l*v `"$LogFilePath`""
        }
        
        $Process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $ArgumentList -NoNewWindow -Wait -PassThru
        $Null
    }
}

[DscResource()]
Class DotNetOfflineInstall {
    [DscProperty(Key)]
    [String] $KbId

    [DscProperty(Mandatory)]
    [Ensure] $Ensure

    [DscProperty(Mandatory)]
    [String] $URL
    
    [DotNetOfflineInstall] Get() {
        $GetObject = [DotNetOfflineInstall]::New()
        $GetObject.KbId = $This.KbId
        $GetObject.URL = $This.URL

        $KbInstalled = Get-HotFix -Id $This.KbId -ErrorAction SilentlyContinue
        If ($KbInstalled) {
            $GetObject.Ensure = [Ensure]::Present
            Write-Verbose -Message "Update $($GetObject.KbId) is installed"
        } Else {
            $GetObject.Ensure = [Ensure]::Absent
            Write-Verbose -Message "Update $($GetObject.KbId) is not installed."
        }
        Return $GetObject
    }

    [Boolean] Test() {
        $TestObject = $This.Get()
        
        $Result = ($TestObject.Ensure -eq $This.Ensure)

        Return $Result
    }

    [Void] Set() {
        $Kb = $This.KbId
        $LogFilePath = Join-Path -Path 'C:\Temp' -ChildPath "$Kb.log"
        Write-Verbose -Message "The $Kb installation will log to the file '$LogFilePath'."
        (New-Object -TypeName 'System.Net.WebClient').DownloadFile($This.Url, "C:\Temp\$Kb.exe")
        $InstallFile = "C:\Temp\$Kb.exe"
        If ($This.Ensure -eq [Ensure]::Present) {
            Write-Verbose -Message "Installing .Net Framework $Kb"
            $ArgumentList = '/q', '/norestart', "/log $LogFilePath"        
        } Else {
            Write-Verbose -Message "Removing .Net Framework $Kb"
            $ArgumentList = '/uninstall', '/q', "/log $LogFilePath"
        }
        
        $Process = Start-Process -FilePath $InstallFile -ArgumentList $ArgumentList -NoNewWindow -Wait
        $Null
    }
}

[DscResource()]
Class SetAdvAudit {
    [DscProperty(Key)]
    [String] $Category

    [DscProperty(Mandatory)]
    [String] $Setting

    [DscProperty(Mandatory)]
    [Ensure] $Ensure

    [SetAdvAudit] Get() {
        $GetObject = [SetAdvAudit]::New()
        $GetObject.Category = $This.Category
        $GetObject.Setting = $This.Setting
        [regex]$SettingRegex = "\s+$($This.Category)\s+$($This.Setting)$"
        $CatName = $This.Category
        $Cat = & Auditpol.exe /get /subcategory:$CatName
        $SettingPresent = $Cat | Select-String -Pattern $SettingRegex
        If ($SettingPresent) {
            $GetObject.Ensure = [Ensure]::Present
            Write-Verbose -Message 'The Advanced Audit Policy is set'
        } Else {
            $GetObject.Ensure = [Ensure]::Absent
            Write-Verbose -Message 'The Advanced Audit Policy is not set'
        }
        Return $GetObject
    }

    [Boolean] Test() {
        $TestObject = $This.Get()
        $Result = ($TestObject.Ensure -eq $This.Ensure)
        Return $Result
    }

    [Void] Set() {
        $CatName = $This.Category
        $CatSetting = $This.Setting
        If ($This.Ensure -eq [Ensure]::Present) {
            Write-Verbose -Message "Setting Active Directory advanced audititing $($This.CatName) and $($This.Setting)"
            $Param = $Null
            Switch ($CatSetting) {
                'Success' { $Param = '/success:enable /failure:disable' }
                'Failure' { $Param = '/success:disable /failure:enable' }
                'Success and Failure' { $Param = '/success:enable /failure:enable' }
                'No Auditing' { $Param = '/success:disable /failure:disable' }
                Default { Write-Verbose -Message 'No valid setting input' }
            }
            $ArgumentList = '/set', "/subcategory:`"$CatName`"", $Param
        } Else {
            Write-Verbose -Message "Disabling Active Directory advanced audititing $($This.CatName) and $($This.Setting)"
            $ArgumentList = '/set', "/subcategory:`"$CatName`"", '/success:disable', '/failure:disable'
        }  
        $Process = Start-Process -FilePath 'Auditpol.exe' -ArgumentList $ArgumentList -NoNewWindow -Wait -PassThru
        $Null
    }
}