$Process = Start-Process -NoNewWindow -PassThru -Wait -FilePath 'C:\Program Files\PowerShell\7\pwsh.exe' '-Command', {
    Function Start-PrimeNumberTest {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $True)][Int32]$TestRunLimit,  #The number of times the test will run in a loop
            [Parameter(Mandatory = $True)][Int32]$UpperNumberRange #The upper number of the range to find prime numbers in (larger the number the longer it takes to process)
        )
        $DoCount = 0
        $NumberRange = 2..$UpperNumberRange
        [System.Collections.ArrayList]$TimeArray = @()
        [System.Collections.ArrayList]$OutputArray = @()
        $vCPUCount = Get-CimInstance -ClassName 'Win32_Processor' | Select-Object -ExpandProperty 'NumberOfLogicalProcessors'
        Do {
            $Time = Measure-Command {
                $Range = $NumberRange
                $Count = 0
                $Range | ForEach-Object -Parallel {
                    $Number = $_
                    $Divisor = [Math]::Sqrt($Number)
                    2..$Divisor | ForEach-Object {
                        If ($Number % $_ -eq 0) {
                            $Prime = $False
                        } Else {
                            $Prime = $True
                        }
                    }
                    If ($Prime) {
                        $Count++
                        If ($Count % 10 -eq 0) {
                            $Null
                        }
                    }
                } -ThrottleLimit $vCPUCount
            }
            $DoCount++
            [void]$TimeArray.Add($Time.TotalSeconds)
            Start-Sleep -Seconds 5
        } Until ($DoCount -eq $TestRunLimit)
        $Output = $TimeArray | Measure-Object -Average -Maximum -Minimum | Select-Object -Property 'Count', 'Average', 'Maximum', 'Minimum'
        [void]$OutputArray.Add("Number of runs                     : $($Output.Count)")
        [void]$OutputArray.Add("Average time to complete (seconds) : $($Output.Average)")
        [void]$OutputArray.Add("Maximum time to complete (seconds) : $($Output.Maximum)")
        [void]$OutputArray.Add("Minimum time to complete (seconds) : $($Output.Minimum)")
        Write-Output $Output
    }
    Start-PrimeNumberTest -TestRunLimit '{{PrimeNumberTestRunLimit}}' -UpperNumberRange '{{PrimeNumberTestUpperNumberRange}}'
}
If ($Process.ExitCode -ne 0) {
    Write-Output "Error running PrimeNumberTest code $($Process.ExitCode)"
    Exit 1
}

$PrimeNumberTestResults = Invoke-Command -ScriptBlock {
    &'C:\Program Files\PowerShell\7\pwsh.exe' '-Command', {
        Function Start-PrimeNumberTest {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $True)][Int32]$TestRunLimit, #The number of times the test will run in a loop
                [Parameter(Mandatory = $True)][Int32]$UpperNumberRange #The upper number of the range to find prime numbers in (larger the number the longer it takes to process)
            )
            $DoCount = 0
            $NumberRange = 2..$UpperNumberRange
            [System.Collections.ArrayList]$TimeArray = @()
            [System.Collections.ArrayList]$OutputArray = @()
            $vCPUCount = Get-CimInstance -ClassName 'Win32_Processor' | Select-Object -ExpandProperty 'NumberOfLogicalProcessors'
            Do {
                $Time = Measure-Command {
                    $Range = $NumberRange
                    $Count = 0
                    $Range | ForEach-Object -Parallel {
                        $Number = $_
                        $Divisor = [Math]::Sqrt($Number)
                        2..$Divisor | ForEach-Object {
                            If ($Number % $_ -eq 0) {
                                $Prime = $False
                            } Else {
                                $Prime = $True
                            }
                        }
                        If ($Prime) {
                            $Count++
                            If ($Count % 10 -eq 0) {
                                $Null
                            }
                        }
                    } -ThrottleLimit $vCPUCount
                }
                $DoCount++
                [void]$TimeArray.Add($Time.TotalSeconds)
                Start-Sleep -Seconds 5
            } Until ($DoCount -eq $TestRunLimit)
            $Output = $TimeArray | Measure-Object -Average -Maximum -Minimum | Select-Object -Property 'Count', 'Average', 'Maximum', 'Minimum'
            Write-Output $Output.Count
            Write-Output $Output.Average
            Write-Output $Output.Maximum
            Write-Output $output.Minimum
        }
        Start-PrimeNumberTest -TestRunLimit 2 -UpperNumberRange 100
    }
}

Write-Output "Number of runs : $($PrimeNumberTestResults[0])"
Write-Output "Average time to complete (seconds): $($PrimeNumberTestResults[1])"
Write-Output "Maximum time to complete (seconds): $($PrimeNumberTestResults[2])"
Write-Output "Average time to complete (seconds): $($PrimeNumberTestResults[3])"



Try {
    [string]$Token = Invoke-RestMethod -Headers @{'X-aws-ec2-metadata-token-ttl-seconds' = '3600' } -Method 'PUT' -Uri 'http://169.254.169.254/latest/api/token' -UseBasicParsing -ErrorAction Stop
    $InstanceType = (Invoke-RestMethod -Headers @{'X-aws-ec2-metadata-token' = $Token } -Method 'GET' -Uri 'http://169.254.169.254/latest/dynamic/instance-identity/document' -UseBasicParsing -ErrorAction Stop | Select-Object -ExpandProperty 'instanceType').ToLower()
} Catch [System.Exception] {
    Write-Output "Failed to get region $_"
    Exit 1
}