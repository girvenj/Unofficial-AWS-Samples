#Requires -Modules 'AWS.Tools.Common', 'AWS.Tools.EC2', 'AWS.Tools.DirectoryService', 'AWS.Tools.IdentityManagement', 'AWS.Tools.Imagebuilder', 'AWS.Tools.Route53Resolver', 'AWS.Tools.SecretsManager', 'AWS.Tools.SimpleSystemsManagement'

Function Write-ToLog {
    [CmdletBinding()]
    Param (
        [parameter(Mandatory = $false)][Switch]$Exit,
        [parameter(Mandatory = $true)][String]$Message,
        [parameter(Mandatory = $true)][String]$Type
    )

    Switch ($Type) {
        'ERROR' { $Color = 'Red' }
        'WARN' { $Color = 'Yellow' }
        'INFO' { $Color = 'Green' }
        default { $Color = 'Gray' }
    }

    $Output = Write-Output "[$Type][$(Get-Date -Format 'yyyy-MM-dd-THH:mm:ss')]$Message"
    $Temp = Join-Path -Path "C:\" -ChildPath "Temp"
    If (-not (Test-Path -Path $Temp)) { New-Item -Path $Temp -ItemType 'Directory' }
    $Output | Out-File -FilePath "C:\Logs\LabBuild$(Get-Date -Format 'yyyy-MM-dd-THH').log" -Append -Encoding utf8 -ErrorAction Continue
    Write-Host -ForegroundColor $Color $Output
    If ($Exit) {
        Exit 1
    }
}

Function New-VPC {
    Param (
        [parameter(Mandatory = $true)][String]$Region,
        [parameter(Mandatory = $true)][String]$VpcCidr,
        [parameter(Mandatory = $true)][String]$VpcTagVal
    )
    
    Trap [System.Exception] {
        Write-Output $_.FullyQualifiedErrorId
        Write-Output $_.Exception.Message
        Write-Output $_.ScriptStackTrace
        Break
    }

    $NaclTagVal = "$VpcTagVal-NACL"
    $DNUTagVal = 'Do-Not-Use'
    
    $VpcId = New-EC2Vpc -CidrBloc $VpcCidr -Region $Region | Select-Object -ExpandProperty 'VpcId'
    $Null = Edit-EC2VpcAttribute -VpcId $VpcId -EnableDnsHostnames $True -Force -Region $Region 

    $NaclId = Get-EC2NetworkAcl -Filter @{ Name = 'vpc-id'; Values = $VpcId } -Region $Region | Select-Object -ExpandProperty 'NetworkAclId'
    $DefaultRtId = Get-EC2RouteTable -Filter @{ Name = 'vpc-id'; Values = "$VpcId" } -Region $Region | Select-Object -ExpandProperty 'RouteTableId'
    $SgId = Get-EC2SecurityGroup -Filter @{ Name = 'group-name'; Values = 'default' }, @{ Name = 'vpc-id'; Values = $VpcId } -Region $Region | Select-Object -ExpandProperty 'GroupId'

    [System.Collections.ArrayList]$Tags = @(
        @{
            Resource = $VpcId
            Tag      = $VpcTagVal 
        },
        @{
            Resource = $DefaultRtId
            Tag      = $DNUTagVal
        },
        @{
            Resource = $SgId
            Tag      = $DNUTagVal
        },
        @{
            Resource = $NaclId
            Tag      = $NaclTagVal
        }    
    ) 

    Foreach ($Tag in $Tags) {
        $TagValue = New-Object -TypeName 'Amazon.EC2.Model.Tag'
        $TagValue.Key = 'Name'
        $TagValue.Value = $Tag.Tag
        $Null = New-EC2Tag -Resource $Tag.Resource -Tag $TagValue -Region $Region  
    }
}

Function Get-VpcIdFromTag {
    [CmdletBinding()]
    Param (
        [parameter(Mandatory = $true)][String]$Region,
        [parameter(Mandatory = $true)][String]$VPCTag
    )
    
    Try {
        $VpcId = Get-EC2Vpc -Filter @{Name = 'tag:Name'; Values = $VPCTag } -Region $Region -ErrorAction Stop | Select-Object -ExpandProperty 'VpcId'
    } Catch [System.Exception] {
        Write-ToLog -Message "Failed to get VPC ID from VPC Name Tag. $_" -Type 'ERROR' -Exit
    } 

    Return $VpcId
}

Function New-PublicSubnet {
    [CmdletBinding()]
    Param (
        [String]$SubnetCidr,
        [String]$SubnetAz,
        [String]$VpcTagVal,
        [String]$Region
    )

    Trap [System.Exception] {
        Write-Output $_.FullyQualifiedErrorId
        Write-Output $_.Exception.Message
        Write-Output $_.ScriptStackTrace
        Break
    }

    $TagValue = New-Object -TypeName 'Amazon.EC2.Model.Tag'
    $TagValue.Key = 'Name'

    $VpcId = Get-VpcIdFromTag -Region $Region -VPCTag $VpcTagVal
    
    $Azs = Get-EC2AvailabilityZone -Region $Region
    $IgwId = Get-EC2InternetGateway -Filter @{ Name = 'attachment.vpc-id'; Values = $VpcId } -Region $Region | Select-Object -ExpandProperty 'InternetGatewayId'
    If ($IgwId) {
        $IgwRtId = Get-EC2RouteTable -Filter @{ Name = 'route.gateway-id'; Values = $IgwId } -Region $Region | Select-Object -ExpandProperty 'RouteTableId'
    } Else {
        $IgwId = New-EC2InternetGateway -Force -Region $Region | Select-Object -ExpandProperty 'InternetGatewayId'
        $Null = Add-EC2InternetGateway -VpcId $VpcId -InternetGatewayId $IgwId -Force -Region $Region
        $IgwRtId = New-EC2RouteTable -VpcId $VpcId -Region $Region | Select-Object -ExpandProperty 'RouteTableId'
        $Null = New-EC2Route -RouteTableId $IgwRtId -DestinationCidrBlock '0.0.0.0/0' -GatewayId $IgwId -Force -Region $Region
        $Vals = @(
            @{
                Resource = $IgwId
                TagValue = "$VpcTagVal-IGW"
            },
            @{    
                Resource = $IgwRtId
                TagValue = "$VpcTagVal-IGW-RTB"
            }          
        )
        Foreach ($Val in $Vals) {
            $TagValue.Value = $Val.TagValue
            $Null = New-EC2Tag -Resource $Val.Resource -Tag $TagValue -Region $Region  
        }
    }
    If ($SubnetAz) {
        $AZ = $SubnetAz
    } Else {
        $AZ = Get-Random $Azs.zonename
    }
    $SubnetID = New-EC2Subnet -VpcId $VpcId -CidrBloc $SubnetCidr -AvailabilityZone $AZ -Region $Region | Select-Object -ExpandProperty 'SubnetId'
    $Null = Edit-EC2SubnetAttribute -SubnetId $SubnetID -MapPublicIpOnLaunch $True -Force -Region $Region
    $Null = Register-EC2RouteTable -RouteTableId $IgwRtId -SubnetId $SubnetId -Region $Region
    $TagValue.Value = "$VpcTagVal-IGW-SUBNET-$SubnetCidr"
    $Null = New-EC2Tag -Resource $SubnetID -Tag $TagValue -Region $Region  
}

Function New-NatSubnet {
    [CmdletBinding()]
    Param (
        [String]$SubnetCidr,
        [String]$SubnetAz,
        [String]$VpcTagVal,
        [String]$Region
    )

    Trap [System.Exception] {
        Write-Output $_.FullyQualifiedErrorId
        Write-Output $_.Exception.Message
        Write-Output $_.ScriptStackTrace
        Break
    }

    $VpcId = Get-VpcIdFromTag -Region $Region -VPCTag $VpcTagVal
    
    $Azs = Get-EC2AvailabilityZone -Region $Region
    $TagValue = New-Object -TypeName 'Amazon.EC2.Model.Tag'
    $TagValue.Key = 'Name'
    If ($SubnetAz) {
        $AZ = $SubnetAz
    } Else {
        $AZ = Get-Random $Azs.zonename
    }
    $IgwSubnetID = Get-EC2Subnet -Filter @{ Name = 'availability-zone'; Values = $AZ }, @{ Name = 'vpc-id'; Values = $VpcId } -Region $Region | Where-Object { $_.MapPublicIpOnLaunch -eq 'True' } | Select-Object -ExpandProperty 'SubnetId'
    If (-not $IgwSubnetID) {
        Write-Output 'No Public Subnet in this AZ, please create a public subnet in this AZ and try again'
        Break
    }
    $NatGwId = Get-EC2NatGateway -Filter @{ Name = 'subnet-id'; Values = $IgwSubnetID }, @{ Name = 'state'; Values = 'available' } -Region $Region | Select-Object -ExpandProperty 'NatGatewayId'
    If ($NatGwId) {
        $NatRtId = Get-EC2RouteTable -Filter @{ Name = 'route.nat-gateway-id'; Values = $NatGwId } -Region $Region | Select-Object -ExpandProperty 'RouteTableId'
    } Else {
        $Count = (Get-EC2NatGateway -Filter @{ Name = 'vpc-id'; Values = $VpcId }, @{ Name = 'state'; Values = 'available' } -Region $Region).Count
        $Number = 1 + $Count
        $EipAllocId = New-EC2Address -Domain 'Vpc' -Region $Region | Select-Object -ExpandProperty 'AllocationId'
        $NatGwId = New-EC2NatGateway -SubnetId $IgwSubnetID -AllocationId $EipAllocId -Region $Region | Select-Object -ExpandProperty 'NatGateway' | Select-Object -ExpandProperty 'NatGatewayId'
        Do { 
            $NatState = Get-EC2NatGateway -NatGatewayId $NatGwId -Region $Region -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'State' | Select-Object -ExpandProperty 'Value'
            If ($NatState -ne 'available') {
                Start-Sleep -Seconds 10
            }
        } Until ($NatState -eq 'available')
        $NatRtId = New-EC2RouteTable -VpcId $VpcId -Region $Region | Select-Object -ExpandProperty 'RouteTableId'
        $Null = New-EC2Route -RouteTableId $NatRtId -DestinationCidrBlock '0.0.0.0/0' -GatewayId $NatGwId -Force -Region $Region


        $Vals = @(
            @{
                Resource = $NatGwId
                TagValue = "$VpcTagVal-NAT0$Number"
            },
            @{    
                Resource = $NatRtId
                TagValue = "$VpcTagVal-NAT0$Number-RTB"
            },
            @{    
                Resource = $EipAllocId
                TagValue = "$VpcTagVal-NAT0$Number-EIP"
            }
        )
        Foreach ($Val in $Vals) {
            $TagValue.Value = $Val.TagValue
            $Null = New-EC2Tag -Resource $Val.Resource -Tag $TagValue -Region $Region  
        }
    }
    $SubnetID = New-EC2Subnet -VpcId $VpcId -CidrBloc $SubnetCidr -AvailabilityZone $AZ -Region $Region | Select-Object -ExpandProperty 'SubnetId'
    $Null = Edit-EC2SubnetAttribute -SubnetId $SubnetID -MapPublicIpOnLaunch $False -Force -Region $Region
    $Null = Register-EC2RouteTable -RouteTableId $NatRtId -SubnetId $SubnetId -Region $Region
    $TagValue.Value = "$VpcTagVal-NAT-SUBNET-$SubnetCidr"
    $Null = New-EC2Tag -Resource $SubnetID -Tag $TagValue -Region $Region  
}

Function New-PrivateSubnet {
    [CmdletBinding()]
    Param (
        [String]$SubnetCidr,
        [String]$SubnetAz,
        [String]$VpcTagVal,
        [String]$Region
    )

    Trap [System.Exception] {
        Write-Output $_.FullyQualifiedErrorId
        Write-Output $_.Exception.Message
        Write-Output $_.ScriptStackTrace
        Break
    }

    $VpcId = Get-VpcIdFromTag -Region $Region -VPCTag $VpcTagVal
    
    $Azs = Get-EC2AvailabilityZone -Region $Region
    $NrRtId = Get-EC2RouteTable -Filter @{ Name = 'tag:Name'; Values = "$VpcTagVal-NRT-RTB" } -Region $Region | Select-Object -ExpandProperty 'RouteTableId'
    $TagValue = New-Object -TypeName 'Amazon.EC2.Model.Tag'
    $TagValue.Key = 'Name'
    If (-not $NrRtId ) {
        $NrRtId = New-EC2RouteTable -VpcId $VpcId -Region $Region | Select-Object -ExpandProperty 'RouteTableId'
        $Val = @{    
            Resource = $NrRtId
            TagValue = "$VpcTagVal-NRT-RTB"
        }          
        $TagValue.Value = $Val.TagValue
        $Null = New-EC2Tag -Resource $Val.Resource -Tag $TagValue -Region $Region  
    }

    If ($SubnetAz) {
        $AZ = $SubnetAz
    } Else {
        $AZ = Get-Random $Azs.zonename
    }
    $SubnetID = New-EC2Subnet -VpcId $VpcId -CidrBloc $SubnetCidr -AvailabilityZone $AZ -Region $Region | Select-Object -ExpandProperty 'SubnetId'
    $Null = Edit-EC2SubnetAttribute -SubnetId $SubnetID -MapPublicIpOnLaunch $False -Force -Region $Region
    $Null = Register-EC2RouteTable -RouteTableId $NrRtId -SubnetId $SubnetId -Region $Region
    $TagValue.Value = "$VpcTagVal-NRT-SUBNET-$SubnetCidr"
    $Null = New-EC2Tag -Resource $SubnetID -Tag $TagValue -Region $Region  
}

Function Get-SubnetIdFromTag {
    [CmdletBinding()]
    Param (
        [parameter(Mandatory = $true)][String]$Region,
        [parameter(Mandatory = $true)][String]$SubnetTag
    )

    Try {
        $SubnetIdsInfo = Get-EC2Subnet -Filter @{ Name = 'tag:Name'; Values = $SubnetTag } -Region $Region -ErrorAction Stop | Select-Object -ExpandProperty 'SubnetId'
    } Catch [System.Exception] {
        Write-ToLog -Message "Failed to get Subnet ID from Subnet Name Tag. $_" -Type 'ERROR' -Exit
    } 

    Return $SubnetIdsInfo
}

Function New-PrefixList {
    [CmdletBinding()]
    Param (
        [String]$PrefixListName,
        [parameter(Mandatory = $true)][ValidateSet('IPv4', 'IPv6')][String]$AddressFamily,
        [String]$CIDR,
        [String]$CIDRDescription,
        [Int]$MaxEntry,
        [String]$Region

    )
    $PrefixListEntry = New-Object -TypeName 'Amazon.EC2.Model.AddPrefixListEntry'
    $PrefixListEntry.Cidr = $CIDR
    $PrefixListEntry.Description = $CIDRDescription
    
    $Tag = @{ Key = 'Name'; Value = $PrefixListName }
    $TagSpec = New-Object -TypeName 'Amazon.EC2.Model.TagSpecification'
    $TagSpec.ResourceType = 'prefix-list'
    $TagSpec.Tags.Add($Tag)

    $Null = New-EC2ManagedPrefixList -PrefixListName $PrefixListName -AddressFamily $AddressFamily -Entry $PrefixListEntry -MaxEntry $MaxEntry -TagSpecification $TagSpec -Force -Region $Region
}

Function New-SecurityGroup {
    Param (
        [parameter(Mandatory = $true)][String]$Region,
        [parameter(Mandatory = $true)][String]$VpcTagVal,
        [parameter(Mandatory = $true)][String]$GroupName,
        [parameter(Mandatory = $true)][String]$Description,
        [parameter(Mandatory = $true)][ValidateSet('tcp', 'udp', 'icmp', 'icmpv6', '-1')][String]$IpProtocol,
        [parameter(Mandatory = $true)][Int]$FromPort,
        [parameter(Mandatory = $true)][Int]$ToPort,
        [parameter(Mandatory = $true)][ValidateSet('PrefixListIds', 'IpRanges')][String]$SourceType,
        [parameter(Mandatory = $False)][String[]]$Sources
    )
    
    Trap [System.Exception] {
        Write-Output $_.FullyQualifiedErrorId
        Write-Output $_.Exception.Message
        Write-Output $_.ScriptStackTrace
        Break
    }

    $VpcId = Get-VpcIdFromTag -Region $Region -VPCTag $VpcTagVal
    
    $SgID = Get-EC2SecurityGroup -Filter @{ Name = 'vpc-id'; Values = $VpcId }, @{ Name = 'group-name'; Values = "$VpcTagVal-$GroupName" } -Region $Region | Select-Object -ExpandProperty 'GroupId'
    If (-not $SgID) {
        $SgID = New-EC2SecurityGroup -GroupName "$VpcTagVal-$GroupName" -Description $Description -VpcId $VpcId -Region $Region
        $TagValue = New-Object -TypeName 'Amazon.EC2.Model.Tag'
        $TagValue.Key = 'Name'
        $TagValue.Value = "$VpcTagVal-$GroupName"
        $Null = New-EC2Tag -Resource $SgID -Tag $TagValue -Region $Region  
    }

    [regex]$PlRegex = '\bpl-\b'
    [regex]$PlVpcRegex = '\bLocal&Trusted-PL\b'
    $Resources = $Null

    Switch ($Sources) {
        'CorpPrefixList' {
            Switch ($Region) {
                # https://code.amazon.com/packages/RIPStaticConfig/blobs/mainline/--/lib/amazon/rip/impl/services/internalprefixlists.rb
                # Corp Only
                'af-south-1' { $Pls = 'pl-6da54004' }
                'ap-east-1' { $Pls = 'pl-9ba643f2' }
                'ap-northeast-1' { $Pls = 'pl-bea742d7' }
                'ap-northeast-2' { $Pls = 'pl-8fa742e6' }
                'ap-northeast-3' { $Pls = 'pl-42a6432b' }
                'ap-south-1' { $Pls = 'pl-f0a04599' }
                'ap-southeast-1' { $Pls = 'pl-60a74209' }
                'ap-southeast-2' { $Pls = 'pl-04a7426d' }
                'ap-southeast-3' { $Pls = 'pl-95a643fc' }
                'ca-central-1' { $Pls = 'pl-85a742ec' }
                'cn-north-1' { $Pls = 'pl-90a045f9' }
                'cn-northwest-1' { $Pls = 'pl-b5a540dc' }
                'eu-central-1' { $Pls = 'pl-19a74270' }
                'eu-north-1' { $Pls = 'pl-c2aa4fab' }
                'eu-south-1' { $Pls = 'pl-6ca54005' }
                'eu-west-1' { $Pls = 'pl-01a74268' }
                'eu-west-2' { $Pls = 'pl-fca24795' }
                'eu-west-3' { $Pls = 'pl-7dac4914' }
                'me-south-1' { $Pls = 'pl-85a643ec' }
                'sa-east-1' { $Pls = 'pl-a6a742cf' }
                'us-east-1' { $Pls = 'pl-60b85b09' }
                'us-east-2' { $Pls = 'pl-3ea44157' }
                'us-gov-east-1' { $Pls = 'pl-41826728' }
                'us-gov-west-1' { $Pls = 'pl-b2a540db' }
                'us-west-1' { $Pls = 'pl-a4a742cd' }
                'us-west-2' { $Pls = 'pl-f8a64391' }
            }
        }
        'VpcCIDR' {
            $Resources = Get-EC2Vpc -Filter @{ Name = 'tag:Name'; Values = $VpcTagVal } -Region $Region | Select-Object -ExpandProperty 'CidrBlock'
        }
        ($Sources -match $PlRegex) {
            $Pls = $Sources
        }
        ($Sources -match $PlVpcRegex) {
            $Pls = Get-EC2ManagedPrefixList -Filter @{ Name = 'prefix-list-name'; Values = $Sources } -Region $Region | Select-Object -ExpandProperty 'PrefixListId'
        }
    }

    Switch ($SourceType) {
        'PrefixListIds' {
            $Type = 'ip-permission.prefix-list-id'
            [System.Collections.ArrayList]$Resources = @()
            Foreach ($Pl in $Pls) {
                $Resource = New-Object -TypeName 'Amazon.EC2.Model.PrefixListId'
                $Resource.Id = $Pl
                [void]$Resources.add($Resource)
            }
        }
        'IpRanges' {
            $Type = 'ip-permission.cidr'
        }
    }
    If (-not $Resources) {
        $Resources = $Sources
    }

    Foreach ($Res in $Resources) {
        $RulePres = Get-EC2SecurityGroup -Filter @{ Name = 'ip-permission.from-port'; Values = $FromPort }, @{ Name = 'ip-permission.to-port'; Values = $ToPort }, @{ Name = 'ip-permission.protocol'; Values = $IpProtocol }, @{ Name = 'group-id'; Values = $SgID }, @{ Name = $Type; Values = $Res } -Region $Region 
        If (-not $RulePres) {
            Switch ($IpProtocol) {
                '-1' { $IpPermission = @{ IpProtocol = $IpProtocol; $SourceType = $Res } }
                Default { $IpPermission = @{ IpProtocol = $IpProtocol; FromPort = $FromPort; ToPort = $ToPort; $SourceType = $Res } }
            }
            $Null = Grant-EC2SecurityGroupIngress -GroupId $SgID -IpPermission $IpPermission -Region $Region -ErrorAction SilentlyContinue   
        }
    }
}

Function Get-SgIdFromTag {
    [CmdletBinding()]
    Param (
        [parameter(Mandatory = $true)][String]$Region,
        [parameter(Mandatory = $true)][String]$SecurityGroupTag
    )

    Try {
        $SgIdInfo = Get-EC2SecurityGroup -Filter @{ Name = 'tag:Name'; Values = $SecurityGroupTag } -Region $Region -ErrorAction Stop | Select-Object -ExpandProperty 'GroupId'
    } Catch [System.Exception] {
        Write-ToLog -Message "Failed to get Security Group ID from Security Group Name Tag. $_" -Type 'ERROR' -Exit
    } 

    Return $SgIdInfo
}

Function New-PeeringConnection {
    Param (
        [parameter(Mandatory = $true)][String]$HomeRegion,
        [parameter(Mandatory = $true)][String]$HomeVpcTagVal,
        [parameter(Mandatory = $true)][String]$PeerVpcTagVal,
        [parameter(Mandatory = $true)][String]$PeerRegion,
        [parameter(Mandatory = $False)][String]$HomePrefixListName,
        [parameter(Mandatory = $False)][String]$PeerPrefixListName
    )

    Trap [System.Exception] {
        Write-Output $_.FullyQualifiedErrorId
        Write-Output $_.Exception.Message
        Write-Output $_.ScriptStackTrace
        Break
    }

    Function Get-VpcInfo {
        Param (
            [String]$Region,
            [String]$VpcTagVal
        )
        $VPC = Get-EC2Vpc -Filter @{ Name = 'tag:Name'; Values = "$VpcTagVal" } -Region $Region
        Return $Vpc
    }
    $HomeVpcInfo = Get-VpcInfo -VpcTagVal $HomeVpcTagVal -Region $HomeRegion 
    $PeerVPCInfo = Get-VpcInfo -VpcTagVal $PeerVpcTagVal -Region $PeerRegion

    $HomeVpcId = $HomeVpcInfo | Select-Object -ExpandProperty 'VpcId'
    $PeerVpcId = $PeerVPCInfo | Select-Object -ExpandProperty 'VpcId'
    $HomeVpcCidr = $HomeVpcInfo | Select-Object -ExpandProperty 'CidrBlock'
    $PeerVpcCidr = $PeerVPCInfo | Select-Object -ExpandProperty 'CidrBlock'

    $PeeringCon = New-EC2VpcPeeringConnection -VpcId $HomeVpcId -PeerVpcId $PeerVpcId -PeerRegion $PeerRegion -Force -Region $HomeRegion | Select-Object 'VpcPeeringConnectionId' -ExpandProperty 'VpcPeeringConnectionId'
    Start-Sleep -Seconds 10
    $Null = Approve-EC2VpcPeeringConnection -VpcPeeringConnectionId $PeeringCon -Force -Region $PeerRegion 

    $SecurityGroups = @(
        @{
            VpcId      = $HomeVpcId
            VpcTag     = $PeerVpcTagVal
            Cidr       = $PeerVpcCidr
            GroupName  = "$HomeVpcTagVal-SG-All-In-VPC"
            Region     = $HomeRegion
            PrefixList = $HomePrefixListName
        },
        @{
            VpcId      = $PeerVpcId
            VpcTag     = $HomeVpcTagVal
            Cidr       = $HomeVpcCidr
            GroupName  = "$PeerVpcTagVal-SG-All-In-VPC"
            Region     = $PeerRegion
            PrefixList = $PeerPrefixListName
        }
    )

    Foreach ($SecurityGroup in $SecurityGroups) {
        $SecurityGroupInfo = Get-EC2SecurityGroup -Filter @{ Name = 'group-name'; Values = $SecurityGroup.GroupName } -Region $SecurityGroup.Region | Select-Object -ExpandProperty 'GroupId'
        If ($HomePrefixListName -and $PeerPrefixListName) {
            $Pl = Get-EC2ManagedPrefixList -Filter @{ Name = 'prefix-list-name'; Values = $SecurityGroup.PrefixList } -Region $SecurityGroup.Region
            $PlId = $Pl | Select-Object -ExpandProperty 'PrefixListId'
            $PlVersion = $Pl | Select-Object -ExpandProperty 'Version'
            $PrefixListEntry = New-Object -TypeName 'Amazon.EC2.Model.AddPrefixListEntry'
            $PrefixListEntry.Cidr = $SecurityGroup.Cidr
            $PrefixListEntry.Description = "The $($SecurityGroup.VpcTag) CIDR Range"
            Edit-EC2ManagedPrefixList -PrefixListId $PlId -AddEntry $PrefixListEntry -CurrentVersion $PlVersion -Force -Region $SecurityGroup.Region
            $PrefixList = New-Object -TypeName 'Amazon.EC2.Model.PrefixListId'
            $PrefixList.Id = $Pl
            $CidrRange = @{ IpProtocol = '-1'; PrefixListIds = $PrefixList }
        } Else {
            $CidrRange = @{ IpProtocol = '-1'; IpRanges = $SecurityGroup.Cidr }
            $Null = Grant-EC2SecurityGroupIngress -GroupId $SecurityGroupInfo -IpPermission $CidrRange -Region $SecurityGroup.Region
        }
    }

    [System.Collections.ArrayList]$HomeRoutesIds = @()
    [System.Collections.ArrayList]$PeerRoutesIds = @()

    $RouteTypes = @(
        @{
            TagValue = 'NRT'
            VpcValue = $HomeVpcId
            Array    = 'HomeRoutesIds'
            Region   = $HomeRegion
        },
        @{
            TagValue = 'NAT'
            VpcValue = $HomeVpcId
            Array    = 'HomeRoutesIds'
            Region   = $HomeRegion
        },
        @{
            TagValue = 'IGW'
            VpcValue = $HomeVpcId
            Array    = 'HomeRoutesIds'
            Region   = $HomeRegion
        },
        @{
            TagValue = 'NRT'
            VpcValue = $PeerVpcId
            Array    = 'PeerRoutesIds'
            Region   = $PeerRegion
        },
        @{
            TagValue = 'NAT'
            VpcValue = $PeerVpcId
            Array    = 'PeerRoutesIds'
            Region   = $PeerRegion
        },
        @{
            TagValue = 'IGW'
            VpcValue = $PeerVpcId
            Array    = 'PeerRoutesIds'
            Region   = $PeerRegion
        }
    )

    ForEach ($RouteType in $RouteTypes) {
        $Rts = Get-EC2RouteTable -Filter @{ Name = 'tag:Name'; Values = "*$($RouteType.TagValue)*-RTB" }, @{ Name = 'vpc-id'; Values = $RouteType.VpcValue } -Region $RouteType.Region | Select-Object -ExpandProperty 'RouteTableId'
        If ($Rts.count -gt 1) {
            Foreach ($Rt in $Rts) {
                Switch ($RouteType.Array) {
                    'HomeRoutesIds' { [void]$HomeRoutesIds.Add($Rt) }
                    'PeerRoutesIds' { [void]$PeerRoutesIds.Add($Rt) }
                }
            }
        } Elseif ($Rts.count -eq 1) {
            Switch ($RouteType.Array) {
                'HomeRoutesIds' { [void]$HomeRoutesIds.Add($Rts) }
                'PeerRoutesIds' { [void]$PeerRoutesIds.Add($Rts) }
            }
        }
    }

    [System.Collections.ArrayList]$Routes = @()

    Foreach ($HomeRoutesId in $HomeRoutesIds) {
        $HomeRoute = @{
            RouteTableId         = $HomeRoutesId
            DestinationCidrBlock = $PeerVpcCidr
            GatewayId            = $PeeringCon
            Region               = $HomeRegion
        }
        [void]$Routes.Add($HomeRoute)
    }

    Foreach ($PeerRoutesId in $PeerRoutesIds) {
        $PeerRoute = @{
            RouteTableId         = $PeerRoutesId
            DestinationCidrBlock = $HomeVpcCidr
            GatewayId            = $PeeringCon
            Region               = $PeerRegion
        }
        [void]$Routes.Add($PeerRoute)
    }

    Foreach ($Route in $Routes) {
        $Null = New-EC2Route -RouteTableId $Route.RouteTableId -DestinationCidrBlock $Route.DestinationCidrBlock -GatewayId $Route.GatewayId -Force -Region $Route.Region
    }

    $TagValue = New-Object -TypeName 'Amazon.EC2.Model.Tag'
    $TagValue.Key = 'Name'
    $TagValue.Value = "$HomeVpcTagVal&$PeerVpcTagVal-Peer"
    $Null = New-EC2Tag -Resource $PeeringCon -Tag $TagValue -Region $HomeRegion
    If ($HomeRegion -ne $PeerRegion) {
        $TagValue.Value = "$PeerVpcTagVal&$HomeVpcTagVal-Peer"
        $Null = New-EC2Tag -Resource $PeeringCon -Tag $TagValue -Region $HomeRegion
    }
}

Function New-LabInstance {
    Param (
        [parameter(Mandatory = $true)][Bool]$AssociatePublicIp,
        [parameter(Mandatory = $true)][String]$InstanceType,
        [parameter(Mandatory = $true)][String]$Subnet,
        [parameter(Mandatory = $true)][String]$Region,
        [parameter(Mandatory = $true)][String]$VolumeSize,
        [parameter(Mandatory = $true)][String]$NameTagValue,
        [parameter(Mandatory = $true)][String]$PrivateIpAddress,
        [parameter(Mandatory = $true)][String]$KeyName,
        [parameter(Mandatory = $true)][String]$OSType,
        [parameter(Mandatory = $true)][String[]]$SecurityGroups,
        [parameter(Mandatory = $false)][String]$RoleName,
        [parameter(Mandatory = $false)][String]$Encrypted,
        [parameter(Mandatory = $false)][String]$KmsKey,
        [parameter(Mandatory = $false)][HashTable[]]$AdditionalInstanceTags
    )

    Trap [System.Exception] {
        Write-Output $_.FullyQualifiedErrorId
        Write-Output $_.Exception.Message
        Write-Output $_.ScriptStackTrace
        Break
    }

    Switch ($OSType) {
        'Full2019Ec2Generic' { $ImageId = Get-SSMLatestEC2Image -Path 'ami-windows-latest' -ImageName 'Windows_Server-2019-English-Full-Base' -Region $Region }
        'Core2019Ec2Generic' { $ImageId = Get-SSMLatestEC2Image -Path 'ami-windows-latest' -ImageName 'Windows_Server-2019-English-Core-Base' -Region $Region }
        'Full2022Ec2Generic' { $ImageId = Get-SSMLatestEC2Image -Path 'ami-windows-latest' -ImageName 'Windows_Server-2022-English-Full-Base' -Region $Region }
        'Core2022Ec2Generic' { $ImageId = Get-SSMLatestEC2Image -Path 'ami-windows-latest' -ImageName 'Windows_Server-2022-English-Core-Base' -Region $Region }
        'Full2019ImageBuilder' { $ImageId = Get-EC2Image -Owner 'self' -Filter @{ Name = 'tag:Name'; Values = 'Windows-Server-2019-Full-Template' } -Region $Region | Sort-Object -Property 'CreationDate' -Descending | Select-Object -First '1' | Select-Object -ExpandProperty 'ImageId' }
        'Core2019ImageBuilder' { $ImageId = Get-EC2Image -Owner 'self' -Filter @{ Name = 'tag:Name'; Values = 'Windows-Server-2019-Core-Template' } -Region $Region | Sort-Object -Property 'CreationDate' -Descending | Select-Object -First '1' | Select-Object -ExpandProperty 'ImageId' }
        'Full2022ImageBuilder' { $ImageId = Get-EC2Image -Owner 'self' -Filter @{ Name = 'tag:Name'; Values = 'Windows-Server-2022-Full-Template' } -Region $Region | Sort-Object -Property 'CreationDate' -Descending | Select-Object -First '1' | Select-Object -ExpandProperty 'ImageId' }
        'Core2022ImageBuilder' { $ImageId = Get-EC2Image -Owner 'self' -Filter @{ Name = 'tag:Name'; Values = 'Windows-Server-2022-Core-Template' } -Region $Region | Sort-Object -Property 'CreationDate' -Descending | Select-Object -First '1' | Select-Object -ExpandProperty 'ImageId' }
        Default { Throw 'InvalidArgument: Invalid value is passed for parameter Type' }
    }

    [System.Collections.ArrayList]$TagSpecifications = @()
    $NameTagKp = @{ Key = 'Name'; Value = $NameTagValue }

    $TagSpecInstance = New-Object -TypeName 'Amazon.EC2.Model.TagSpecification'
    $TagSpecInstance.ResourceType = 'Instance'
    $TagSpecInstance.Tags.Add($NameTagKp)
    [void]$TagSpecifications.Add($TagSpecInstance)

    $TagSpecVolume = New-Object -TypeName 'Amazon.EC2.Model.TagSpecification'
    $TagSpecVolume.ResourceType = 'Volume'
    $TagSpecVolume.Tags.Add($NameTagKp)
    [void]$TagSpecifications.Add($TagSpecVolume)

    $EbsSettings = New-Object -TypeName 'Amazon.EC2.Model.EbsBlockDevice'
    $EbsSettings.VolumeSize = $VolumeSize
    $EbsSettings.Iops = '3000'
    $EbsSettings.Throughput = '125'
    $EbsSettings.VolumeType = 'gp3'
    $EbsSettings.DeleteOnTermination = 'True'
    If ($Encrypted -and $KmsKey) {
        $KmsKeyId = Get-KMSAliasList -Region $Region | Where-Object { $_.AliasName -eq "alias/$KmsKey" } | Select-Object -ExpandProperty 'TargetKeyId'
        $EbsSettings.Encrypted = $Encrypted
        $EbsSettings.KmsKeyId = $KmsKeyId
    }
    $EbsInfo = New-Object -TypeName 'Amazon.EC2.Model.BlockDeviceMapping'
    $EbsInfo.DeviceName = '/dev/sda1'
    $EbsInfo.Ebs = $EbsSettings

    If ($Subnet -match '^subnet-[a-zA-Z0-9]{17}$' -or $Subnet -match '^subnet-[a-zA-Z0-9]{8}$') {
        $SubnetId = $Subnet
    } Else {
        $SubnetId = Get-SubnetIdFromTag -Region $Region -SubnetTag $Subnet
    }
    
    [System.Collections.ArrayList]$SecurityGroupIds = @()
    Foreach ($SecurityGroup in $SecurityGroups) {
        If ($SecurityGroup -match '^sg-[a-zA-Z0-9]{17}$' -or $SecurityGroup -match '^sg-[a-zA-Z0-9]{8}$') {
            [void]$SecurityGroupIds.Add($SecurityGroup)
        } Else { 
            $SecurityGroupInfo = Get-SgIdFromTag -Region $Region -SecurityGroupTag $SecurityGroup  
            [void]$SecurityGroupIds.Add($SecurityGroupInfo)
        }
    }

    If ($RoleName) {
        $InstanceId = New-EC2Instance -ImageId $ImageId -AssociatePublicIp $AssociatePublicIp -InstanceType $InstanceType -BlockDeviceMapping $EbsInfo -SubnetId $SubnetId -PrivateIpAddress $PrivateIpAddress -SecurityGroupId $SecurityGroupIds -KeyName $KeyName -Monitoring $True -InstanceProfile_Name $RoleName -TagSpecification $TagSpecifications -Region $Region | Select-Object -ExpandProperty 'Instances' | Select-Object -ExpandProperty 'InstanceId'
    } Else {
        $InstanceId = New-EC2Instance -ImageId $ImageId -AssociatePublicIp $AssociatePublicIp -InstanceType $InstanceType -BlockDeviceMapping $EbsInfo -SubnetId $SubnetId -PrivateIpAddress $PrivateIpAddress -SecurityGroupId $SecurityGroupIds -KeyName $KeyName -Monitoring $True -TagSpecification $TagSpecifications -Region $Region | Select-Object -ExpandProperty 'Instances' | Select-Object -ExpandProperty 'InstanceId'
    }

    Start-Sleep -Seconds '5'

    $EniId = Get-EC2Instance -InstanceId $InstanceId -Region $Region | Select-Object -ExpandProperty 'Instances' | Select-Object -ExpandProperty 'NetworkInterfaces' | Select-Object -ExpandProperty 'NetworkInterfaceId'
    $EniTagVal = New-Object -TypeName 'Amazon.EC2.Model.Tag'
    $ENITagVal.Key = 'Name'
    $EniTagVal.Value = $NameTagValue
    New-EC2Tag -Resource $EniId -Tag $EniTagVal -Region $Region  

    If ($AdditionalInstanceTags) {
        Foreach ($AdditionalInstanceTag in $AdditionalInstanceTags) {
            $TagVal = New-Object -TypeName 'Amazon.EC2.Model.Tag'
            $TagVal.Key = $AdditionalInstanceTag.Key
            $TagVal.Value = $AdditionalInstanceTag.Value
            New-EC2Tag -Resource $InstanceId -Tag $TagVal -Region $Region  
        }
    }
}

Function Get-LabInstancesPW {
    Param (
        [parameter(Mandatory = $true)][String]$Region,
        [parameter(Mandatory = $true)][String]$TagValue,
        [parameter(Mandatory = $true)][String]$PemFile 
    )

    Trap [System.Exception] {
        Write-Output $_.FullyQualifiedErrorId
        Write-Output $_.Exception.Message
        Write-Output $_.ScriptStackTrace
        Break
    }

    $InstanceID = Get-EC2Instance -Filter @{Name = 'tag:Name'; Values = $TagValue } -Region $Region | Select-Object -ExpandProperty 'Instances' | Select-Object -ExpandProperty 'InstanceId'
    $InstancePw = Get-EC2PasswordData -InstanceId $InstanceID -PemFile $PemFile -Region $Region
    Write-Output "$($TagValue), $InstancePw"
}

Function New-NewMadDomain {
    Param (
        [parameter(Mandatory = $true)][String]$Description,
        [parameter(Mandatory = $true)][String]$FQDN,
        [parameter(Mandatory = $true)][String]$NetBios,
        [parameter(Mandatory = $true)][String]$Password,
        [parameter(Mandatory = $true)][String]$Region,
        [parameter(Mandatory = $true)][String[]]$Subnets,
        [parameter(Mandatory = $true)][String]$Verison,
        [parameter(Mandatory = $true)][String]$VPC
    )

    Trap [System.Exception] {
        Write-Output $_.FullyQualifiedErrorId
        Write-Output $_.Exception.Message
        Write-Output $_.ScriptStackTrace
        Break
    }

    $SecretString = '{"UserName":"Admin","Password":"PlaceHolder"}'
    $SecretString = $SecretString.Replace('PlaceHolder', $Password)
    $Secret = New-SECSecret -Name $Description -SecretString $SecretString -Region $Region | Select-Object -ExpandProperty 'ARN'

    If ($VPC -match '^vpc-[a-zA-Z0-9]{17}$' -or $VPC -match '^vpc-[a-zA-Z0-9]{8}$') {
        $VpcId = $VPC
    } Else {
        $VpcId = Get-VpcIdFromTag -Region $Region -VPCTag $VPC
    }

    [System.Collections.ArrayList]$SubnetIds = @()
    Foreach ($Subnet in $Subnets) {
        If ($Subnet -match '^subnet-[a-zA-Z0-9]{17}$' -or $Subnet -match '^subnet-[a-zA-Z0-9]{8}$') {
            [void]$SubnetIds.Add($Subnet)
        } Else {
            $SubnetIdsInfo = Get-SubnetIdFromTag -Region $Region -SubnetTag $Subnet
            [void]$SubnetIds.Add($SubnetIdsInfo)
        }
    }

    $Edition = New-Object -TypeName 'Amazon.DirectoryService.DirectoryEdition' -ArgumentList $Verison
    $TagSpec = New-Object -TypeName 'Amazon.DirectoryService.Model.Tag'
    $TagSpec.Key = 'Name'
    $TagSpec.Value = $Description

    Try {
        $DirectoryId = New-DSMicrosoftAD -Name $FQDN -Description $Description -Edition $Edition -Password $Password -ShortName $NetBios -VpcSettings_SubnetId $SubnetIds -Tag $TagSpec -VpcSettings_VpcId $VpcId -Force -Region $Region -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -Message "Failed to created new AWS Managed Microsoft Active Directory. $_" -Type 'ERROR' -Exit
    }

    Start-Sleep -Seconds 60
    
    $CidrRange = @{ IpProtocol = "-1"; IpRanges = '0.0.0.0/0' }
    Try {
        $SecurityGroupId = Get-EC2SecurityGroup -Filter @{ Name = 'group-name'; Values = "$($DirectoryId)_controllers" } -Region $Region -ErrorAction Stop | Select-Object -Property 'GroupId' -ExpandProperty 'GroupId'
        Grant-EC2SecurityGroupEgress -GroupId $SecurityGroupId -IpPermission $CidrRange -Region $Region -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get or modify the AWS Managed Microsoft Active Directory Security Group. $_"
    }

    Write-ToLog -Message "Getting AWS Managed Active Directory information for $DirectoryId." -Type 'INFO'
    Try {
        $Directory = Get-DSDirectory -DirectoryId $DirectoryId -Region $Region
    } Catch [System.Exception] {
        Write-ToLog -Message "Failed to get directory information for $DirectoryId. $_" -Type 'ERROR'
    } 

    $DnsIpAddrs = $Directory | Select-Object -ExpandProperty 'DnsIpAddrs'

    $Output = [PSCustomObject][Ordered]@{
        'Directory ID'             = $DirectoryId
        'Directory Type'           = 'Microsoft AD'
        'Directory Edition'        = $Verison
        'Directory DNS Name'       = $FQDN
        'Directory NetBIOS Name'   = $NetBios
        'Description'              = $Description
        'Primary Region'           = $Region
        'DNS IP Information'       = $DnsIpAddrs
        'Admin Account Secret ARN' = $Secret
    }

    $Output | ConvertTo-Json -Depth 5 | Out-File "C:\Temp\$DirectoryId.txt"
    Return $Output
}

Function Add-ManagedADDomainRegion {
    [CmdletBinding()]
    Param (
        [parameter(Mandatory = $true)][String]$DirectoryId,
        [parameter(Mandatory = $true)][String]$HomeRegion,
        [parameter(Mandatory = $true)][String]$RegionName,
        [parameter(Mandatory = $true)][String[]]$Subnets,
        [parameter(Mandatory = $true)][String]$VPC
    )

    If ($VPC -match '^vpc-[a-zA-Z0-9]{17}$' -or $VPC -match '^vpc-[a-zA-Z0-9]{8}$') {
        $VpcId = $VPC
    } Else {
        $VpcId = Get-VpcIdFromTag -Region $RegionName -VPCTag $VPC
    }

    [System.Collections.ArrayList]$SubnetIds = @()
    Foreach ($Subnet in $Subnets) {
        If ($Subnet -match '^subnet-[a-zA-Z0-9]{17}$' -or $Subnet -match '^subnet-[a-zA-Z0-9]{8}$') {
            [void]$SubnetIds.Add($Subnet)
        } Else {
            $SubnetIdsInfo = Get-SubnetIdFromTag -Region $RegionName -SubnetTag $Subnet
            [void]$SubnetIds.Add($SubnetIdsInfo)
        }
    }

    Try {
        Add-DSRegion -DirectoryId $DirectoryId -RegionName $RegionName -VPCSettings_SubnetId $SubnetIds -VPCSettings_VpcId $VpcId -Region $HomeRegion -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -Message "Failed to add new AWS Managed Microsoft Active Directory region $RegionName. $_" -Type 'ERROR' -Exit
    } 

    Start-Sleep -Seconds 60

    $CidrRange = @{ IpProtocol = "-1"; IpRanges = '0.0.0.0/0' }
    Try {
        $SecurityGroupId = Get-EC2SecurityGroup -Filter @{ Name = 'group-name'; Values = "$($DirectoryId)_controllers" } -Region $RegionName -ErrorAction Stop | Select-Object -Property 'GroupId' -ExpandProperty 'GroupId'
        Grant-EC2SecurityGroupEgress -GroupId $SecurityGroupId -IpPermission $CidrRange -Region $RegionName -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -Message "Failed to get or modify the AWS Managed Microsoft Active Directory Security Group. $_" -Type 'WARN'
    } 
    Write-ToLog -Message "AWS Managed Microsoft Active Directory build process completed succesfully in $Region." -Type 'INFO'
}

Function New-ManagedADLogSub {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][String]$AccountNumber,
        [Parameter(Mandatory = $true)][String]$DirectoryId,
        [Parameter(Mandatory = $true)][String]$Region
    )

    $PolicyDoc = @{ Version = '2012-10-17'; Statement = @( @{ Effect = 'Allow'; Action = @( 'logs:CreateLogStream', 'logs:PutLogEvents' ); Principal = @{ Service = 'ds.amazonaws.com' }; Resource = @( "arn:aws:logs:$($Region):$($AccountNumber):log-group:/aws/directoryservice/*" ) } ) } | ConvertTo-Json -Depth 3

    Try {
        New-CWLLogGroup -LogGroupName "/aws/directoryservice/$DirectoryId" -Force -Region $Region -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -Message "Failed to setup CloudWatch Log Group AWS Managed Microsoft Active Directory. $_" -Type 'ERROR' -Exit
    } 

    Try { 
        $Null = Write-CWLResourcePolicy -PolicyName 'DSLogSubscription' -PolicyDocument $PolicyDoc -Region $Region -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -Message "Failed to setup CloudWatch Resource Policy for AWS Managed Microsoft Active Directory. $_" -Type 'ERROR' -Exit
    } 

    Try {
        New-DSLogSubscription -DirectoryId $DirectoryId -LogGroupName "/aws/directoryservice/$DirectoryId" -Force -Region $Region -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -Message "Failed to enable Event Log Forwarding for AWS Managed Microsoft Active Directory. $_" -Type 'ERROR' -Exit
    } 
}

Function New-ManagedADSNSMonitor {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][String]$DirectoryId,
        [Parameter(Mandatory = $true)][String]$EmailAddr,
        [Parameter(Mandatory = $true)][String]$Region
    )

    Try {
        $TopicArn = New-SNSTopic -Name "DirectoryMonitoring_$DirectoryId" -Attribute @{ DisplayName = 'AWSDIRSrvc' } -Force -Region $Region -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -Message "Failed to created new SNS Topic for AWS Managed Microsoft Active Directory. $_" -Type 'ERROR' -Exit
    } 
    
    Try {
        $SubArn = Connect-SNSNotification -TopicArn $TopicArn -Protocol 'email' -Endpoint $EmailAddr -ReturnSubscriptionArn $True -Region $Region -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -Message "Failed to created new SNS Subscription for AWS Managed Microsoft Active Directory. $_" -Type 'ERROR' -Exit
    } 

    Try {
        Register-DSEventTopic -TopicName "DirectoryMonitoring_$DirectoryId" -DirectoryId $DirectoryId -Force -Region $Region -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -Message "Failed to register SNS Topic with AWS Managed Microsoft Active Directory. $_" -Type 'ERROR' -Exit
    } 
}

Function New-ManagedADTrust {
    [CmdletBinding()]
    Param (
        [parameter(Mandatory = $true)][String[]]$ConditionalForwarderIpAddr,
        [parameter(Mandatory = $true)][ValidatePattern('^d-[a-zA-Z0-9]{10}$')][String]$DirectoryId,
        [parameter(Mandatory = $true)][ValidatePattern('^\w{2}-[a-z]*-[0-9]{1}$')][String]$Region,
        [parameter(Mandatory = $true)][String]$RemoteDomainName,
        [parameter(Mandatory = $true)][ValidateSet('Enabled', 'Disabled')][String]$SelectiveAuth,
        [parameter(Mandatory = $true)][ValidateSet('OneWayIncoming', 'OneWayOutgoing', 'Two-Way')][String]$TrustDirection,
        [parameter(Mandatory = $true)][String]$TrustPassword,
        [parameter(Mandatory = $true)][ValidateSet('External', 'Forest')][String]$TrustType
    )

    $SelectiveObj = New-Object -TypeName 'Amazon.DirectoryService.SelectiveAuth' -ArgumentList $SelectiveAuth
    $TrustDirObj = New-Object -TypeName 'Amazon.DirectoryService.TrustDirection' -ArgumentList $TrustDirection
    $TrustTypeObj = New-Object -TypeName 'Amazon.DirectoryService.TrustType' -ArgumentList $TrustType

    Try {
        $TrustID = New-DSTrust -DirectoryId $DirectoryId -ConditionalForwarderIpAddr $ConditionalForwarderIpAddr -Region $Region -RemoteDomainName $RemoteDomainName -SelectiveAuth $SelectiveObj -TrustDirection $TrustDirObj -TrustType $TrustTypeObj -TrustPassword $TrustPassword -ErrorAction Stop
    } Catch [System.Exception] {
        Write-ToLog -Message "Failed to create trust with on-premises domain $RemoteDomainName. $_" -Type 'ERROR' -Exit
    }
    
    Write-ToLog -Message "Checking the AWS Managed Microsoft Active Directory trust creation process in $Region." -Type 'INFO'
    $Counter = 0
    Do {
        $State = Get-DSTrust -DirectoryId $DirectoryId -Region $Region -TrustId $TrustID -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'TrustState' | Select-Object -ExpandProperty 'Value'
        If ($State -ne 'Verified') {
            $Counter ++
            If ($Counter -gt '1') {
                Write-Host -ForegroundColor Yellow "[$WARN][$(Get-Date -Format 'yyyy-MM-dd-THH:mm:ss')] AWS Managed Microsoft Active Directory in trust creation state is $State and is not yet Verified, sleeping for 10 seconds."
                Start-Sleep -Seconds 10
            }
        }
    } Until ($Counter -ge 30 -or $Stage -eq 'Verified' -or $Stage -eq 'Failed')
    
    If ($Counter -ge 30 -or $Stage -eq 'Failed') {
        Write-ToLog -Message "AWS Managed Active Microsoft Directory failed to create trust in $Region.  Manually check the AWS Managed Microsoft Active Directory and see if action is need and try again" -Type 'ERROR' -Exit
    }
    
    $Output = [PSCustomObject][Ordered]@{
        'Directory ID' = $DirectoryId
        'Trust ID'     = $TrustID
    }
    
    Return $Output
}

Function New-ConnectDomain {
    Param (
        [parameter(Mandatory = $true)][String]$VPC,
        [parameter(Mandatory = $true)][String]$Region,
        [parameter(Mandatory = $true)][String[]]$Subnets,
        [parameter(Mandatory = $true)][String]$Verison,
        [parameter(Mandatory = $true)][String]$Description,
        [parameter(Mandatory = $true)][String]$FQDN,
        [parameter(Mandatory = $true)][String]$Password,
        [parameter(Mandatory = $true)][String]$NetBios,
        [parameter(Mandatory = $true)][String[]]$CustomerDnsIp,
        [parameter(Mandatory = $true)][String]$CustomerUserName
    )

    Trap [System.Exception] {
        Write-Output $_.FullyQualifiedErrorId
        Write-Output $_.Exception.Message
        Write-Output $_.ScriptStackTrace
        Break
    }

    If ($VPC -match '^vpc-[a-zA-Z0-9]{17}$' -or $VPC -match '^vpc-[a-zA-Z0-9]{8}$') {
        $VpcId = $VPC
    } Else {
        $VpcId = Get-VpcIdFromTag -Region $Region -VPCTag $VPC
    }

    [System.Collections.ArrayList]$SubnetIds = @()
    Foreach ($Subnet in $Subnets) {
        If ($Subnet -match '^subnet-[a-zA-Z0-9]{17}$' -or $Subnet -match '^subnet-[a-zA-Z0-9]{8}$') {
            [void]$SubnetIds.Add($Subnet)
        } Else {
            $SubnetIdsInfo = Get-SubnetIdFromTag -Region $Region -SubnetTag $Subnet
            [void]$SubnetIds.Add($SubnetIdsInfo)
        }
    }

    $Size = New-Object -TypeName 'Amazon.DirectoryService.DirectorySize' -ArgumentList $Verison

    $TagSpec = New-Object -TypeName 'Amazon.DirectoryService.Model.Tag'
    $TagSpec.Key = 'Name'
    $TagSpec.Value = "$($FQDN) MAD"

    Connect-DSDirectory -Name $FQDN -Password $Password -ConnectSettings_CustomerDnsIp $CustomerDnsIp -ConnectSettings_CustomerUserName $CustomerUserName -Description $Description -ShortName $NetBios -Size $Size -ConnectSettings_SubnetId $SubnetIds -Tag $TagSpec -ConnectSettings_VpcId $VpcId -Force -Region $Region
}

Function New-AMICreation {
    Param (
        [parameter(Mandatory = $true)][String]$Region,
        [parameter(Mandatory = $true)][String]$Name,
        [parameter(Mandatory = $true)][String]$Description,
        [parameter(Mandatory = $true)][String]$TagValue
    )

    Trap [System.Exception] {
        Write-Output $_.FullyQualifiedErrorId
        Write-Output $_.Exception.Message
        Write-Output $_.ScriptStackTrace
        Break
    }

    $InstanceId = Get-EC2Instance -Filter @{ Name = 'tag:Name'; Values = $TagValue } -Region $Region | Select-Object -ExpandProperty 'Instances' | Select-Object -ExpandProperty 'InstanceId'
    New-EC2Image -InstanceId $InstanceId -Name $Name -Description $Description -Region $Region
}

Function Invoke-AMICopy {
    Param (
        [parameter(Mandatory = $true)][String]$SourceRegion,
        [parameter(Mandatory = $true)][String]$DestRegion,
        [parameter(Mandatory = $true)][String]$Name
    )

    Trap [System.Exception] {
        Write-Output $_.FullyQualifiedErrorId
        Write-Output $_.Exception.Message
        Write-Output $_.ScriptStackTrace
        Break
    }

    $ImageId = Get-EC2Image -Filter @{Name = 'name'; Values = $Name } -Region us-west-2 | Select-Object -ExpandProperty 'ImageId'
    Copy-EC2Image -SourceRegion $SourceRegion -SourceImageId $ImageId -Region $DestRegion -Name $Name
}

Function New-R53RResolver {
    [CmdletBinding()]
    Param (
        [String]$DirectionValue,
        [String]$IPAddress1,
        [String]$Subnet1Tag,
        [String]$IPAddress2,
        [String]$Subnet2Tag,
        [String]$Name,
        [String[]]$SecurityGroups,
        [String]$Region
    )

    $IP1SubnetId = Get-EC2Subnet -Filter @{ Name = 'tag:Name'; Values = $Subnet1Tag } -Region $Region | Select-Object -ExpandProperty 'SubnetId'
    $IP2SubnetId = Get-EC2Subnet -Filter @{ Name = 'tag:Name'; Values = $Subnet2Tag } -Region $Region | Select-Object -ExpandProperty 'SubnetId'

    [System.Collections.ArrayList]$SecurityGroupIds = @()
    Foreach ($SecurityGroup in $SecurityGroups) {
        If ($SecurityGroup -match '^sg-[a-zA-Z0-9]{17}$' -or $SecurityGroup -match '^sg-[a-zA-Z0-9]{8}$') {
            [void]$SecurityGroupIds.Add($SecurityGroup)
        } Else { 
            $SecurityGroupInfo = Get-SgIdFromTag -Region $Region -SecurityGroupTag $SecurityGroup  
            [void]$SecurityGroupIds.Add($SecurityGroupInfo)
        }
    }

    $Tag = New-Object -TypeName 'Amazon.Route53Resolver.Model.Tag'
    $Tag.Key = 'Name'
    $Tag.Value = $Name

    $IpAddr1 = New-Object -TypeName 'Amazon.Route53Resolver.Model.IpAddressRequest'
    $IpAddr1.Ip = $IPAddress1
    $IpAddr1.SubnetId = $IP1SubnetId

    $IpAddr2 = New-Object -TypeName 'Amazon.Route53Resolver.Model.IpAddressRequest'
    $IpAddr2.Ip = $IPAddress2
    $IpAddr2.SubnetId = $IP2SubnetId

    Write-Output $Name, $DirectionValue, $IpAddr1, $IpAddr2, $Name, $SecurityGroupIds, $Tag, $Region

    New-R53RResolverEndpoint -CreatorRequestId $Name -Direction $DirectionValue -IpAddress $IpAddr1, $IpAddr2 -Name $Name -SecurityGroupId $SecurityGroupIds -Tag $Tag -Force -Region $Region
}

Function New-R53RRule {
    [CmdletBinding()]
    Param (
        [String]$DomainName,
        [String]$Name,
        [String]$ResolverName,
        [String[]]$IPAddress,
        [String[]]$VPC,
        [String]$Region
    )

    $ResolverEndpointId = Get-R53RResolverEndpointList -Region $Region | Where-Object { $_.Name -eq $ResolverName } | Select-Object -ExpandProperty 'Id'

    $Tag = New-Object -TypeName 'Amazon.Route53Resolver.Model.Tag'
    $Tag.Key = 'Name'
    $Tag.Value = $DomainName

    [System.Collections.ArrayList]$TargetIp = @()
    Foreach ($IP in $IPAddress) {
        $IpAddr = New-Object -TypeName 'Amazon.Route53Resolver.Model.TargetAddress'
        $IpAddr.Ip = $IP
        $IpAddr.Port = '53'
        [void]$TargetIp.Add($IpAddr)
    }
   
    $Rule = New-R53RResolverRule -DomainName $DomainName -CreatorRequestId $DomainName -Name $Name -ResolverEndpointId $ResolverEndpointId -RuleType 'FORWARD' -Tag $Tag -TargetIp $TargetIp -Region $Region

    Foreach ($VPC in $VPCTag) {
    
        If ($VPC -match '^vpc-[a-zA-Z0-9]{17}$' -or $VPC -match '^vpc-[a-zA-Z0-9]{8}$') {
            $VpcId = $VPC
        } Else {
            $VpcId = Get-VpcIdFromTag -Region $Region -VPCTag $VPC
        }
    
        Add-R53RResolverRuleAssociation -ResolverRuleId $Rule.Id -VPCId $VPCId -Region $Region -Force
    }
}

Function Invoke-ImageBuildCycle {  
    [CmdletBinding()]
    param (
        [string]$HomeRegion
    )
    $ImageVersions = Get-EC2IBImageList -Region $HomeRegion
    If ($ImageVersions) {
        ForEach ($ImageVersion in $ImageVersions) {
            $ImageBuildVersions = Get-EC2IBImageBuildVersionList -ImageVersionArn $ImageVersion.Arn -Region $HomeRegion
            ForEach ($ImageBuildVersion in $ImageBuildVersions) {
                $State = $ImageBuildVersion | Select-Object -ExpandProperty 'State' | Select-Object -ExpandProperty 'Status' | Select-Object -ExpandProperty 'Value'
                If ($State -eq 'AVAILABLE') {
                    Remove-EC2IBImage -ImageBuildVersionArn $ImageBuildVersion.Arn -Region $HomeRegion -Force
                    $Amis = $ImageBuildVersion | Select-Object -ExpandProperty 'OutputResources' | Select-Object -ExpandProperty 'Amis'
                    Foreach ($Ami in $Amis) {
                        $ImageRegion = $Ami.Region
                        $ImageId = $Ami.Image
                        Unregister-EC2Image -ImageId $ImageId -Region $ImageRegion -Force
                        $Snapshot = Get-EC2Snapshot -Filter @{ Name = 'description'; Values = "*$ImageId*" } -Region $ImageRegion | Select-Object -ExpandProperty 'SnapshotId'
                        Remove-EC2Snapshot -SnapshotId $Snapshot -Force -Region $ImageRegion
                    }
                }
            }
        }
    }
    $IbPipelines = Get-EC2IBImagePipelineList -Region $HomeRegion
    ForEach ($IbPipeline in $IbPipelines) {
        Start-EC2IBImagePipelineExecution -ImagePipelineArn $IbPipeline.Arn -Force -Region $HomeRegion
    }
}

Function New-PatchSetWithRegistration {
    [CmdletBinding()]
    param (
        [String]$ApproveAfterDays,
        [String]$BaselineName,
        [String]$BaselineDesc,
        [String]$PatchGroup,
        [String]$Region,
        [String]$OperatingSystem,
        [bool]$Default
    )

    $LinuxOs = @(
        'AMAZON_LINUX',
        'AMAZON_LINUX_2',
        'CENTOS',
        'ORACLE_LINUX',
        'REDHAT_ENTERPRISE_LINUX',
        'UBUNTU',
        'DEBIAN'
    )

    $DEBU = @(
        'UBUNTU',
        'DEBIAN'
    )

    $SeverityOs = @(
        'AMAZON_LINUX',
        'AMAZON_LINUX_2',
        'CENTOS',
        'ORACLE_LINUX',
        'REDHAT_ENTERPRISE_LINUX'
    )

    [System.Collections.ArrayList]$Rules = @()
    If ($OperatingSystem -eq 'WINDOWS') {
        $PatchSets = @(
            'OS'
            'APPLICATION'
        )
    } Else {
        $PatchSets = @(
            'OS'
        )
    }
    Foreach ($PatchSet in $PatchSets) {
        $Rule = New-Object -TypeName 'Amazon.SimpleSystemsManagement.Model.PatchRule'
        $Rule.ComplianceLevel = 'CRITICAL'
        $Rule.ApproveAfterDays = $ApproveAfterDays
        If ($LinuxOs -contains $OperatingSystem) {
            $Rule.EnableNonSecurity = $True 
        }
    
        $RuleFilters = New-Object -TypeName 'Amazon.SimpleSystemsManagement.Model.PatchFilterGroup'
    
        If ($OperatingSystem -eq 'WINDOWS') {
            $PSet = New-Object -TypeName 'Amazon.SimpleSystemsManagement.Model.PatchFilter'
            $PSet.Key = 'PATCH_SET'
            $PSet.Values = $PatchSet
            $RuleFilters.PatchFilters.Add($PSet)

            $MsrcSeverityFilter = New-Object -TypeName 'Amazon.SimpleSystemsManagement.Model.PatchFilter'
            $MsrcSeverityFilter.Key = 'MSRC_SEVERITY'
            $MsrcSeverityFilter.Values = '*'
            $RuleFilters.PatchFilters.Add($MsrcSeverityFilter)   
        }

        $PatchFilter = New-Object -TypeName 'Amazon.SimpleSystemsManagement.Model.PatchFilter'
        $PatchFilter.Key = 'PRODUCT'
        $PatchFilter.Values = '*'
        $RuleFilters.PatchFilters.Add($PatchFilter)
            
        Switch ($PatchSet) {
            'APPLICATION' { 
                $AppPatchFilter = New-Object -TypeName 'Amazon.SimpleSystemsManagement.Model.PatchFilter'
                $AppPatchFilter.Key = 'PRODUCT_FAMILY'
                $AppPatchFilter.Values = '*'
                $RuleFilters.PatchFilters.Add($AppPatchFilter)
            }
        }

    If ($DEBU -notcontains $OperatingSystem) {
        $ClassificationFilter = New-Object -TypeName 'Amazon.SimpleSystemsManagement.Model.PatchFilter'
        $ClassificationFilter.Key = 'CLASSIFICATION'
        $ClassificationFilter.Values = '*'
        $RuleFilters.PatchFilters.Add($ClassificationFilter)
    }

    If ($DEBU -contains $OperatingSystem) {
        $PriorityFilter = New-Object -TypeName 'Amazon.SimpleSystemsManagement.Model.PatchFilter'
        $PriorityFilter.Key = 'PRIORITY'
        $PriorityFilter.Values = '*'
        $RuleFilters.PatchFilters.Add($PriorityFilter)

        $SectionFilter = New-Object -TypeName 'Amazon.SimpleSystemsManagement.Model.PatchFilter'
        $SectionFilter.Key = 'SECTION'
        $SectionFilter.Values = '*'
        $RuleFilters.PatchFilters.Add($SectionFilter)
    }

    If ($SeverityOs -contains $OperatingSystem) {
        $SeverityFilter = New-Object -TypeName 'Amazon.SimpleSystemsManagement.Model.PatchFilter'
        $SeverityFilter.Key = 'SEVERITY'
        $SeverityFilter.Values = '*'
        $RuleFilters.PatchFilters.Add($SeverityFilter)   
    }

        $Rule.PatchFilterGroup = $RuleFilters
        [void]$Rules.Add($Rule)
    }
    $PatchBaseline = New-SSMPatchBaseline -Name $BaselineName -Description $BaselineDesc -ApprovalRules_PatchRule $Rules -OperatingSystem $OperatingSystem -Tag @{ Key = 'Name'; Value = $BaselineName } -Region $Region
    If ($Default -eq $True) {
        Register-SSMDefaultPatchBaseline -BaselineId $PatchBaseline -Force -Region $Region
    }
    Register-SSMPatchBaselineForPatchGroup -BaselineId $PatchBaseline -PatchGroup $PatchGroup -Region $Region
}

Function Get-SecretCreds {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)][String]$DomainNetBIOSName,
        [Parameter(Mandatory = $True)][String]$SecretArn
    )

    #==================================================
    # Main
    #==================================================

    Write-Output "Getting $SecretArn Secret"
    Try {
        $SecretContent = Get-SECSecretValue -SecretId $SecretArn -ErrorAction Stop | Select-Object -ExpandProperty 'SecretString' | ConvertFrom-Json -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get $SecretArn Secret $_"
        Exit 1
    }
       
    Write-Output 'Creating Credential Object'
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