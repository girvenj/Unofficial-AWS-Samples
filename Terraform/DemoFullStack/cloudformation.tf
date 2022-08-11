resource "aws_cloudformation_stack" "instance_root_dc" {
  name = "instance-root-dc-${random_string.random_string.result}"
  parameters = {
    AMI                       = data.aws_ami.windows_2022.id
    FsxOnpremParentOu         = var.onprem_fsx_ou
    IntegrateFsxOnprem        = tostring(var.onprem_deploy_fsx)
    InstanceProfile           = aws_iam_instance_profile.ec2.id
    MadAdminSecret            = aws_secretsmanager_secret.secret_mad.id
    MadDomainName             = var.mad_domain_fqdn
    OnPremAdministratorSecret = aws_secretsmanager_secret.secret_onprem.id
    OnpremDomainName          = var.onprem_domain_fqdn
    OnpremNetBiosName         = var.onprem_domain_netbios
    SecurityGroupIds          = aws_security_group.onprem_ad_sg.id
    SsmAutoDocument           = "SSM-Baseline-${random_string.random_string.result}"
    SubnetId                  = aws_subnet.network_subnet1.id
    TrustDirection            = var.mad_onprem_trust_direction
    VPCCIDR                   = aws_vpc.network.cidr_block
  }

  template_body = <<STACK
    AWSTemplateFormatVersion: '2010-09-09'
    Parameters:
      AMI:
        #Default: /aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base
        Description: System Manager parameter value for latest Windows Server AMI
        Type: String
      IntegrateFsxOnprem:
        AllowedValues:
          - 'true'
          - 'false'
        Description: Deploy & Integrate Amazon FSX for Windows with On-Premises AD
        Type: String
      FsxOnpremParentOu:
        Default: DC=onpremises,DC=local
        Description: Parent DN for Amazon FSX for Windows OU (Only used when deployment with On-Premises AD)
        Type: String
      InstanceProfile:
        Description: Instance profile and role to allow instances to use SSM Automation
        Type: String  
      MadAdminSecret:
        Description: Secret containing the random password of the AWS Managed Microsoft AD Admin account
        Type: String  
      MadDomainName:
        AllowedPattern: ^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$
        Description: Fully qualified domain name (FQDN) of the AWS Managed Microsoft AD domain e.g. corp.example.com
        MaxLength: '255'
        MinLength: '2'
        Type: String
      OnPremAdministratorSecret:
        Description: Secret containing the random password of the onpremises Microsoft AD Administrator account
        Type: String  
      OnpremDomainName:
        AllowedPattern: ^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$
        Description: Fully qualified domain name (FQDN) of the On-Premises domain e.g. onpremises.local
        MaxLength: '255'
        MinLength: '2'
        Type: String
      OnpremNetBiosName:
        AllowedPattern: ^[^\\/:*?"<>|.]+[^\\/:*?"<>|]*$
        Description: NetBIOS name of the On-Premises domain (up to 15 characters) e.g. ONPREMISES
        MaxLength: '15'
        MinLength: '1'
        Type: String
      SecurityGroupIds:
        Description: Security Group Id
        Type: AWS::EC2::SecurityGroup::Id
      SubnetId:
        Description: Subnet Id
        Type: AWS::EC2::Subnet::Id
      SsmAutoDocument:
        Description: SSM Automation Document used to configure the instances
        Type: String
      TrustDirection:
        AllowedValues:
          - Two-Way
          - 'One-Way: Incoming'
          - 'One-Way: Outgoing'
        Description: Trust Direction from AWS Managed Microsoft AD to on-premises domain
        Type: String
      VPCCIDR:
        Description: VPC CIDR where instance will be deployed to
        Type: String
    Resources:
      OnPremDomainController:
        Type: AWS::EC2::Instance
        CreationPolicy:
          ResourceSignal:
            Count: 1
            Timeout: PT60M
        Properties:
          BlockDeviceMappings:
            - DeviceName: /dev/sda1
              Ebs:
                DeleteOnTermination: true
                Encrypted: true
                KmsKeyId: alias/aws/ebs
                VolumeSize: 60
                VolumeType: gp3
            - DeviceName: /dev/xvdf
              Ebs:
                DeleteOnTermination: true
                Encrypted: true
                KmsKeyId: alias/aws/ebs
                VolumeSize: 10
                VolumeType: gp3
          IamInstanceProfile: !Ref InstanceProfile
          ImageId: !Ref AMI
          InstanceType: m6i.large
          KeyName: Baseline
          SecurityGroupIds:
            - Ref: SecurityGroupIds
          SubnetId: !Ref SubnetId
          Tags:
              - Key: Domain
                Value: !Ref OnpremDomainName
              - Key: Name
                Value: ONPREM-DC01
              - Key: Role
                Value: Domain Controller
          UserData:
            Fn::Base64: !Sub
              - |
                  <powershell>
                  $Params = @{
                      TrustSecretName = '$${TrustSecretName}'
                      DeployPki = 'No'
                      DeploymentType = 'RootDomainController'
                      DomainDNSName = '$${DomainDNSName}'
                      DomainNetBIOSName = '$${OnpremNetBiosName}'
                      FsxOnpremParentOu = '$${FsxOnpremParentOu}'
                      IntegrateFsxOnprem = '$${IntegrateFsxOnprem}'
                      LogicalResourceId = 'OnPremDomainController'
                      MadDNSName = '$${MadDNSName}'
                      AdministratorSecretName = '$${AdministratorSecretName}'
                      ServerNetBIOSName = 'ONPREM-DC01'
                      ServerRole = 'DomainController'
                      StackName = 'instance-root-dc-${random_string.random_string.result}'
                      TrustDirection = '$${TrustDirection}'
                      VPCCIDR = '$${VPCCIDR}'
                  }
                  Start-SSMAutomationExecution -DocumentName '$${SsmAutoDocument}' -Parameter $Params
                  </powershell>
              - TrustSecretName: !Ref MadAdminSecret
                DomainDNSName: !Ref OnpremDomainName
                FsxOnpremParentOu: !Ref FsxOnpremParentOu
                IntegrateFsxOnprem: !Ref IntegrateFsxOnprem
                MadDNSName: !Ref MadDomainName
                AdministratorSecretName: !Ref OnPremAdministratorSecret
                TrustDirection: !Ref TrustDirection
                VPCCIDR: !Ref VPCCIDR
    Outputs:
      OnpremDomainControllerInstanceID:
        Description: Onprem Domain Controller Instance ID
        Value: !Ref OnPremDomainController
      OnpremDomainControllerInstancePrivateIP:
        Description: Onprem Domain Controller Instance Private IP
        Value: !GetAtt OnPremDomainController.PrivateIp
STACK
  timeouts {
    create = "120m"
  }
  depends_on = [
    aws_route53_resolver_rule_association.r53_outbound_resolver_rule_mad_association
  ]
}

resource "aws_cloudformation_stack" "instance_child_dc" {
  count = var.onprem_create_child_domain ? 1 : 0
  name  = "instance-child_dc-${random_string.random_string.result}"
  parameters = {
    AMI                       = data.aws_ami.windows_2022.id
    InstanceProfile           = aws_iam_instance_profile.ec2.id
    OnPremAdministratorSecret = aws_secretsmanager_secret.secret_onprem.id
    OnpremChildNetBiosName    = var.onprem_child_domain_netbios
    OnpremDomainName          = var.onprem_domain_fqdn
    ParentInstanceIP          = aws_cloudformation_stack.instance_root_dc.outputs.OnpremDomainControllerInstancePrivateIP
    SecurityGroupIds          = aws_security_group.onprem_ad_sg.id
    SsmAutoDocument           = "SSM-Baseline-${random_string.random_string.result}"
    SubnetId                  = aws_subnet.network_subnet1.id
    VPCCIDR                   = aws_vpc.network.cidr_block
  }

  template_body = <<STACK
    AWSTemplateFormatVersion: '2010-09-09'
    Parameters:
      AMI:
        #Default: /aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base
        Description: System Manager parameter value for latest Windows Server AMI
        Type: String
      InstanceProfile:
        Description: Instance profile and role to allow instances to use SSM Automation
        Type: String  
      OnPremAdministratorSecret:
        Description: Secret containing the random password of the onpremises Microsoft AD Administrator account
        Type: String  
      OnpremChildNetBiosName:
        AllowedPattern: ^[^\\/:*?"<>|.]+[^\\/:*?"<>|]*$
        Description: NetBIOS name of the On-Premises child domain (up to 15 characters) e.g. CHILD
        MaxLength: '15'
        MinLength: '1'
        Type: String
      OnpremDomainName:
        AllowedPattern: ^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$
        Description: Fully qualified domain name (FQDN) of the On-Premises domain e.g. onpremises.local
        MaxLength: '255'
        MinLength: '2'
        Type: String
      ParentInstanceIP:
        Description: IP Address of the forest root domain controller
        Type: String
      SecurityGroupIds:
        Description: Security Group Id
        Type: AWS::EC2::SecurityGroup::Id
      SubnetId:
        Description: Subnet Id
        Type: AWS::EC2::Subnet::Id
      SsmAutoDocument:
        Description: SSM Automation Document used to configure the instances
        Type: String
      VPCCIDR:
        Description: VPC CIDR where instance will be deployed to
        Type: String
    Resources:
      ChildOnPremDomainController:
        Type: AWS::EC2::Instance
        CreationPolicy:
          ResourceSignal:
            Count: 1
            Timeout: PT60M
        Properties:
          BlockDeviceMappings:
            - DeviceName: /dev/sda1
              Ebs:
                DeleteOnTermination: true
                Encrypted: true
                KmsKeyId: alias/aws/ebs
                VolumeSize: 60
                VolumeType: gp3
            - DeviceName: /dev/xvdf
              Ebs:
                DeleteOnTermination: true
                Encrypted: true
                KmsKeyId: alias/aws/ebs
                VolumeSize: 10
                VolumeType: gp3
          IamInstanceProfile: !Ref InstanceProfile
          ImageId: !Ref AMI
          InstanceType: m6i.large
          KeyName: Baseline
          SecurityGroupIds:
            - Ref: SecurityGroupIds
          SubnetId: !Ref SubnetId
          Tags:
            - Key: Domain
              Value: !Join [ '.', [ !Ref OnpremChildNetBiosName, !Ref OnpremDomainName ] ]
            - Key: Name
              Value: CHILD-DC01
            - Key: Role
              Value: Domain Controller
          UserData:
            Fn::Base64: !Sub
              - |
                  <powershell>
                  $Params = @{
                      DeployPki = 'No'
                      DeploymentType = 'ChildDomainController'
                      DomainDNSName = '$${DomainDNSName}'
                      DomainNetBIOSName = '$${DomainNetBIOSName}'
                      LogicalResourceId = 'ChildOnPremDomainController'
                      ParentDomainDNSName = '$${ParentDomainDNSName}'
                      ParentInstanceIP = '$${ParentInstanceIP}'
                      AdministratorSecretName = '$${AdministratorSecretName}'
                      ServerNetBIOSName = 'CHILD-DC01'
                      ServerRole = 'DomainController'
                      StackName = 'instance-child_dc-${random_string.random_string.result}'
                      VPCCIDR = '$${VPCCIDR}'
                  }
                  Start-SSMAutomationExecution -DocumentName '$${SsmAutoDocument}' -Parameter $Params
                  </powershell>
              - DomainDNSName: !Join [ '.', [ !Ref OnpremChildNetBiosName, !Ref OnpremDomainName ] ]
                DomainNetBIOSName: !Ref OnpremChildNetBiosName
                ParentDomainDNSName: !Ref OnpremDomainName
                ParentInstanceIP: !Ref ParentInstanceIP
                AdministratorSecretName: !Ref OnPremAdministratorSecret
                VPCCIDR: !Ref VPCCIDR
    Outputs:
      ChildOnpremDomainControllerInstanceID:
        Condition: YesCreateChildDomain
        Description: Child Onprem Domain Controller Instance ID
        Value: !Ref ChildOnPremDomainController
      ChildOnpremDomainControllerInstancePrivateIP:
        Condition: YesCreateChildDomain
        Description: Child Onprem Domain Controller Instance Private IP
        Value: !GetAtt ChildOnPremDomainController.PrivateIp
STACK
  timeouts {
    create = "120m"
  }
}

resource "aws_cloudformation_stack" "instance_root_pki" {
  count = var.onprem_deploy_pki ? 1 : 0
  name  = "instance-root-pki-${random_string.random_string.result}"
  parameters = {
    AMI                       = data.aws_ami.windows_2022.id
    InstanceProfile           = aws_iam_instance_profile.ec2.id
    OnPremAdministratorSecret = aws_secretsmanager_secret.secret_onprem.id
    OnpremDomainName          = var.onprem_domain_fqdn
    OnpremNetBiosName         = var.onprem_domain_netbios
    SecurityGroupIds          = aws_security_group.onprem_ad_sg.id
    SsmAutoDocument           = "SSM-Baseline-${random_string.random_string.result}"
    SubnetId                  = aws_subnet.network_subnet1.id
    VPCCIDR                   = aws_vpc.network.cidr_block
  }

  template_body = <<STACK
    AWSTemplateFormatVersion: '2010-09-09'
    Parameters:
      AMI:
        #Default: /aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base
        Description: System Manager parameter value for latest Windows Server AMI
        Type: String
      InstanceProfile:
        Description: Instance profile and role to allow instances to use SSM Automation
        Type: String  
      OnPremAdministratorSecret:
        Description: Secret containing the random password of the onpremises Microsoft AD Administrator account
        Type: String  
      OnpremDomainName:
        AllowedPattern: ^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$
        Description: Fully qualified domain name (FQDN) of the On-Premises domain e.g. onpremises.local
        MaxLength: '255'
        MinLength: '2'
        Type: String
      OnpremNetBiosName:
        AllowedPattern: ^[^\\/:*?"<>|.]+[^\\/:*?"<>|]*$
        Description: NetBIOS name of the On-Premises domain (up to 15 characters) e.g. ONPREMISES
        MaxLength: '15'
        MinLength: '1'
        Type: String
      SecurityGroupIds:
        Description: Security Group Id
        Type: AWS::EC2::SecurityGroup::Id
      SubnetId:
        Description: Subnet Id
        Type: AWS::EC2::Subnet::Id
      SsmAutoDocument:
        Description: SSM Automation Document used to configure the instances
        Type: String
      VPCCIDR:
        Description: VPC CIDR where instance will be deployed to
        Type: String
    Resources:
      OnpremPkiInstance:
        Type: AWS::EC2::Instance
        CreationPolicy:
          ResourceSignal:
            Timeout: PT60M
            Count: 1
        Properties:
            BlockDeviceMappings:
              - DeviceName: /dev/sda1
                Ebs:
                  VolumeSize: 60
                  VolumeType: gp3
                  Encrypted: true
                  KmsKeyId: alias/aws/ebs
                  DeleteOnTermination: true
              - DeviceName: /dev/xvdf
                Ebs:
                  VolumeSize: 10
                  VolumeType: gp3
                  Encrypted: true
                  KmsKeyId: alias/aws/ebs
                  DeleteOnTermination: true
            IamInstanceProfile: !Ref InstanceProfile
            ImageId: !Ref AMI
            InstanceType: m6i.large
            KeyName: Baseline
            SecurityGroupIds:
              - !Ref SecurityGroupIds
            SubnetId: !Ref SubnetId
            Tags:
              - Key: Name
                Value: ONPREM-PKI01
              - Key: Domain
                Value: !Ref MadDomainName
              - Key: Role
                Value: Enterpise CA
            UserData:
              Fn::Base64: !Sub
                - |
                    <powershell>
                    $Params = @{
                        DeployPki = 'Yes'
                        DeploymentType = 'EnterpriseCA'
                        DomainDNSName = '$${DomainDNSName}'
                        DomainNetBIOSName = '$${DomainNetBIOSName}'
                        DomainType = 'SelfManagedAD'
                        LogicalResourceId = 'OnpremPkiInstance'
                        AdministratorSecretName = '$${AdministratorSecretName}'
                        ServerNetBIOSName = 'ONPREM-PKI01'
                        ServerRole = 'CertificateAuthority'
                        StackName = 'instance-root-pki-${random_string.random_string.result}'
                        VPCCIDR = '$${VPCCIDR}'
                    }
                    Start-SSMAutomationExecution -DocumentName '$${SsmAutoDocument}' -Parameter $Params
                    </powershell>
                - DomainDNSName: !Ref OnpremDomainName
                  DomainNetBIOSName: !Ref OnpremNetBiosName
                  AdministratorSecretName: !Ref OnPremAdministratorSecret
                  VPCCIDR: !Ref VPCCIDR
    Outputs:
      OnpremPkiInstanceID:
        Condition: YesDeployOnpremPki
        Description: Onprem PKI Instance ID
        Value: !Ref OnpremPkiInstance
      OnpremPkiInstancePrivateIP:
        Condition: YesDeployOnpremPki
        Description: Onprem PKI Instance Private IP
        Value: !GetAtt OnpremPkiInstance.PrivateIp
STACK
  timeouts {
    create = "120m"
  }
  depends_on = [
    aws_route53_resolver_rule_association.r53_outbound_resolver_rule_onprem_association
  ]
}

resource "aws_cloudformation_stack" "instance_mad_mgmt" {
  name = "instance-mad-mgmt-${random_string.random_string.result}"
  parameters = {
    AMI              = data.aws_ami.windows_2022.id
    DeployMadPki     = tostring(var.mad_deploy_pki)
    InstanceProfile  = aws_iam_instance_profile.ec2.id
    MadAdminSecret   = aws_secretsmanager_secret.secret_mad.id
    MadDirectoryId   = aws_directory_service_directory.mad.id
    MadDomainName    = var.mad_domain_fqdn
    MadNetBiosName   = var.mad_domain_netbios
    OnpremDomainName = var.onprem_domain_fqdn
    SecurityGroupIds = aws_security_group.onprem_ad_sg.id
    SsmAutoDocument  = "SSM-Baseline-${random_string.random_string.result}"
    SubnetId         = aws_subnet.network_subnet1.id
    TrustDirection   = var.mad_onprem_trust_direction
    VPCCIDR          = aws_vpc.network.cidr_block
  }

  template_body = <<STACK
    AWSTemplateFormatVersion: '2010-09-09'
    Parameters:
      AMI:
        #Default: /aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base
        Description: System Manager parameter value for latest Windows Server AMI
        Type: String
      DeployMadPki:
        AllowedValues:
          - 'true'
          - 'false'
        Description: Deploy Enterpise Ca with AWS Managed Microsoft AD
        Type: String  
      InstanceProfile:
        Description: Instance profile and role to allow instances to use SSM Automation
        Type: String  
      MadAdminSecret:
        Description: Secret containing the random password of the AWS Managed Microsoft AD Admin account
        Type: String  
      MadDirectoryId:
        Description: Directory ID of the AWS Managed Microsoft AD
        Type: String  
      MadDomainName:
        AllowedPattern: ^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$
        Description: Fully qualified domain name (FQDN) of the AWS Managed Microsoft AD domain e.g. corp.example.com
        MaxLength: '255'
        MinLength: '2'
        Type: String
      MadNetBiosName:
        AllowedPattern: ^[^\\/:*?"<>|.]+[^\\/:*?"<>|]*$
        Description: NetBIOS name of the AWS Managed Microsoft AD domain (up to 15 characters) e.g. CORP
        MaxLength: '15'
        MinLength: '1'
        Type: String
      OnpremDomainName:
        AllowedPattern: ^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$
        Description: Fully qualified domain name (FQDN) of the On-Premises domain e.g. onpremises.local
        MaxLength: '255'
        MinLength: '2'
        Type: String
      SecurityGroupIds:
        Description: Security Group Id
        Type: AWS::EC2::SecurityGroup::Id
      SubnetId:
        Description: Subnet Id
        Type: AWS::EC2::Subnet::Id
      SsmAutoDocument:
        Description: SSM Automation Document used to configure the instances
        Type: String
      TrustDirection:
        AllowedValues:
          - Two-Way
          - 'One-Way: Incoming'
          - 'One-Way: Outgoing'
        Description: Trust Direction from AWS Managed Microsoft AD to on-premises domain
        Type: String
      VPCCIDR:
        Description: VPC CIDR where instance will be deployed to
        Type: String
    Resources:
      MADMgmtInstance:
        Type: AWS::EC2::Instance
        CreationPolicy:
          ResourceSignal:
            Timeout: PT60M
            Count: 1
        Properties:
          BlockDeviceMappings:
              - DeviceName: /dev/sda1
                Ebs:
                  VolumeSize: 60
                  VolumeType: gp3
                  Encrypted: true
                  KmsKeyId: alias/aws/ebs
                  DeleteOnTermination: true
              - DeviceName: /dev/xvdf
                Ebs:
                  VolumeSize: 10
                  VolumeType: gp3
                  Encrypted: true
                  KmsKeyId: alias/aws/ebs
                  DeleteOnTermination: true
          IamInstanceProfile: !Ref InstanceProfile
          ImageId: !Ref AMI
          InstanceType: m6i.large
          KeyName: Baseline
          SecurityGroupIds:
            - !Ref SecurityGroupIds
          SubnetId: !Ref SubnetId
          Tags:
            - Key: Name
              Value: MAD-MGMT01
            - Key: Domain
              Value: !Ref MadDomainName
            - Key: Role
              Value: Enterpise CA
          UserData:
            Fn::Base64: !Sub
              - |
                  <powershell>
                  If ('$${DeployMadPki}' -eq 'true'){
                    $DeployPki = 'Yes'
                    $DeploymentType = 'EnterpriseCAManagementInstance'
                    $ServerRole = 'CertificateAuthority'
                  } Else{
                    $DeployPki = 'No'
                    $DeploymentType = 'ManagementInstance'
                    $ServerRole = 'Default'
                  }
                  $Params = @{
                      DeployPki = $DeployPki
                      DeploymentType = $DeploymentType
                      DomainDNSName = '$${DomainDNSName}'
                      DomainNetBIOSName = '$${DomainNetBIOSName}'
                      DomainType = 'AWSManagedAD'
                      LogicalResourceId = 'MADMgmtInstance'
                      MadDirectoryID = '$${MadDirectoryID}'
                      OnpremDomainDNSName = '$${OnpremDomainDNSName}'
                      AdministratorSecretName = '$${AdministratorSecretName}'
                      ServerNetBIOSName = 'MAD-MGMT01'
                      ServerRole = $ServerRole
                      StackName = 'instance-mad-mgmt-${random_string.random_string.result}'
                      TrustDirection = '$${TrustDirection}'
                      VPCCIDR = '$${VPCCIDR}'
                  }
                  Start-SSMAutomationExecution -DocumentName '$${SsmAutoDocument}' -Parameter $Params
                  </powershell>
              - AdministratorSecretName: !Ref MadAdminSecret 
                DeployMadPki: !Ref DeployMadPki
                DomainDNSName: !Ref MadDomainName
                DomainNetBIOSName: !Ref MadNetBiosName
                MadDirectoryID: !Ref MadDirectoryId
                OnpremDomainDNSName: !Ref OnpremDomainName
                TrustDirection: !Ref TrustDirection
                VPCCIDR: !Ref VPCCIDR
    Outputs:
      MADMgmtInstanceID:
        Description: MAD Mgmt Instance ID
        Value: !Ref MADMgmtInstance
      MADMgmtInstancePrivateIP:
        Description: MAD Mgmt Instance Private IP
        Value: !GetAtt MADMgmtInstance.PrivateIp
STACK
  timeouts {
    create = "120m"
  }
  depends_on = [
    aws_route53_resolver_rule_association.r53_outbound_resolver_rule_mad_association,
    aws_route53_resolver_rule_association.r53_outbound_resolver_rule_onprem_association
  ]
}
