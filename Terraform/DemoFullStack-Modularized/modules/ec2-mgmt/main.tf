data "aws_ami" "ami" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base*"]
  }
}

data "aws_partition" "main" {}

data "aws_region" "main" {}

data "aws_caller_identity" "main" {}

data "aws_iam_policy_document" "ec2_instance_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "ec2" {
  statement {
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    effect    = "Allow"
    resources = [var.mad_mgmt_admin_secret]
  }
  statement {
    actions   = ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups", "ssm:DescribeInstanceInformation", "ssm:GetAutomationExecution", "ssm:ListCommands", "ssm:ListCommandInvocations", "ds:CreateConditionalForwarder", "ds:CreateTrust", "ds:DescribeTrusts", "ds:VerifyTrust"]
    effect    = "Allow"
    resources = ["*"]
  }
  statement {
    actions = ["ssm:StartAutomationExecution"]
    effect  = "Allow"
    resources = [
      "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:automation-definition/${var.mad_mgmt_ssm_docs[0]}:$DEFAULT",
      "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:automation-definition/${var.mad_mgmt_ssm_docs[1]}:$DEFAULT",
      "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:automation-definition/${var.mad_mgmt_ssm_docs[2]}:$DEFAULT"
    ]
  }
  statement {
    actions   = ["ssm:SendCommand"]
    effect    = "Allow"
    resources = ["arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:*:document/AWS-RunRemoteScript", "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:*:document/AWS-RunPowerShellScript"]
  }

  statement {
    actions = ["ssm:SendCommand"]
    effect  = "Allow"
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "ssm:ResourceTag/aws:cloudformation:stack-name"
      values = [
        "instance-mad-mgmt-${var.mad_mgmt_random_string}"
      ]
    }
    resources = ["arn:${data.aws_partition.main.partition}:ec2:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:instance/*"]
  }
  statement {
    actions = ["cloudformation:SignalResource"]
    effect  = "Allow"
    resources = [
      "arn:${data.aws_partition.main.partition}:cloudformation:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:stack/instance-mad-mgmt-${var.mad_mgmt_random_string}/*"
    ]
  }
}

resource "aws_iam_role" "ec2" {
  name               = "MAD-Mgmt-EC2-Instance-IAM-Role-${var.mad_mgmt_random_string}"
  assume_role_policy = data.aws_iam_policy_document.ec2_instance_assume_role_policy.json
  inline_policy {
    name   = "build-policy"
    policy = data.aws_iam_policy_document.ec2.json
  }
  managed_policy_arns = [
    "arn:${data.aws_partition.main.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:${data.aws_partition.main.partition}:iam::aws:policy/CloudWatchAgentServerPolicy"
  ]
  tags = {
    Name = "MAD-Mgmt-EC2-Instance-IAM-Role-${var.mad_mgmt_random_string}"
  }
}

resource "aws_iam_instance_profile" "ec2" {
  name = aws_iam_role.ec2.name
  role = aws_iam_role.ec2.name
}

resource "aws_cloudformation_stack" "instance_mad_mgmt" {
  name = "instance-mad-mgmt-${var.mad_mgmt_random_string}"
  parameters = {
    AMI              = data.aws_ami.ami.id
    DeployMadPki     = tostring(var.mad_mgmt_deploy_pki)
    InstanceProfile  = aws_iam_instance_profile.ec2.id
    MadAdminSecret   = var.mad_mgmt_admin_secret
    MadDirectoryId   = var.mad_mgmt_directory_id
    MadDomainName    = var.mad_mgmt_domain_fqdn
    MadNetBiosName   = var.mad_mgmt_domain_netbios
    OnpremDomainName = var.onprem_domain_fqdn
    SecurityGroupIds = var.mad_mgmt_security_group_ids
    SsmAutoDocument  = var.mad_mgmt_ssm_docs[0]
    SubnetId         = var.mad_mgmt_subnet_id
    TrustDirection   = var.mad_trust_direction
    VPCCIDR          = var.mad_mgmt_vpc_cidr
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
          - None
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
                      StackName = 'instance-mad-mgmt-${var.mad_mgmt_random_string}'
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
}
