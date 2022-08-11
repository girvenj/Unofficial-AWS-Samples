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
    resources = [var.onprem_administrator_secret]
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
      "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:automation-definition/${var.onprem_pki_ssm_docs[0]}:$DEFAULT",
      "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:automation-definition/${var.onprem_pki_ssm_docs[1]}:$DEFAULT",
      "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:automation-definition/${var.onprem_pki_ssm_docs[2]}:$DEFAULT"
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
        "instance-pki-${var.onprem_pki_random_string}"
      ]
    }
    resources = ["arn:${data.aws_partition.main.partition}:ec2:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:instance/*"]
  }
  statement {
    actions = ["cloudformation:SignalResource"]
    effect  = "Allow"
    resources = [
      "arn:${data.aws_partition.main.partition}:cloudformation:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:stack/instance-pki-${var.onprem_pki_random_string}/*"
    ]
  }
}

resource "aws_iam_role" "ec2" {
  name               = "Onprem-PKI-EC2-Instance-IAM-Role-${var.onprem_pki_random_string}"
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
    Name = "Onprem-PKI-EC2-Instance-IAM-Role-${var.onprem_pki_random_string}"
  }
}

resource "aws_iam_instance_profile" "ec2" {
  name = aws_iam_role.ec2.name
  role = aws_iam_role.ec2.name
}

resource "aws_cloudformation_stack" "instance_pki" {
  name  = "instance-pki-${var.onprem_pki_random_string}"
  parameters = {
    AMI                       = data.aws_ami.ami.id
    InstanceProfile           = aws_iam_instance_profile.ec2.id
    OnPremAdministratorSecret = var.onprem_administrator_secret
    OnpremDomainName          = var.onprem_domain_fqdn
    OnpremNetBiosName         = var.onprem_domain_netbios
    SecurityGroupIds          = var.onprem_pki_security_group_ids
    SsmAutoDocument           = var.onprem_pki_ssm_docs[0]
    SubnetId                  = var.onprem_pki_subnet_id
    VPCCIDR                   = var.onprem_pki_vpc_cidr
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
                Value: !Ref OnpremDomainName
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
                        StackName = 'instance-pki-${var.onprem_pki_random_string}'
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
        Description: Onprem PKI Instance ID
        Value: !Ref OnpremPkiInstance
      OnpremPkiInstancePrivateIP:
        Description: Onprem PKI Instance Private IP
        Value: !GetAtt OnpremPkiInstance.PrivateIp
STACK
  timeouts {
    create = "120m"
  }
}