terraform {
  required_version = ">= 0.12.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

data "aws_ami" "ami" {
  most_recent = true
  owners      = [var.onprem_additional_dc_ec2_ami_owner]
  filter {
    name   = "name"
    values = [var.onprem_additional_dc_ec2_ami_name]
  }
  filter {
    name   = "platform"
    values = ["windows"]
  }
}

data "aws_partition" "main" {}

data "aws_region" "main" {}

data "aws_caller_identity" "main" {}

data "aws_kms_key" "kms" {
  key_id = var.onprem_administrator_secret_kms_key
}

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
      "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:automation-definition/${var.onprem_additional_dc_ssm_docs[0]}:$DEFAULT",
      "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:automation-definition/${var.onprem_additional_dc_ssm_docs[1]}:$DEFAULT",
      "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:automation-definition/${var.onprem_additional_dc_ssm_docs[2]}:$DEFAULT"
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
        "instance-additional-dc-${var.onprem_additional_dc_random_string}"
      ]
    }
    resources = ["arn:${data.aws_partition.main.partition}:ec2:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:instance/*"]
  }
  statement {
    actions = ["cloudformation:SignalResource"]
    effect  = "Allow"
    resources = [
      "arn:${data.aws_partition.main.partition}:cloudformation:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:stack/instance-additional-dc-${var.onprem_additional_dc_random_string}/*"
    ]
  }
}

resource "aws_iam_role" "ec2" {
  name               = "Onprem-Additional-DC-EC2-Instance-IAM-Role-${var.onprem_additional_dc_random_string}"
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
    Name = "Onprem-Additional-DC-EC2-Instance-IAM-Role-${var.onprem_additional_dc_random_string}"
  }
}

resource "aws_iam_instance_profile" "ec2" {
  name = aws_iam_role.ec2.name
  role = aws_iam_role.ec2.name
}

resource "aws_iam_role_policy" "kms" {
  name  = "kms-policy"
  count = var.onprem_additional_dc_use_customer_managed_key ? 1 : 0
  role  = aws_iam_role.ec2.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "kms:Decrypt",
        ]
        Effect = "Allow"
        Resource = [
          data.aws_kms_key.kms.arn
        ]
      },
    ]
  })
}

resource "aws_kms_grant" "kms_admin_secret" {
  count             = var.onprem_additional_dc_use_customer_managed_key ? 1 : 0
  name              = "kms-admin-secret-grant"
  key_id            = data.aws_kms_key.kms.id
  grantee_principal = aws_iam_role.ec2.arn
  operations        = ["Decrypt"]
}

resource "aws_cloudformation_stack" "instance_additional_dc" {
  name = "instance-additional-dc-${var.onprem_additional_dc_random_string}"
  parameters = {
    AMI                       = data.aws_ami.ami.id
    EbsKmsKey                 = var.onprem_additional_dc_ebs_kms_key
    InstanceProfile           = aws_iam_instance_profile.ec2.id
    OnPremAdministratorSecret = var.onprem_administrator_secret
    OnpremDomainName          = var.onprem_domain_fqdn
    OnpremNetBiosName         = var.onprem_domain_netbios
    ParentInstanceIP          = var.onprem_dc_ip
    SecurityGroupId           = var.onprem_additional_dc_security_group_id
    SsmAutoDocument           = var.onprem_additional_dc_ssm_docs[0]
    SubnetId                  = var.onprem_additional_dc_subnet_id
    VPCCIDR                   = var.onprem_additional_dc_vpc_cidr
  }

  template_body = <<STACK
    AWSTemplateFormatVersion: '2010-09-09'
    Parameters:
      AMI:
        #Default: /aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base
        Description: System Manager parameter value for latest Windows Server AMI
        Type: String
      EbsKmsKey:
        Description: Alias for the KMS encryption key used to encrypt the EBS volumes
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
      ParentInstanceIP:
        Description: IP Address of the forest root domain controller
        Type: String
      SecurityGroupId:
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
      AdditionalOnPremDomainController:
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
                KmsKeyId: !Sub $${EbsKmsKey}
                VolumeSize: 60
                VolumeType: gp3
            - DeviceName: /dev/xvdf
              Ebs:
                DeleteOnTermination: true
                Encrypted: true
                KmsKeyId: !Sub $${EbsKmsKey}
                VolumeSize: 10
                VolumeType: gp3
          IamInstanceProfile: !Ref InstanceProfile
          ImageId: !Ref AMI
          InstanceType: m6i.large
          KeyName: Baseline
          SecurityGroupIds:
            - Ref: SecurityGroupId
          SubnetId: !Ref SubnetId
          Tags:
            - Key: Domain
              Value: !Ref OnpremDomainName
            - Key: Name
              Value: Additional-DC01
            - Key: Role
              Value: Domain Controller
          UserData:
            Fn::Base64: !Sub
              - |
                  <powershell>
                  $Params = @{
                      AdministratorSecretName = '$${AdministratorSecretName}'
                      DeployPki = 'No'
                      DeploymentType = 'AdditionalDomainController'
                      DomainDNSName = '$${DomainDNSName}'
                      DomainNetBIOSName = '$${DomainDNSName}'
                      LogicalResourceId = 'AdditionalOnPremDomainController'
                      ParentInstanceIP = '$${ParentInstanceIP}'
                      ServerNetBIOSName = 'Additional-DC01'
                      ServerRole = 'DomainController'
                      StackName = 'instance-additional-dc-${var.onprem_additional_dc_random_string}'
                      VPCCIDR = '$${VPCCIDR}'
                  }
                  Start-SSMAutomationExecution -DocumentName '$${SsmAutoDocument}' -Parameter $Params
                  </powershell>
              - DomainDNSName: !Ref OnpremDomainName
                DomainNetBIOSName: !Ref OnpremNetBiosName
                ParentInstanceIP: !Ref ParentInstanceIP
                AdministratorSecretName: !Ref OnPremAdministratorSecret
                VPCCIDR: !Ref VPCCIDR
    Outputs:
      additionalOnpremDomainControllerInstanceID:
        Description: Additional Onprem Domain Controller Instance ID
        Value: !Ref AdditionalOnPremDomainController
      additionalOnpremDomainControllerInstancePrivateIP:
        Description: Additional Onprem Domain Controller Instance Private IP
        Value: !GetAtt AdditionalOnPremDomainController.PrivateIp
STACK
  timeouts {
    create = "120m"
  }
}

resource "aws_ec2_tag" "main" {
  resource_id = aws_cloudformation_stack.instance_additional_dc.outputs.additionalOnpremDomainControllerInstanceID
  key         = "Patch Group"
  value       = var.onprem_additional_dc_patch_group_tag
}
