terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

data "aws_ami" "ami" {
  most_recent = true
  owners      = [var.onprem_pki_ec2_ami_owner]
  filter {
    name   = "name"
    values = [var.onprem_pki_ec2_ami_name]
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
    actions   = ["ec2:DescribeInstances", "ssm:DescribeInstanceInformation", "ssm:GetAutomationExecution", "ssm:ListCommands", "ssm:ListCommandInvocations"]
    effect    = "Allow"
    resources = ["*"]
  }
  statement {
    actions = ["ssm:StartAutomationExecution"]
    effect  = "Allow"
    resources = [
      "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:automation-definition/${var.onprem_pki_ssm_docs[0]}:$DEFAULT",
      "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:automation-definition/${var.onprem_pki_ssm_docs[1]}:$DEFAULT",
      "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:automation-definition/${var.onprem_pki_ssm_docs[2]}:$DEFAULT",
      "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:automation-definition/${var.onprem_pki_ssm_docs[3]}:$DEFAULT"
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
        "instance-onprem-pki-${var.onprem_pki_random_string}"
      ]
    }
    resources = ["arn:${data.aws_partition.main.partition}:ec2:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:instance/*"]
  }
  statement {
    actions = ["cloudformation:SignalResource"]
    effect  = "Allow"
    resources = [
      "arn:${data.aws_partition.main.partition}:cloudformation:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:stack/instance-onprem-pki-${var.onprem_pki_random_string}/*"
    ]
  }
}

resource "aws_iam_role" "ec2" {
  name               = "Onprem-PKI-${var.onprem_domain_fqdn}-EC2-Instance-IAM-Role-${var.onprem_pki_random_string}"
  assume_role_policy = data.aws_iam_policy_document.ec2_instance_assume_role_policy.json
  tags = {
    Name = "Onprem-PKI-${var.onprem_domain_fqdn}-EC2-Instance-IAM-Role-${var.onprem_pki_random_string}"
  }
}

resource "aws_iam_role_policy" "build" {
  name = "build-policy"
  role = aws_iam_role.ec2.id
  policy = data.aws_iam_policy_document.ec2.json
}

resource "aws_iam_role_policy_attachments_exclusive" "ec2" {
  role_name   = aws_iam_role.ec2.name
  policy_arns = [
    "arn:${data.aws_partition.main.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:${data.aws_partition.main.partition}:iam::aws:policy/CloudWatchAgentServerPolicy"
  ]
}

resource "aws_iam_instance_profile" "ec2" {
  name = aws_iam_role.ec2.name
  role = aws_iam_role.ec2.name
}

resource "aws_iam_role_policy" "kms" {
  name = "kms-policy"
  role = aws_iam_role.ec2.id
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

resource "aws_kms_grant" "kms_administrator_secret" {
  name              = "kms-decrypt-secret-grant-onprem-pki"
  key_id            = data.aws_kms_key.kms.id
  grantee_principal = aws_iam_role.ec2.arn
  operations        = ["Decrypt"]
}

resource "aws_cloudformation_stack" "instance_pki" {
  name = "instance-onprem-pki-${var.onprem_pki_random_string}"
  parameters = {
    AMI                       = data.aws_ami.ami.id
    DomainDNSResolutionIP     = join(",", var.onprem_pki_dns_resolver_ip)
    EbsKmsKey                 = var.onprem_pki_ebs_kms_key
    InstanceProfile           = aws_iam_instance_profile.ec2.id
    InstanceType              = var.onprem_pki_ec2_instance_type
    LaunchTemplate            = var.onprem_pki_ec2_launch_template
    OnPremAdministratorSecret = var.onprem_administrator_secret
    OnpremDomainName          = var.onprem_domain_fqdn
    OnpremNetBiosName         = var.onprem_domain_netbios
    SecurityGroupId           = var.onprem_pki_security_group_id
    ServerNetBIOSName         = var.onprem_pki_server_netbios_name
    SsmAutoDocument           = var.onprem_pki_ssm_docs[0]
    SubnetId                  = var.onprem_pki_subnet_id
    VPCCIDR                   = var.onprem_pki_vpc_cidr
  }

  template_body = <<STACK
    AWSTemplateFormatVersion: '2010-09-09'
    Parameters:
      AMI:
        #Default: /aws/service/ami-windows-latest/TPM-Windows_Server-2022-English-Full-Base
        Description: System Manager parameter value for latest Windows Server AMI
        Type: String
      DomainDNSResolutionIP:
        Description: IP Address(s) of DNS resolver
        Type: String
      EbsKmsKey:
        Description: Alias for the KMS encryption key used to encrypt the EBS volumes
        Type: String
      InstanceProfile:
        Description: Instance profile and role to allow instances to use SSM Automation
        Type: String
      InstanceType:
        Description: Instance type to use for the instance
        Type: String
      LaunchTemplate:
        Description: Specifies a Launch Template to configure the instance
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
      SecurityGroupId:
        Description: Security Group Id
        Type: AWS::EC2::SecurityGroup::Id
      ServerNetBIOSName:
        Description: The NetBIOS name for the server, such as ONPREM-PKI01
        Type: String
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
                  KmsKeyId: !Sub $${EbsKmsKey}
                  DeleteOnTermination: true
              - DeviceName: /dev/xvdf
                Ebs:
                  VolumeSize: 10
                  VolumeType: gp3
                  Encrypted: true
                  KmsKeyId: !Sub $${EbsKmsKey}
                  DeleteOnTermination: true
            IamInstanceProfile: !Ref InstanceProfile
            ImageId: !Ref AMI
            InstanceType: !Ref InstanceType
            KeyName: Baseline
            LaunchTemplate: 
              LaunchTemplateId: !Ref LaunchTemplate
              Version: 1
            SecurityGroupIds:
              - !Ref SecurityGroupId
            SubnetId: !Ref SubnetId
            Tags:
              - Key: Name
                Value: !Ref ServerNetBIOSName
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
                        DomainDNSResolutionIP = '$${DomainDNSResolutionIP}'
                        DomainNetBIOSName = '$${DomainNetBIOSName}'
                        DomainType = 'SelfManagedAD'
                        LogicalResourceId = 'OnpremPkiInstance'
                        AdministratorSecretName = '$${AdministratorSecretName}'
                        ServerNetBIOSName = '$${ServerNetBIOSName}'
                        ServerRole = 'CertificateAuthority'
                        StackName = 'instance-onprem-pki-${var.onprem_pki_random_string}'
                        VPCCIDR = '$${VPCCIDR}'
                    }
                    Start-SSMAutomationExecution -DocumentName '$${SsmAutoDocument}' -Parameter $Params
                    </powershell>
                - AdministratorSecretName: !Ref OnPremAdministratorSecret
                  DomainDNSName: !Ref OnpremDomainName
                  DomainDNSResolutionIP: !Ref DomainDNSResolutionIP
                  DomainNetBIOSName: !Ref OnpremNetBiosName
                  ServerNetBIOSName: !Ref ServerNetBIOSName
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

resource "aws_ec2_tag" "main" {
  resource_id = aws_cloudformation_stack.instance_pki.outputs.OnpremPkiInstanceID
  key         = "PatchGroup"
  value       = var.onprem_pki_patch_group_tag
}

data "aws_instance" "main" {
  instance_id = aws_cloudformation_stack.instance_pki.outputs.OnpremPkiInstanceID
}

resource "aws_ec2_tag" "eni" {
  resource_id = data.aws_instance.main.network_interface_id
  key         = "Name"
  value       = var.onprem_pki_server_netbios_name
}

data "aws_ebs_volume" "sda1" {
  most_recent = true
  filter {
    name   = "attachment.device"
    values = ["/dev/sda1"]
  }
  filter {
    name   = "attachment.instance-id"
    values = [aws_cloudformation_stack.instance_pki.outputs.OnpremPkiInstanceID]
  }
}

data "aws_ebs_volume" "xvdf" {
  most_recent = true
  filter {
    name   = "attachment.device"
    values = ["/dev/xvdf"]
  }
  filter {
    name   = "attachment.instance-id"
    values = [aws_cloudformation_stack.instance_pki.outputs.OnpremPkiInstanceID]
  }
}

resource "aws_ec2_tag" "sda1" {
  resource_id = data.aws_ebs_volume.sda1.id
  key         = "Name"
  value       = var.onprem_pki_server_netbios_name
}

resource "aws_ec2_tag" "xvdf" {
  resource_id = data.aws_ebs_volume.xvdf.id
  key         = "Name"
  value       = var.onprem_pki_server_netbios_name
}
