terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}


data "aws_ami" "ami" {
  most_recent = true
  owners      = [var.onprem_root_dc_ec2_ami_owner]
  filter {
    name   = "name"
    values = [var.onprem_root_dc_ec2_ami_name]
  }
  filter {
    name   = "platform"
    values = ["windows"]
  }
}

data "aws_kms_key" "kms" {
  key_id = var.onprem_root_dc_secret_kms_key
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
    resources = [module.store_secret_administrator.secret_id, var.mad_admin_secret]
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
      "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:automation-definition/${var.onprem_root_dc_ssm_docs[0]}:$DEFAULT",
      "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:automation-definition/${var.onprem_root_dc_ssm_docs[1]}:$DEFAULT",
      "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:automation-definition/${var.onprem_root_dc_ssm_docs[2]}:$DEFAULT",
      "arn:${data.aws_partition.main.partition}:ssm:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:automation-definition/${var.onprem_root_dc_ssm_docs[3]}:$DEFAULT"

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
        "instance-onprem-root-dc-${var.onprem_root_dc_random_string}"
      ]
    }
    resources = ["arn:${data.aws_partition.main.partition}:ec2:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:instance/*"]
  }
  statement {
    actions = ["cloudformation:SignalResource"]
    effect  = "Allow"
    resources = [
      "arn:${data.aws_partition.main.partition}:cloudformation:${data.aws_region.main.name}:${data.aws_caller_identity.main.account_id}:stack/instance-onprem-root-dc-${var.onprem_root_dc_random_string}/*"
    ]
  }
}

resource "aws_iam_role_policy" "fsx_svc" {
  name  = "fsx-svc-policy"
  count = var.onprem_root_dc_deploy_fsx ? 1 : 0
  role  = aws_iam_role.ec2.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Effect = "Allow"
        Resource = [
          module.store_secret_fsx_svc[0].secret_arn
        ]
      },
    ]
  })
}

resource "aws_iam_role_policy" "cad_svc" {
  name  = "adc-svc-policy"
  count = var.onprem_root_dc_deploy_adc ? 1 : 0
  role  = aws_iam_role.ec2.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Effect = "Allow"
        Resource = [
          module.store_secret_cad_svc[0].secret_arn
        ]
      },
    ]
  })
}

resource "aws_iam_role_policy" "kms" {
  name  = "kms-policy"
  count = var.onprem_root_dc_use_customer_managed_key ? 1 : 0
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

resource "aws_kms_grant" "kms_administrator_secret" {
  count             = var.onprem_root_dc_use_customer_managed_key ? 1 : 0
  name              = "kms-decrypt-secret-grant-onprem-root-dc"
  key_id            = data.aws_kms_key.kms.id
  grantee_principal = aws_iam_role.ec2.arn
  operations        = ["Decrypt"]
}

resource "aws_iam_role" "ec2" {
  name               = "Onprem-Root-DC-${var.onprem_root_dc_domain_fqdn}-EC2-Instance-IAM-Role-${var.onprem_root_dc_random_string}"
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
    Name = "Onprem-Root-DC-${var.onprem_root_dc_domain_fqdn}-EC2-Instance-IAM-Role-${var.onprem_root_dc_random_string}"
  }
}

resource "aws_iam_instance_profile" "ec2" {
  name = aws_iam_role.ec2.name
  role = aws_iam_role.ec2.name
}

resource "random_password" "administrator" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "random_password" "fsx_svc" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "random_password" "adc_svc" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

module "store_secret_administrator" {
  source                  = "../secret"
  name                    = "Onprem-${var.onprem_root_dc_domain_fqdn}-Administrator-Secret-${var.onprem_root_dc_random_string}"
  username                = "Administrator"
  password                = random_password.administrator.result
  recovery_window_in_days = 0
  secret_kms_key          = var.onprem_root_dc_secret_kms_key
}

module "store_secret_fsx_svc" {
  count                   = var.onprem_root_dc_deploy_fsx ? 1 : 0
  source                  = "../secret"
  name                    = "Onprem-${var.onprem_root_dc_domain_fqdn}-FSx-Svc-Secret-${var.onprem_root_dc_random_string}"
  username                = var.onprem_root_dc_fsx_svc_username
  password                = random_password.fsx_svc.result
  recovery_window_in_days = 0
  secret_kms_key          = var.onprem_root_dc_secret_kms_key
}

module "store_secret_cad_svc" {
  count                   = var.onprem_root_dc_deploy_adc ? 1 : 0
  source                  = "../secret"
  name                    = "Onprem-${var.onprem_root_dc_domain_fqdn}-CAD-Svc-Secret-${var.onprem_root_dc_random_string}"
  username                = var.onprem_root_dc_adc_svc_username
  password                = random_password.adc_svc.result
  recovery_window_in_days = 0
  secret_kms_key          = var.onprem_root_dc_secret_kms_key
}

resource "aws_cloudformation_stack" "instance_root_dc" {
  name = "instance-onprem-root-dc-${var.onprem_root_dc_random_string}"
  parameters = {
    AdcSvcSecret              = var.onprem_root_dc_deploy_adc ? module.store_secret_cad_svc[0].secret_id : "placeholder" 
    AMI                       = data.aws_ami.ami.id
    EbsKmsKey                 = var.onprem_root_dc_ebs_kms_key
    FsxOnpremSvcSecret        = var.onprem_root_dc_deploy_fsx ? module.store_secret_fsx_svc[0].secret_id : "placeholder"
    IntegrateAdConnector      = tostring(var.onprem_root_dc_deploy_adc)
    IntegrateFsxOnprem        = tostring(var.onprem_root_dc_deploy_fsx)
    InstanceProfile           = aws_iam_instance_profile.ec2.id
    InstanceType              = var.onprem_root_dc_ec2_instance_type
    LaunchTemplate            = var.onprem_root_dc_ec2_launch_template
    MadAdminSecret            = var.mad_admin_secret
    MadDomainName             = var.mad_domain_fqdn
    MadDirectoryId            = var.mad_directory_id
    OnPremAdministratorSecret = module.store_secret_administrator.secret_id
    OnpremDomainName          = var.onprem_root_dc_domain_fqdn
    OnpremNetBiosName         = var.onprem_root_dc_domain_netbios
    SecurityGroupId           = var.onprem_root_dc_security_group_id
    ServerNetBIOSName         = var.onprem_root_dc_server_netbios_name
    SsmAutoDocument           = var.onprem_root_dc_ssm_docs[0]
    SubnetId                  = var.onprem_root_dc_subnet_id
    TrustDirection            = var.mad_trust_direction
    VPCCIDR                   = var.onprem_root_dc_vpc_cidr
  }
  template_body = <<STACK
    AWSTemplateFormatVersion: '2010-09-09'
    Parameters:
      AdcSvcSecret:
        Description: Secret containing the random password of the onpremises Microsoft AD AD Connector account
        Type: String
      AMI:
        #Default: /aws/service/ami-windows-latest/TPM-Windows_Server-2022-English-Full-Base
        Description: System Manager parameter value for latest Windows Server AMI
        Type: String
      EbsKmsKey:
        Description: Alias for the KMS encryption key used to encrypt the EBS volumes
        Type: String
      FsxOnpremSvcSecret:
        Description: The secret containing the password for the service account on your self-managed AD domain that Amazon FSx will use to join to your AD domain
        Type: String
      InstanceProfile:
        Description: Instance profile and role to allow instances to use SSM Automation
        Type: String
      InstanceType:
        Description: Instance type to use for the instance
        Type: String
      IntegrateAdConnector:
        AllowedValues:
          - 'true'
          - 'false'
        Description: Deploy & Integrate AWS AD Connector with On-Premises AD
        Type: String
      IntegrateFsxOnprem:
        AllowedValues:
          - 'true'
          - 'false'
        Description: Deploy & Integrate Amazon FSX for Windows with On-Premises AD
        Type: String
      LaunchTemplate:
        Description: Specifies a Launch Template to configure the instance
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
        Description: The NetBIOS name for the server, such as ONPREM-DC01
        Type: String
      SsmAutoDocument:
        Description: SSM Automation Document used to configure the instances
        Type: String
      SubnetId:
        Description: Subnet Id
        Type: AWS::EC2::Subnet::Id
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
          InstanceType: !Ref InstanceType
          KeyName: Baseline
          LaunchTemplate: 
            LaunchTemplateId: !Ref LaunchTemplate
            Version: 1
          SecurityGroupIds:
            - Ref: SecurityGroupId
          SubnetId: !Ref SubnetId
          Tags:
              - Key: Domain
                Value: !Ref OnpremDomainName
              - Key: Name
                Value: !Ref ServerNetBIOSName
              - Key: Role
                Value: Domain Controller
          UserData:
            Fn::Base64: !Sub
              - |
                  <powershell>
                  $Params = @{
                      AdConnectorSvcSecret = '$${AdcSvcSecret}'
                      DeployPki = 'No'
                      DeploymentType = 'RootDomainController'
                      DomainDNSName = '$${DomainDNSName}'
                      DomainNetBIOSName = '$${OnpremNetBiosName}'
                      FsxOnpremSvcSecret = '$${FsxOnpremSvcSecret}'
                      IntegrateAdConnector = '$${IntegrateAdConnector}'
                      IntegrateFsxOnprem = '$${IntegrateFsxOnprem}'
                      LogicalResourceId = 'OnPremDomainController'
                      MadDirectoryID = '$${MadDirectoryID}'
                      MadDNSName = '$${MadDNSName}'
                      AdministratorSecretName = '$${AdministratorSecretName}'
                      ServerNetBIOSName = '$${ServerNetBIOSName}'
                      ServerRole = 'DomainController'
                      StackName = 'instance-onprem-root-dc-${var.onprem_root_dc_random_string}'
                      TrustDirection = '$${TrustDirection}'
                      TrustSecretName = '$${TrustSecretName}'
                      VPCCIDR = '$${VPCCIDR}'
                  }
                  Start-SSMAutomationExecution -DocumentName '$${SsmAutoDocument}' -Parameter $Params
                  </powershell>
              - AdcSvcSecret: !Ref AdcSvcSecret
                AdministratorSecretName: !Ref OnPremAdministratorSecret
                DomainDNSName: !Ref OnpremDomainName
                FsxOnpremSvcSecret: !Ref FsxOnpremSvcSecret
                IntegrateAdConnector: !Ref IntegrateAdConnector
                IntegrateFsxOnprem: !Ref IntegrateFsxOnprem
                MadDirectoryID: !Ref MadDirectoryId
                MadDNSName: !Ref MadDomainName
                ServerNetBIOSName: !Ref ServerNetBIOSName
                TrustDirection: !Ref TrustDirection
                TrustSecretName: !Ref MadAdminSecret
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
}

data "aws_instance" "main" {
  instance_id = aws_cloudformation_stack.instance_root_dc.outputs.OnpremDomainControllerInstanceID
}

resource "aws_ec2_tag" "eni" {
  resource_id = data.aws_instance.main.network_interface_id
  key         = "Name"
  value       = var.onprem_root_dc_server_netbios_name
}

data "aws_ebs_volume" "sda1" {
  most_recent = true
  filter {
    name   = "attachment.device"
    values = ["/dev/sda1"]
  }
  filter {
    name   = "attachment.instance-id"
    values = [aws_cloudformation_stack.instance_root_dc.outputs.OnpremDomainControllerInstanceID]
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
    values = [aws_cloudformation_stack.instance_root_dc.outputs.OnpremDomainControllerInstanceID]
  }
}

resource "aws_ec2_tag" "sda1" {
  resource_id = data.aws_ebs_volume.sda1.id
  key         = "Name"
  value       = var.onprem_root_dc_server_netbios_name
}

resource "aws_ec2_tag" "xvdf" {
  resource_id = data.aws_ebs_volume.xvdf.id
  key         = "Name"
  value       = var.onprem_root_dc_server_netbios_name
}

resource "aws_ec2_tag" "main" {
  resource_id = aws_cloudformation_stack.instance_root_dc.outputs.OnpremDomainControllerInstanceID
  key         = "PatchGroup"
  value       = var.onprem_root_dc_patch_group_tag
}
