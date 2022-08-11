resource "aws_security_group" "onprem_ad_sg" {
  name        = "Domain-Controller-Security-Group-${random_string.random_string.result}"
  description = "Domain Controller Security Group"
  vpc_id      = aws_vpc.network.id

  dynamic "ingress" {
    for_each = local.ad_ports
    iterator = ad_ports
    content {
      description = ad_ports.value.description
      from_port   = ad_ports.value.from_port
      to_port     = ad_ports.value.to_port
      protocol    = ad_ports.value.protocol
      cidr_blocks = [ad_ports.value.cidr_blocks]
    }
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "Domain-Controller-Security-Group-${random_string.random_string.result}"
  }
}

resource "aws_security_group" "pki_sg" {
  name        = "PKI-Security-Group-${random_string.random_string.result}"
  description = "PKI Security Group"
  vpc_id      = aws_vpc.network.id

  dynamic "ingress" {
    for_each = local.pki_ports
    iterator = pki_ports
    content {
      description = pki_ports.value.description
      from_port   = pki_ports.value.from_port
      to_port     = pki_ports.value.to_port
      protocol    = pki_ports.value.protocol
      cidr_blocks = [pki_ports.value.cidr_blocks]
    }
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "PKI-Security-Group-${random_string.random_string.result}"
  }
}

resource "aws_security_group" "ms_sg" {
  name        = "Member-Server-Security-Group-${random_string.random_string.result}"
  description = "Member Server Security Group"
  vpc_id      = aws_vpc.network.id

  dynamic "ingress" {
    for_each = local.ms_ports
    iterator = ms_ports
    content {
      description = ms_ports.value.description
      from_port   = ms_ports.value.from_port
      to_port     = ms_ports.value.to_port
      protocol    = ms_ports.value.protocol
      cidr_blocks = [ms_ports.value.cidr_blocks]
    }
  }
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "Member-Server-Security-Group-${random_string.random_string.result}"
  }
}

data "aws_ami" "windows_2022" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base*"]
  }
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
    resources = [aws_secretsmanager_secret.secret_mad.id, aws_secretsmanager_secret.secret_onprem.id]
  }
  statement {
    actions   = ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups", "ssm:DescribeInstanceInformation", "ssm:GetAutomationExecution", "ssm:ListCommands", "ssm:ListCommandInvocations", "ds:CreateConditionalForwarder", "ds:CreateTrust", "ds:DescribeTrusts", "ds:VerifyTrust"]
    effect    = "Allow"
    resources = ["*"]
  }
  statement {
    actions   = ["ec2:AuthorizeSecurityGroupEgress"]
    effect    = "Allow"
    resources = ["arn:${data.aws_partition.main.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.main.account_id}:security-group/*"]
  }
  statement {
    actions = ["ssm:StartAutomationExecution"]
    effect  = "Allow"
    resources = [
      "arn:${data.aws_partition.main.partition}:ssm:${var.aws_region}:${data.aws_caller_identity.main.account_id}:automation-definition/${aws_ssm_document.ssm_baseline.name}:$DEFAULT",
      "arn:${data.aws_partition.main.partition}:ssm:${var.aws_region}:${data.aws_caller_identity.main.account_id}:automation-definition/${aws_ssm_document.ssm_auditpol.name}:$DEFAULT",
      "arn:${data.aws_partition.main.partition}:ssm:${var.aws_region}:${data.aws_caller_identity.main.account_id}:automation-definition/${aws_ssm_document.ssm_pki.name}:$DEFAULT"
    ]
  }
  statement {
    actions   = ["ssm:SendCommand"]
    effect    = "Allow"
    resources = ["arn:${data.aws_partition.main.partition}:ssm:${var.aws_region}:*:document/AWS-RunRemoteScript", "arn:${data.aws_partition.main.partition}:ssm:${var.aws_region}:*:document/AWS-RunPowerShellScript"]
  }
  statement {
    actions = ["ssm:SendCommand"]
    effect  = "Allow"
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "ssm:ResourceTag/aws:cloudformation:stack-name"
      values   = [
        "instance-root-dc-${random_string.random_string.result}", 
        "instance-child_dc-${random_string.random_string.result}", 
        "instance-root-pki-${random_string.random_string.result}", 
        "instance-mad-mgmt-${random_string.random_string.result}"
      ]
    }
    resources = ["arn:${data.aws_partition.main.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.main.account_id}:instance/*"]
  }
  statement {
    actions = ["cloudformation:SignalResource"]
    effect  = "Allow"
    resources = [
      "arn:${data.aws_partition.main.partition}:cloudformation:${var.aws_region}:${data.aws_caller_identity.main.account_id}:stack/instance-root-dc-${random_string.random_string.result}/*",
      "arn:${data.aws_partition.main.partition}:cloudformation:${var.aws_region}:${data.aws_caller_identity.main.account_id}:stack/instance-child-dc-${random_string.random_string.result}/*",
      "arn:${data.aws_partition.main.partition}:cloudformation:${var.aws_region}:${data.aws_caller_identity.main.account_id}:stack/instance-root-pki-${random_string.random_string.result}/*",
      "arn:${data.aws_partition.main.partition}:cloudformation:${var.aws_region}:${data.aws_caller_identity.main.account_id}:stack/instance-mad-mgmt-${random_string.random_string.result}/*"
    ]
  }
}

resource "aws_iam_role" "ec2" {
  name               = "EC2-Instance-IAM-Role-${random_string.random_string.result}"
  assume_role_policy = data.aws_iam_policy_document.ec2_instance_assume_role_policy.json
  inline_policy {
    name   = "policy-8675309"
    policy = data.aws_iam_policy_document.ec2.json
  }
  managed_policy_arns = [
    "arn:${data.aws_partition.main.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:${data.aws_partition.main.partition}:iam::aws:policy/CloudWatchAgentServerPolicy"
  ]
  tags = {
    Name = "EC2-Instance-IAM-Role-${random_string.random_string.result}"
  }
}

resource "aws_iam_instance_profile" "ec2" {
  name = aws_iam_role.ec2.name
  role = aws_iam_role.ec2.name
}
