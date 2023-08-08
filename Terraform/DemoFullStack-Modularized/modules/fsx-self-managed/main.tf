terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

data "aws_vpc" "main" {
  id = var.fsx_self_vpc_id
}

data "aws_kms_alias" "main" {
  name = var.fsx_self_kms_key
}

data "aws_secretsmanager_secret_version" "main" {
  secret_id = var.fsx_self_password_secret
}

locals {
  fsx_ports = [
    {
      from_port   = 445
      to_port     = 445
      description = "SMB"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    },
    {
      from_port   = 5985
      to_port     = 5986
      description = "WinRM"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    }
  ]
}

module "fsx_security_group" {
  source      = "../vpc-security-group-ingress"
  name        = "${var.fsx_self_alias}-FSx-Security-Group-${var.fsx_self_random_string}"
  description = "${var.fsx_self_alias} FSx Security Group"
  vpc_id      = var.fsx_self_vpc_id
  ports       = local.fsx_ports
}

resource "aws_fsx_windows_file_system" "main" {
  aliases                         = ["${var.fsx_self_alias}.${var.fsx_self_domain_fqdn}"]
  automatic_backup_retention_days = var.fsx_self_automatic_backup_retention_days
  deployment_type                 = var.fsx_self_deployment_type
  kms_key_id                      = data.aws_kms_alias.main.arn
  preferred_subnet_id             = var.fsx_self_subnet_ids[0]
  security_group_ids              = [module.fsx_security_group.sg_id]
  skip_final_backup               = true
  storage_capacity                = var.fsx_self_storage_capacity
  storage_type                    = var.fsx_self_storage_type
  subnet_ids                      = var.fsx_self_subnet_ids
  throughput_capacity             = var.fsx_self_throughput_capacity
  tags = {
    Name = "${var.fsx_self_alias}-${var.fsx_self_random_string}"
  }
  self_managed_active_directory {
    dns_ips                                = var.fsx_self_dns_ips
    domain_name                            = var.fsx_self_domain_fqdn
    file_system_administrators_group       = var.fsx_self_file_system_administrators_group
    organizational_unit_distinguished_name = "OU=FSx,${var.fsx_self_parent_ou_dn}"
    password                               = jsondecode(data.aws_secretsmanager_secret_version.main.secret_string)["password"]
    username                               = var.fsx_self_username
  }
}

resource "aws_ec2_tag" "eni" {
  for_each    = aws_fsx_windows_file_system.main.network_interface_ids
  resource_id = each.value
  key         = "Name"
  value       = "${var.fsx_self_alias}-${var.fsx_self_random_string}"
}
