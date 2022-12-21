terraform {
  required_version = ">= 0.12.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

data "aws_vpc" "main" {
  id = var.fsx_mad_vpc_id
}

data "aws_directory_service_directory" "main" {
  directory_id = var.fsx_mad_directory_id
}

data "aws_kms_alias" "main" {
  name = var.fsx_mad_kms_key
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
  name        = "${var.fsx_mad_alias}-FSx-Security-Group-${var.fsx_mad_random_string}"
  description = "${var.fsx_mad_alias} FSx Security Group"
  vpc_id      = var.fsx_mad_vpc_id
  ports       = local.fsx_ports
}

resource "aws_fsx_windows_file_system" "main" {
  active_directory_id             = var.fsx_mad_directory_id
  aliases                         = ["${var.fsx_mad_alias}.${data.aws_directory_service_directory.main.name}"]
  automatic_backup_retention_days = var.fsx_mad_automatic_backup_retention_days
  deployment_type                 = var.fsx_mad_deployment_type
  kms_key_id                      = data.aws_kms_alias.main.arn
  preferred_subnet_id             = var.fsx_mad_subnet_ids[0]
  security_group_ids              = [module.fsx_security_group.sg_id]
  skip_final_backup               = true
  storage_capacity                = var.fsx_mad_storage_capacity
  storage_type                    = var.fsx_mad_storage_type
  subnet_ids                      = var.fsx_mad_subnet_ids
  throughput_capacity             = var.fsx_mad_throughput_capacity
  tags = {
    Name = "${var.fsx_mad_alias}-${var.fsx_mad_random_string}"
  }
}
