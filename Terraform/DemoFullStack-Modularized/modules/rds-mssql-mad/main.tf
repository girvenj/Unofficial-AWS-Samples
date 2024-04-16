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

locals {
  rds_ports = [
    {
      from_port   = var.rds_port_number
      to_port     = var.rds_port_number
      description = "SQL"
      protocol    = "TCP"
      cidr_blocks = [data.aws_vpc.main.cidr_block]
    }
  ]
}

data "aws_iam_policy_document" "rds_instance_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "rds_monitoring_role_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

data "aws_partition" "main" {}

data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_vpc" "main" {
  id = var.rds_vpc_id
}

resource "random_password" "main" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

module "kms_secret_key" {
  source                          = "../kms"
  kms_key_description             = "KMS key for RDS encryption"
  kms_key_usage                   = "ENCRYPT_DECRYPT"
  kms_customer_master_key_spec    = "SYMMETRIC_DEFAULT"
  kms_key_deletion_window_in_days = 7
  kms_enable_key_rotation         = true
  kms_key_alias_name              = "rds-kms-key"
  kms_multi_region                = false
  kms_random_string               = var.rds_random_string
}

module "store_secret" {
  source                  = "../secret"
  name                    = "RDS-MAD-${var.rds_identifier}-Admin-Secret-${var.rds_random_string}"
  username                = var.rds_username
  username_key            = "username"
  password                = random_password.main.result
  password_key            = "password"
  recovery_window_in_days = 0
  secret_kms_key          = module.kms_secret_key.kms_alias_name
}

resource "aws_iam_role" "rds" {
  name                = "RDS-MAD-${var.rds_identifier}-Domain-IAM-Role-${var.rds_random_string}"
  assume_role_policy  = data.aws_iam_policy_document.rds_instance_assume_role_policy.json
  managed_policy_arns = ["arn:${data.aws_partition.main.partition}:iam::aws:policy/service-role/AmazonRDSDirectoryServiceAccess"]
  tags = {
    Name = "RDS-${var.rds_identifier}-Domain-IAM-Role-${var.rds_random_string}"
  }
}

resource "aws_iam_role" "rds_monitoring_role" {
  name               = "RDS-MAD-${var.rds_identifier}-Enhanced-Monitoring-Role-${var.rds_random_string}"
  assume_role_policy = data.aws_iam_policy_document.rds_monitoring_role_assume_role_policy.json
  managed_policy_arns = [
    "arn:${data.aws_partition.main.partition}:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
  ]
  tags = {
    Name = "RDS-MAD-${var.rds_identifier}-Enhanced-Monitoring-Role-${var.rds_random_string}"
  }
}

resource "aws_db_subnet_group" "rds" {
  name       = "rds-mad-${var.rds_identifier}-subnet-group-${var.rds_random_string}"
  subnet_ids = var.rds_subnet_ids
  tags = {
    Name = "RDS-MAD-${var.rds_identifier}-Subnet-Group-${var.rds_random_string}"
  }
}

module "rds_security_group" {
  source      = "../vpc-security-group-ingress"
  name        = "RDS-MAD-${var.rds_identifier}-Security-Group-${var.rds_random_string}"
  description = "RDS MAD ${var.rds_identifier} Security Group ${var.rds_random_string}"
  vpc_id      = var.rds_vpc_id
  ports       = local.rds_ports
}

resource "aws_db_instance" "rds" {
  allocated_storage                     = var.rds_allocated_storage
  apply_immediately                     = true
  auto_minor_version_upgrade            = true
  availability_zone                     = data.aws_availability_zones.available.names[0]
  backup_retention_period               = 1
  db_subnet_group_name                  = aws_db_subnet_group.rds.id
  delete_automated_backups              = true
  deletion_protection                   = false
  domain                                = var.rds_directory_id
  domain_iam_role_name                  = aws_iam_role.rds.name
  enabled_cloudwatch_logs_exports       = ["agent", "error"]
  engine                                = var.rds_engine
  #engine_version                        = var.rds_engine_version
  identifier                            = var.rds_identifier
  instance_class                        = var.rds_instance_class
  kms_key_id                            = module.kms_secret_key.kms_key_arn
  license_model                         = "license-included"
  monitoring_interval                   = 5
  monitoring_role_arn                   = aws_iam_role.rds_monitoring_role.arn
  multi_az                              = false
  password                              = random_password.main.result
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = module.kms_secret_key.kms_key_arn
  performance_insights_retention_period = 7
  port                                  = var.rds_port_number
  publicly_accessible                   = false
  skip_final_snapshot                   = true
  storage_encrypted                     = true
  storage_type                          = var.rds_storage_type
  tags = {
    Name = "RDS-MAD-${var.rds_identifier}-${var.rds_random_string}"
  }
  vpc_security_group_ids = [module.rds_security_group.sg_id]
  username               = var.rds_username
  timeouts {
    create = "3h"
    delete = "3h"
    update = "3h"
  }
}
