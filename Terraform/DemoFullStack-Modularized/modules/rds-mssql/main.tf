terraform {
  required_version = ">= 0.12.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
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

data "aws_partition" "main" {}

data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_kms_alias" "main" {
  name = "alias/${var.rds_kms_key}"
}

data "aws_vpc" "main" {
  id = var.rds_vpc_id
}

resource "random_password" "main" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

module "store_secret" {
  source         = "../secret"
  name           = "RDS-Admin-Secret-${var.rds_random_string}"
  username       = var.rds_username
  password       = random_password.main.result
  secret_kms_key = var.rds_secret_kms_key
}

resource "aws_iam_role" "rds" {
  name                = "RDS-Domain-IAM-Role-${var.rds_random_string}"
  assume_role_policy  = data.aws_iam_policy_document.rds_instance_assume_role_policy.json
  managed_policy_arns = ["arn:${data.aws_partition.main.partition}:iam::aws:policy/service-role/AmazonRDSDirectoryServiceAccess"]
  tags = {
    Name = "RDS-Domain-IAM-Role-${var.rds_random_string}"
  }
}

resource "aws_db_subnet_group" "rds" {
  name       = "rds-subnet-group-${var.rds_random_string}"
  subnet_ids = var.rds_subnet_ids
  tags = {
    Name = "RDS-Subnet-Group"
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

module "rds_security_group" {
  source      = "../vpc-security-group-ingress"
  name        = "${var.rds_identifier}-RDS-Security-Group-${var.rds_random_string}"
  description = "${var.rds_identifier} RDS Security Group"
  vpc_id      = var.rds_vpc_id
  ports       = local.rds_ports
}


resource "aws_db_instance" "rds" {
  allocated_storage    = var.rds_allocated_storage
  availability_zone    = data.aws_availability_zones.available.names[0]
  db_subnet_group_name = aws_db_subnet_group.rds.id
  domain               = var.rds_directory_id
  domain_iam_role_name = aws_iam_role.rds.name
  engine               = var.rds_engine
  engine_version       = var.rds_engine_version
  identifier           = var.rds_identifier
  instance_class       = var.rds_instance_class
  kms_key_id           = data.aws_kms_alias.main.arn
  license_model        = "license-included"
  multi_az             = false
  password             = random_password.main.result
  port                 = var.rds_port_number
  skip_final_snapshot  = true
  storage_encrypted    = true
  storage_type         = var.rds_storage_type
  tags = {
    Name = "RDSMad-${var.rds_random_string}"
  }
  vpc_security_group_ids = [module.rds_security_group.sg_id]
  username               = var.rds_username
}
