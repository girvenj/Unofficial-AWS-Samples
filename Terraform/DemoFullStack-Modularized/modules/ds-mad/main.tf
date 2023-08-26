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

resource "random_password" "main" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

module "kms_secret_key" {
  source                          = "../kms"
  kms_key_description             = "KMS key for MAD Admin account Secret encryption"
  kms_key_usage                   = "ENCRYPT_DECRYPT"
  kms_customer_master_key_spec    = "SYMMETRIC_DEFAULT"
  kms_key_deletion_window_in_days = 7
  kms_enable_key_rotation         = true
  kms_key_alias_name              = "mad-secret-kms-key"
  kms_multi_region                = false
  kms_random_string               = var.mad_random_string
}

module "store_secret" {
  source                  = "../secret"
  name                    = "MAD-${var.mad_domain_fqdn}-Admin-Secret-${var.mad_random_string}"
  username                = "Admin"
  password                = random_password.main.result
  recovery_window_in_days = 0
  secret_kms_key          = module.kms_secret_key.kms_alias_name
}

resource "aws_directory_service_directory" "main" {
  desired_number_of_domain_controllers = var.mad_desired_number_of_domain_controllers
  edition                              = var.mad_edition
  enable_sso                           = false
  name                                 = var.mad_domain_fqdn
  password                             = random_password.main.result
  short_name                           = var.mad_domain_netbios
  tags = {
    Name = "MAD-${var.mad_domain_fqdn}-${var.mad_random_string}"
  }
  type = "MicrosoftAD"
  vpc_settings {
    vpc_id     = var.mad_vpc_id
    subnet_ids = var.mad_subnet_ids
  }
}

resource "aws_security_group_rule" "main" {
  type              = "egress"
  description       = "All outbound"
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 0
  security_group_id = aws_directory_service_directory.main.security_group_id
}
