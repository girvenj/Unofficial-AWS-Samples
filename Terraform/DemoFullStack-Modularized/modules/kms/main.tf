terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_kms_key" "main" {
  description              = var.kms_key_description
  key_usage                = var.kms_key_usage
  customer_master_key_spec = var.kms_customer_master_key_spec
  deletion_window_in_days  = var.kms_key_deletion_window_in_days
  is_enabled               = true
  enable_key_rotation      = var.kms_enable_key_rotation
  multi_region             = var.kms_multi_region
  tags = {
    Name = "${var.kms_key_alias_name}-${var.kms_random_string}"
  }
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.kms_key_alias_name}-${var.kms_random_string}"
  target_key_id = aws_kms_key.main.key_id
}
