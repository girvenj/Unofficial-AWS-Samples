terraform {
  required_version = ">= 0.12.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

data "aws_kms_alias" "secret" {
  name = var.secret_kms_key
}

resource "aws_secretsmanager_secret" "main" {
  name                    = var.name
  description             = var.description
  kms_key_id              = data.aws_kms_alias.secret.arn
  recovery_window_in_days = var.recovery_window_in_days
  tags = {
    Name = var.name
  }
}

resource "aws_secretsmanager_secret_version" "main" {
  secret_id     = aws_secretsmanager_secret.main.id
  secret_string = jsonencode({ username = var.username, password = var.password })
}
