data "aws_kms_alias" "secret" {
  name = "alias/${var.secret_kms_key}"
}

resource "aws_secretsmanager_secret" "main" {
  name = var.name
  description = var.description
  kms_key_id = data.aws_kms_alias.secret.arn
  tags = {
    Name = var.name
  }
}

resource "aws_secretsmanager_secret_version" "main" {
  secret_id     = aws_secretsmanager_secret.main.id
  secret_string = jsonencode({ username = var.username, password = var.password })
}