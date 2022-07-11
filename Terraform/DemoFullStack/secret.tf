resource "random_password" "secret_mad" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_secretsmanager_secret" "secret_mad" {
  name = "${var.mad_domain_fqdn}-MAD-Secret-${random_string.random_string.result}"
  tags = {
    Name = "${var.mad_domain_fqdn}-MAD-Secret-${random_string.random_string.result}"
  }
}

resource "aws_secretsmanager_secret_version" "secret_mad" {
  secret_id     = aws_secretsmanager_secret.secret_mad.id
  secret_string = jsonencode({ username = var.mad_user_admin, password = random_password.secret_mad.result })
  depends_on = [
    aws_secretsmanager_secret.secret_mad,
    random_password.secret_mad
  ]
}

resource "random_password" "secret_rds" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_secretsmanager_secret" "secret_rds" {
  name = "RDS-Admin-Secret-${random_string.random_string.result}"
  tags = {
    Name = "RDS-Admin-Secret-${random_string.random_string.result}"
  }
}

resource "aws_secretsmanager_secret_version" "secret_rds" {
  secret_id     = aws_secretsmanager_secret.secret_rds.id
  secret_string = jsonencode({ username = var.mad_user_admin, password = random_password.secret_rds.result })
  depends_on = [
    aws_secretsmanager_secret.secret_rds,
    random_password.secret_rds
  ]
}

resource "random_password" "secret_onprem" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_secretsmanager_secret" "secret_onprem" {
  name = "${var.onprem_domain_fqdn}-Onprem-Secret-${random_string.random_string.result}"
  tags = {
    Name = "${var.onprem_domain_fqdn}-Onprem-Secret-${random_string.random_string.result}"
  }
}

resource "aws_secretsmanager_secret_version" "secret_onprem" {
  secret_id     = aws_secretsmanager_secret.secret_onprem.id
  secret_string = jsonencode({ username = var.onprem_user_admin, password = random_password.secret_onprem.result })
  depends_on = [
    aws_secretsmanager_secret.secret_onprem,
    random_password.secret_onprem
  ]
}

resource "random_password" "secret_fsx" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_secretsmanager_secret" "secret_fsx" {
  name = "FSx-Service-Account-Secret-${random_string.random_string.result}"
  tags = {
    Name = "FSx-Service-Account-Secret-${random_string.random_string.result}"
  }
}

resource "aws_secretsmanager_secret_version" "secret_fsx" {
  secret_id     = aws_secretsmanager_secret.secret_fsx.id
  secret_string = jsonencode({ username = "FSxServiceAccount", password = random_password.secret_fsx.result })
  depends_on = [
    aws_secretsmanager_secret.secret_fsx,
    random_password.secret_fsx
  ]
}