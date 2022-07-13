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
  count            = var.onprem_deploy_fsx ? 1 : 0
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_secretsmanager_secret" "secret_fsx" {
  count = var.onprem_deploy_fsx ? 1 : 0
  name  = "FSx-Service-Account-Secret-${random_string.random_string.result}"
  tags = {
    Name = "FSx-Service-Account-Secret-${random_string.random_string.result}"
  }
}

resource "aws_secretsmanager_secret_version" "secret_fsx" {
  count         = var.onprem_deploy_fsx ? 1 : 0
  secret_id     = aws_secretsmanager_secret.secret_fsx[0].id
  secret_string = jsonencode({ username = "FSxServiceAccount", password = random_password.secret_fsx[0].result })
  depends_on = [
    aws_secretsmanager_secret.secret_fsx,
    random_password.secret_fsx
  ]
}

resource "random_password" "secret_rds" {
  count            = var.mad_deploy_rds ? 1 : 0
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_secretsmanager_secret" "secret_rds" {
  count = var.mad_deploy_rds ? 1 : 0
  name  = "RDS-Admin-Secret-${random_string.random_string.result}"
  tags = {
    Name = "RDS-Admin-Secret-${random_string.random_string.result}"
  }
}

resource "aws_secretsmanager_secret_version" "secret_rds" {
  count         = var.mad_deploy_rds ? 1 : 0
  secret_id     = aws_secretsmanager_secret.secret_rds[0].id
  secret_string = jsonencode({ username = var.mad_user_admin, password = random_password.secret_rds[0].result })
  depends_on = [
    aws_secretsmanager_secret.secret_rds,
    random_password.secret_rds
  ]
}
