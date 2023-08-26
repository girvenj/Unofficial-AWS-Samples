output "rds_admin_password_secret_id" {
  value = module.store_secret.secret_id
}

output "rds_admin_password_secret_kms_key_arn" {
  value = module.kms_secret_key.kms_key_arn
}

output "rds_endpoint" {
  value = aws_db_instance.rds.endpoint
}
