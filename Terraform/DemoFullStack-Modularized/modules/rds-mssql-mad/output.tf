output "managed_ad_rds_admin_password_secret_arn" {
  value = module.store_secret.secret_arn
}

output "managed_ad_rds_admin_password_secret_id" {
  value = module.store_secret.secret_id
}

output "managed_ad_rds_endpoint" {
  value = aws_db_instance.rds.endpoint
}

output "managed_ad_rds_kms_key_arn" {
  value = module.kms_secret_key.kms_key_arn
}
