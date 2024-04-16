output "self_ad_rds_admin_password_secret_arn" {
  value = module.store_secret.secret_arn
}

output "self_ad_rds_admin_password_secret_id" {
  value = module.store_secret.secret_id
}

output "self_ad_rds_endpoint" {
  value = aws_db_instance.rds.endpoint
}

output "self_ad_rds_kms_key_arn" {
  value = module.kms_key.kms_key_arn
}
