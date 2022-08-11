output "rds_admin_password_secret_id" {
  value = module.store_secret.secret_id
}

output "rds_endpoint" {
  value = aws_db_instance.rds.endpoint
}