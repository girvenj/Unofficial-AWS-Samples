output "managed_ad_domain_name" {
  value = aws_directory_service_directory.main.name
}

output "managed_ad_id" {
  value = aws_directory_service_directory.main.id
}

output "managed_ad_ips" {
  value = aws_directory_service_directory.main.dns_ip_addresses
}

output "managed_ad_netbios_name" {
  value = aws_directory_service_directory.main.short_name
}

output "managed_ad_password_secret_arn" {
  value = module.store_secret.secret_arn
}

output "managed_ad_password_secret_id" {
  value = module.store_secret.secret_id
}

output "managed_ad_password_secret_kms_alias_name" {
  value = module.kms_secret_key.kms_alias_name
}

output "managed_ad_password_secret_kms_key_arn" {
  value = module.kms_secret_key.kms_key_arn
}

output "managed_ad_sg_id" {
  value = aws_directory_service_directory.main.security_group_id
}
