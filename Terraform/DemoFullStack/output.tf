output "managed_ad_id" {
  value = aws_directory_service_directory.mad.id
}

output "managed_ad_dns_ips" {
  value = aws_directory_service_directory.mad.dns_ip_addresses
}

output "managed_ad_sg_id" {
  value = aws_directory_service_directory.mad.security_group_id
}

output "managed_ad_password_secret_id" {
  value = aws_secretsmanager_secret.secret_mad.id
}
