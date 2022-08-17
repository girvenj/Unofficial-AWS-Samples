output "managed_ad_id" {
  value = aws_directory_service_directory.main.id
}

output "managed_ad_ips" {
  value = aws_directory_service_directory.main.dns_ip_addresses
}

output "managed_ad_sg_id" {
  value = aws_directory_service_directory.main.security_group_id
}


