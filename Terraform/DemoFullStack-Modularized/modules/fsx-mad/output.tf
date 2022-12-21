output "managed_ad_fsx_dns_name" {
  value = aws_fsx_windows_file_system.main.dns_name
}

output "managed_ad_alias_dns_name" {
  value = aws_fsx_windows_file_system.main.aliases
}