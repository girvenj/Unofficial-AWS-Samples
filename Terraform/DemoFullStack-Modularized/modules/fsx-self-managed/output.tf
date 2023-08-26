output "self_managed_ad_fsx_alias_dns_name" {
  value = aws_fsx_windows_file_system.main.aliases
}

output "self_managed_ad_fsx_dns_name" {
  value = aws_fsx_windows_file_system.main.dns_name
}

output "self_managed_ad_fsx_secret_arn" {
  value = module.store_secret_fsx_svc.secret_arn
}

output "self_managed_ad_fsx_encryption_kms_key_arn" {
  value = module.kms_key.kms_key_arn
}