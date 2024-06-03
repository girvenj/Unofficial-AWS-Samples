output "self_managed_ad_fsx_secret_arn" {
  value = module.store_secret_fsx_ontap_svc.secret_arn
}

output "self_managed_ad_fsx_encryption_kms_key_arn" {
  value = module.kms_key.kms_key_arn
}