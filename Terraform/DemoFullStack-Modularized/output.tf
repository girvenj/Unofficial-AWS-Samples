output "managed_ad_fsx_alias_dns_name" {
  value = module.fsx_mad.managed_ad_fsx_alias_dns_name
}

output "managed_ad_fsx_dns_name" {
  value = module.fsx_mad.managed_ad_fsx_dns_name
}

output "managed_ad_fsx_encryption_kms_key_arn" {
  value = module.fsx_mad.managed_ad_fsx_encryption_kms_key_arn
}

output "managed_ad_id" {
  value = module.managed_ad.managed_ad_id
}

output "managed_ad_ips" {
  value = module.managed_ad.managed_ad_ips
}

output "managed_ad_mgmt_instance_id" {
  value = module.mad_mgmt_instance.managed_ad_mgmt_instance_id
}

output "managed_ad_mgmt_ip" {
  value = module.mad_mgmt_instance.managed_ad_mgmt_ip
}

output "managed_ad_password_secret_arn" {
  value = module.managed_ad.managed_ad_password_secret_arn
}

output "managed_ad_password_secret_kms_key_arn" {
  value = module.managed_ad.managed_ad_password_secret_kms_key_arn
}

output "managed_ad_rds_admin_password_secret_arn" {
  value = module.rds_mad.managed_ad_rds_admin_password_secret_arn
}

output "managed_ad_rds_endpoint" {
  value = module.rds_mad.managed_ad_rds_endpoint
}

output "managed_ad_rds_kms_key_arn" {
  value = module.rds_mad.managed_ad_rds_kms_key_arn
}

output "managed_ad_sg_id" {
  value = module.managed_ad.managed_ad_sg_id
}

output "onprem_child_ad_domain_name" {
  value = module.onprem_child_dc_instance.onprem_child_ad_domain_name
}

output "onprem_child_ad_instance_id" {
  value = module.onprem_child_dc_instance.child_onprem_ad_instance_id
}

output "onprem_child_ad_ip" {
  value = module.onprem_child_dc_instance.child_onprem_ad_ip
}

output "onprem_child_ad_netbios_name" {
  value = module.onprem_child_dc_instance.onprem_child_ad_netbios_name
}

output "onprem_root_ad_domain_name" {
  value = module.onprem_root_dc_instance.onprem_ad_domain_name
}

output "onprem_root_ad_instance_id" {
  value = module.onprem_root_dc_instance.onprem_ad_instance_id
}

output "onprem_root_ad_ip" {
  value = module.onprem_root_dc_instance.onprem_ad_ip
}

output "onprem_root_ad_netbios_name" {
  value = module.onprem_root_dc_instance.onprem_ad_netbios_name
}

output "onprem_root_ad_password_secret_arn" {
  value = module.onprem_root_dc_instance.onprem_ad_password_secret_arn
}

output "onprem_root_ad_password_secret_kms_key_arn" {
  value = module.onprem_root_dc_instance.onprem_ad_password_secret_kms_key_arn
}

output "onprem_root_additional_ad_instance_id" {
  value = module.onprem_additional_root_dc_instance.additional_onprem_ad_instance_id
}

output "onprem_root_additional_ad_ip" {
  value = module.onprem_additional_root_dc_instance.additional_onprem_ad_ip
}

output "onprem_root_fsx_alias_dns_name" {
  value = module.fsx_onpremises.self_managed_ad_fsx_alias_dns_name
}

output "onprem_root_fsx_dns_name" {
  value = module.fsx_onpremises.self_managed_ad_fsx_dns_name
}

output "onprem_root_fsx_encryption_kms_key_arn" {
  value = module.fsx_onpremises.self_managed_ad_fsx_encryption_kms_key_arn
}

output "onprem_root_fsx_secret_arn" {
  value = module.fsx_onpremises.self_managed_ad_fsx_secret_arn
}

output "onprem_root_pki_instance_id" {
  value = module.onprem_pki_instance.onprem_pki_instance_id
}

output "onprem_root_pki_ip" {
  value = module.onprem_pki_instance.onprem_pki_ip
}

output "r53_resolver_inbound_endpoint_id" {
  value = join("", module.r53_outbound_resolver[*].resolver_inbound_endpoint_id)
}

output "r53_resolver_outbound_endpoint_id" {
  value = module.r53_outbound_resolver.resolver_outbound_endpoint_id
}

output "vpc_cidr_primary_region" {
  value = module.network.vpc_cidr
}

output "vpc_id_primary_region" {
  value = module.network.vpc_id
}

output "vpc_cidr_secondary_region" {
  value = module.network_secondary.vpc_cidr
}

output "vpc_id_secondary_region" {
  value = module.network_secondary.vpc_id
}
