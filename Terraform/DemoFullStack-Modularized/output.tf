
output "vpc_id" {
  value = module.network.vpc_id
}

output "vpc_cidr" {
  value = module.network.vpc_cidr
}

output "managed_ad_id" {
  value = module.managed_ad.managed_ad_id
}

output "managed_ad_ips" {
  value = module.managed_ad.managed_ad_ips
}

output "managed_ad_password_secret_id" {
  value = module.managed_ad.managed_ad_password_secret_id
}

output "managed_ad_sg_id" {
  value = module.managed_ad.managed_ad_sg_id
}

output "managed_ad_mgmt_instance_id" {
  value = module.mad_mgmt_instance.managed_ad_mgmt_instance_id
}

output "managed_ad_mgmt_ip" {
  value = module.mad_mgmt_instance.managed_ad_mgmt_ip
}

output "onprem_ad_instance_id" {
  value = module.onprem_root_dc_instance.onprem_ad_instance_id
}

output "onprem_ad_ip" {
  value = module.onprem_root_dc_instance.onprem_ad_ip
}

output "onprem_pki_instance_id" {
  value = module.onprem_pki_instance.onprem_pki_instance_id
}

output "onprem_pki_ip" {
  value = module.onprem_pki_instance.onprem_pki_ip
}

output "onprem_ad_password_secret_id" {
  value = module.onprem_root_dc_instance.onprem_ad_password_secret_id
}

output "onprem_ad_fsx_svc_secret_id" {
  value = module.onprem_root_dc_instance.onprem_ad_fsx_svc_secret_id
}

output "onprem_ad_cad_svc__secret_id" {
  value = module.onprem_root_dc_instance.onprem_ad_cad_svc_secret_id
}
