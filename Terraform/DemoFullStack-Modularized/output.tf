output "vpc_id" {
  value = module.network.vpc_id
}

output "vpc_cidr" {
  value = module.network.vpc_cidr
}

output "subnet1_id" {
  value = module.network.subnet1_id
}

output "subnet2_id" {
  value = module.network.subnet2_id
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
/*
output "rds_admin_password_secret_id" {
  value = module.rds_mad.rds_admin_password_secret_id
}

output "rds_endpoint" {
  value = module.rds_mad.rds_endpoint
}

output "managed_ad_fsx_dns_name" {
  value = module.fsx_mad.managed_ad_fsx_dns_name
}*/
