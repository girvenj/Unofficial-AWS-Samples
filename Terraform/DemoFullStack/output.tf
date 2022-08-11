output "child_onprem_ad_instance_id" {
  value = join("", aws_cloudformation_stack.instance_child_dc[*].outputs.ChildOnpremDomainControllerInstanceID)
}

output "child_onprem_ad_ip" {
  value = join("", aws_cloudformation_stack.instance_child_dc[*].outputs.ChildOnpremDomainControllerInstancePrivateIP)
}

output "managed_ad_fsx_dns_name" {
  value = join("", aws_fsx_windows_file_system.mad_fsx[*].dns_name)
}

output "managed_ad_id" {
  value = aws_directory_service_directory.mad.id
}

output "managed_ad_ips" {
  value = aws_directory_service_directory.mad.dns_ip_addresses
}

output "managed_ad_mgmt_instance_id" {
  value = join("", aws_cloudformation_stack.instance_mad_mgmt[*].outputs.MADMgmtInstanceID)
}

output "managed_ad_mgmt_ip" {
  value = join("", aws_cloudformation_stack.instance_mad_mgmt[*].outputs.MADMgmtInstancePrivateIP)
}

output "managed_ad_password_secret_id" {
  value = aws_secretsmanager_secret.secret_mad.id
}

output "managed_ad_sg_id" {
  value = aws_directory_service_directory.mad.security_group_id
}

output "onprem_ad_instance_id" {
  value = aws_cloudformation_stack.instance_root_dc.outputs.OnpremDomainControllerInstanceID
}

output "onprem_ad_ip" {
  value = aws_cloudformation_stack.instance_root_dc.outputs.OnpremDomainControllerInstancePrivateIP
}

output "onprem_ad_password_secret_id" {
  value = aws_secretsmanager_secret.secret_onprem.id
}

output "onprem_fsx_dns_name" {
  value = join("", aws_fsx_windows_file_system.onprem_fsx[*].dns_name)
}

output "onprem_fsx_svc_password_secret_id" {
  value = join("", aws_secretsmanager_secret.secret_fsx[*].id)
}

output "onprem_pki_instance_id" {
  value = join("", aws_cloudformation_stack.instance_root_pki[*].outputs.OnpremPkiInstanceID)
}

output "onprem_pki_ip" {
  value = join("", aws_cloudformation_stack.instance_root_pki[*].outputs.OnpremPkiInstancePrivateIP)
}

output "rds_admin_password_secret_id" {
  value = join("", aws_secretsmanager_secret.secret_rds[*].id)
}

output "rds_endpoint" {
  value = join("", aws_db_instance.rds[*].endpoint)
}
