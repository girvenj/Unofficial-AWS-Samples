output "onprem_ad_instance_id" {
  value = aws_cloudformation_stack.instance_root_dc.outputs.OnpremDomainControllerInstanceID
}

output "onprem_ad_ip" {
  value = aws_cloudformation_stack.instance_root_dc.outputs.OnpremDomainControllerInstancePrivateIP
}

output "onprem_ad_password_secret_id" {
  value = module.store_secret_admin.secret_id
}

output "onprem_ad_fsx_svc_password_secret_id" {
  value = module.store_secret_fsx_svc.secret_id
}