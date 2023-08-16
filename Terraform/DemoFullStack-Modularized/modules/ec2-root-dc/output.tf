output "onprem_ad_instance_id" {
  value = aws_cloudformation_stack.instance_root_dc.outputs.OnpremDomainControllerInstanceID
}

output "onprem_ad_ip" {
  value = aws_cloudformation_stack.instance_root_dc.outputs.OnpremDomainControllerInstancePrivateIP
}

output "onprem_ad_password_secret_id" {
  value = module.store_secret_administrator.secret_id
}

output "onprem_ad_cad_svc_secret_id" {
  value = join("", module.store_secret_cad_svc[*].secret_id)
}

output "onprem_ad_fsx_svc_secret_id" {
  value = join("", module.store_secret_fsx_svc[*].secret_id)
}

output "onprem_ad_domain_name" {
  value = aws_cloudformation_stack.instance_root_dc.parameters.OnpremDomainName
}

output "onprem_ad_netbios_name" {
  value = aws_cloudformation_stack.instance_root_dc.parameters.OnpremNetBiosName
}

output "mad_trust_direction" {
  value = aws_cloudformation_stack.instance_root_dc.parameters.TrustDirection
}
